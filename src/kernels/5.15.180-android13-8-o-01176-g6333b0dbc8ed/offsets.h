/* 5.15.180-android13-8-o-01176-g6333b0dbc8ed
 *
 * OPPO PJA110 / OP5943L1 (kalama, SM8550), arm64, VA_BITS=39, KASLR on,
 * CONFIG_DEBUG_INFO_BTF=y.
 *
 * Measured on the running build (2026-09-19):
 *   symbols   : /proc/kallsyms as root, rebased on _text (0xffffffed04600000
 *               for that boot; _stext = _text + 0x10000)
 *   structures: /sys/kernel/btf/vmlinux (md5 67e85746de90ae6386685dae1d3c99b4)
 *   phys load : /proc/iomem "Kernel code a8010000" = _stext, so _text = 0xa8000000
 *
 * The kernel is a 5.15 android13 tree: rt_mutex_waiter is the flat layout
 * (tree_entry 0x00 / pi_tree_entry 0x18 / task 0x30 / lock 0x38 /
 * wake_state 0x40 / prio 0x44 / deadline 0x48 / ww_ctx 0x50, size 0x58), which
 * is what the compact_waiter branch of prepare_skb_payload() writes, and
 * struct cred carries a 4-byte usage word (uid at +4, caps at 0x28..0x50).
 *
 * pselect_waiter_shift is left 0 (unmeasured): the compact route defaults to
 * TCP zerocopy, and GHOSTLOCK_TCP_ROUTE=0 falls back to the target.h default.
 */

OFFSETS_ENTRY(
    "5.15.180-android13-8-o-01176-g6333b0dbc8ed",
    .kernel_phys_load = 0xa8000000,
    .pselect_waiter_shift = 0,
    .off_init_task = 0x03286400,
    .off_init_cred = 0x0323f3e8,
    .off_root_task_group = 0x033d3580,
    .off_selinux_enforcing = 0x033f9990, /* selinux_state, enforcing at +0 */
    .off_selinux_blob_sizes = 0x02613d88,
    .off_security_hook_heads = 0x02611900,
    .off_slide_nfulnl_logger = 0x031424f0,
    .off_slide_loggers_0_1 = 0x03142418,
    .off_slide_boot_id = 0x03516bd1, /* sysctl_bootid */
    .task_prio = 0x7c,
    .task_normal_prio = 0x84,
    .task_sched_task_group = 0x400,
    .task_pi_lock = 0x884,
    .task_pi_waiters = 0x898,
    .task_pi_top_task = 0x8a8,
    .task_pi_blocked_on = 0x8b0,
    .task_pid = 0x5d8,
    .task_tgid = 0x5dc,
    .task_atomic_flags = 0x598,
    .task_real_cred = 0x790,
    .task_cred = 0x798,
    .task_comm = 0x7a8,
    .task_tasks = 0x4d0,
    .task_seccomp = 0x860,
    .task_usage = 0x38, /* refcount_t usage; 0x40 on the 6.x layouts */
    .compact_waiter = 1,
    .mm_struct_sz = 0x400, /* BTF size 0x3e0, cacheline-aligned stride */
),
