#!/system/bin/sh
# cleanup-w1.sh -- clean up after a *W1-only* run (GHOSTLOCK_W1_ONLY=1).
#
# W1 leaves the same class of residue as the W1c/W2 park -- the MulticastWaiter
# write leaves this process's PI fields pointing at forged objects in the payload
# page, and <exit_pi_state_list> walks them if the process dies first (observed:
# exit=0 then a frozen screen with adb dead, no panic).  Two things differ, and
# both are why this wrapper exists:
#
#   1) no receipt.  GHOSTLOCK_W1_ONLY returns before the parked.d/<pid> block
#      (that block lives in the W1c path), so `cleanup-parked.sh` cannot find the
#      process by walking receipts.  We locate it from w1.log's
#      "parking after W1 ... (pid=N)" line, or from ps: the W1 park runs on the
#      *shell* uid (2000), while the W1c park runs as uid 0 inside the Magica
#      channel, so the uid is the discriminator.
#   2) no credential collateral.  W1 stores a non-Credential value
#      (layout.right = page_base + 0x100), so the collateral store
#      *(value) = target-8 lands inside our own payload page, and W1b repairs
#      that scratch in-process.  Nothing global is written: init_cred[0..16]
#      must still read 04 00 00 00 00 ... (usage=4, uid=gid=0), which is exactly
#      what cleanup-parked.sh's verify step checks.
#
# The erase + verify + kill itself is NOT reimplemented here: this delegates to
# cleanup-parked.sh (one implementation), passing the pid and letting it resolve
# the task address through init_task.tasks and init_cred through kallsyms.
#
# Usage
#   sh cleanup-w1.sh                    # dry run: locate + read + show the writes
#   sh cleanup-w1.sh --apply            # erase, verify, then kill the parked pid
#   sh cleanup-w1.sh --apply --no-kill  # erase + verify, leave the process alive
#   sh cleanup-w1.sh --apply 18779      # explicit pid
#
# Needs: uid 0 (the /proc files are 0600) and kread_min.ko; cleanup-parked.sh
# loads it itself (unloading the OPPO modules first when it has to).
# Killing the process does NOT undo the permissive flip: the selinux_state word
# is already written, and that write is the whole point of W1.

set -u

GL_DIR=${GL_DIR:-/data/local/tmp/gl-w1}
GL_LOG=${GL_LOG:-$GL_DIR/w1.log}
CLEANER=${CLEANER:-$GL_DIR/cleanup-parked.sh}

APPLY=""
NO_KILL=0
while [ $# -gt 0 ]; do
    case "$1" in
        --apply)   APPLY="--apply"; shift ;;
        --no-kill) NO_KILL=1; shift ;;
        *)         break ;;
    esac
done
PID=${1:-}

[ -r "$CLEANER" ] || { echo "cleanup-w1: $CLEANER not found"; exit 2; }

# ---------------------------------------------------------------- locate -----
# PID numbers are recycled: w1.log survives reboots, so its "(pid=N)" line can
# name a process that has long exited while N now belongs to something else
# (seen on hardware: pid 13777 had become thermal-engine-v2, uid 0, 164 threads).
# Existence of /proc/<pid> is therefore NOT evidence -- every candidate has to
# pass an identity check, because the cleaner writes zeros into that task's PI
# fields and a wrong task means corrupting an unrelated kernel process.
ident_ok() {   # ident_ok <pid>
    [ -r "/proc/$1/comm" ] || return 1
    [ "$(cat "/proc/$1/comm" 2>/dev/null)" = "ghostlock" ]
}

LOGPID=""
if [ -z "$PID" ] && [ -r "$GL_LOG" ]; then
    LOGPID=$(grep -a 'parking after W1' "$GL_LOG" | tail -1 |
             sed -n 's/.*(pid=\([0-9][0-9]*\)).*/\1/p')
    if [ -n "$LOGPID" ] && ident_ok "$LOGPID"; then
        PID=$LOGPID
    fi
fi
if [ -z "$PID" ]; then
    # Identity, not uid: a W1 park launched from a plain adb shell runs on the
    # shell uid, one launched from a root shell (runcon u:r:shell:s0) runs on 0,
    # and the W1c park runs inside the Magica channel -- comm is the only
    # invariant.  With more than one candidate we refuse and ask for a pid
    # rather than guess.
    CAND=$(ps -A -o PID,UID,STAT,NAME 2>/dev/null | awk '$4 == "ghostlock" { print $1 }')
    NCAND=$(echo "$CAND" | grep -c . 2>/dev/null)
    [ -z "$CAND" ] && NCAND=0
    if [ "$NCAND" = 1 ]; then
        PID=$CAND
    elif [ "$NCAND" -gt 1 ]; then
        echo "cleanup-w1: $NCAND ghostlock processes are running -- pick one:"
        for p in $CAND; do
            echo "  pid=$p uid=$(sed -n 's/^Uid:\t\([0-9]*\).*/\1/p' "/proc/$p/status" 2>/dev/null) \
cap=$(sed -n 's/^CapEff:\t//p' "/proc/$p/status" 2>/dev/null) \
state=$(sed -n 's/^State:\t//p' "/proc/$p/status" 2>/dev/null)"
        done
        echo "  (the W1 park is the one that did not replace its credentials; the"
        echo "   W1c park is uid 0 with CapEff 000001ffffffffff)"
        echo "  re-run: sh $0 ${APPLY:-} <pid>"
        exit 3
    fi
fi
if [ -z "$PID" ]; then
    echo "cleanup-w1: no parked W1 process found (no live process with comm=ghostlock)"
    if [ -n "$LOGPID" ]; then
        if [ -r "/proc/$LOGPID/comm" ]; then
            echo "            note: $GL_LOG names pid $LOGPID, but that pid is now"
            echo "                  \"$(cat "/proc/$LOGPID/comm" 2>/dev/null)\" -- pid reuse, stale log"
        else
            echo "            note: $GL_LOG names pid $LOGPID, which has exited -- stale log"
        fi
    fi
    exit 2
fi
if ! ident_ok "$PID"; then
    echo "cleanup-w1: REFUSING -- pid $PID is not a ghostlock process (comm=\"$(cat "/proc/$PID/comm" 2>/dev/null)\")."
    echo "            Writing PI fields into the wrong task would corrupt it."
    exit 2
fi
if [ ! -d "/proc/$PID" ]; then
    echo "cleanup-w1: pid $PID is gone; the forged state died with it."
    echo "            A reboot is the clean way out if that exit wedged anything."
    exit 2
fi

echo "== parked W1 process"
grep -E '^(Name|State|Uid|Threads):' "/proc/$PID/status" 2>/dev/null
echo "cmdline: $(tr '\0' ' ' < "/proc/$PID/cmdline" 2>/dev/null)"

if [ -r "$GL_LOG" ]; then
    echo "== markers in $GL_LOG"
    grep -aE 'startup context|W1: SELinux target|mcast nonresident: page=|private scratch repaired|parking after W1' "$GL_LOG" | tail -5
    PAGE=$(grep -a 'mcast nonresident: page=0x' "$GL_LOG" | tail -1 |
           sed -n 's/.*page=0x\([0-9a-f][0-9a-f]*\).*/\1/p')
    [ -n "$PAGE" ] && echo "== payload page (the forged PI links must point in here): 0x$PAGE"
fi

# ----------------------------------------------------------------- read ------
# Dry run first: it loads kread_min.ko, resolves the task through
# init_task.tasks, and prints the before/after fields we would verify.
echo
echo "== dry run via $CLEANER"
DRY=$(GL_DIR="$GL_DIR" GL_LOG="$GL_LOG" sh "$CLEANER" "" "" "$PID" 2>&1)
echo "$DRY"
T=$(echo "$DRY" | sed -n 's/^task      = 0x\([0-9a-f]*\).*/\1/p' | tail -1)
IC=$(echo "$DRY" | sed -n 's/^init_cred = 0x\([0-9a-f]*\).*/\1/p' | tail -1)
IC0=$(echo "$DRY" | sed -n 's/^init_cred\[0\.\.16\] = //p' | tail -1)
BEFORE_NODE=$(echo "$DRY" | sed -n 's/^pi_waiters\.node  = 0x//p' | tail -1)
BEFORE_BLOCKED=$(echo "$DRY" | sed -n 's/^pi_blocked_on    = 0x//p' | tail -1)

if [ -z "$T" ]; then
    echo
    echo "cleanup-w1: could not resolve the task address -- not touching anything."
    exit 1
fi
echo
echo "task=0x$T  init_cred=0x${IC:-?}  pi_waiters.node=0x${BEFORE_NODE:-?}  pi_blocked_on=0x${BEFORE_BLOCKED:-?}"
case "${IC0:-}" in
    04000000000000000000000000000000)
        echo "init_cred is pristine (usage=4, uid/gid=0) -- W1's collateral stayed in" \
             "our own page, as designed, and the verify step can pass." ;;
    "")
        echo "NOTE: no init_cred readback (kread unavailable?) -- --apply would fail" \
             "the verify step rather than kill anything." ;;
    *)
        echo "WARNING: init_cred[0..16] = ${IC0} is NOT the pristine usage=4 pattern."
        echo "         cleanup-parked.sh's verify requires that pattern, so --apply"
        echo "         will report NOT clean and will refuse to kill.  Fix init_cred"
        echo "         first (that is a W1c/W2 problem, not a W1 one)." ;;
esac
if [ -n "${PAGE:-}" ] && [ -n "${BEFORE_NODE:-}" ]; then
    case "$BEFORE_NODE" in
        0|"") : ;;
        0*"${PAGE#0}"*|"${PAGE}"*) echo "forged node is inside the payload page -- expected for W1." ;;
        *) echo "NOTE: pi_waiters.node=0x$BEFORE_NODE is not zero and not inside" \
                "0x$PAGE; check the log/page before applying." ;;
    esac
fi

if [ -z "$APPLY" ]; then
    echo
    echo "dry run only.  Re-run with --apply to erase, verify and (unless --no-kill)"
    echo "kill pid=$PID."
    exit 0
fi

# ---------------------------------------------------------------- apply ------
echo
if [ "$NO_KILL" = 1 ]; then
    echo "== apply (erase + verify, keeping the process alive)"
    GL_DIR="$GL_DIR" GL_LOG="$GL_LOG" sh "$CLEANER" --apply "$T" "$IC" ""
    rc=$?
    echo "cleanup-w1: rc=$rc; the process is still parked (pid=$PID)."
    echo "             Once the erase verified, you may kill it with: kill -9 $PID"
else
    echo "== apply (erase + verify, then kill the parked pid)"
    GL_DIR="$GL_DIR" GL_LOG="$GL_LOG" sh "$CLEANER" --apply "$T" "$IC" "$PID"
    rc=$?
    if [ "$rc" = 0 ]; then
        echo "cleanup-w1: done -- pid=$PID was cleaned and killed; permissive stays."
    else
        echo "cleanup-w1: rc=$rc -- NOT clean, the process was left parked on purpose."
        echo "             Do not kill it by hand."
    fi
fi
exit $rc
