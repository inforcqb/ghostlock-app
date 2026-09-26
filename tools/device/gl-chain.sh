#!/system/bin/sh
# gl-chain.sh -- W1 driver, run from adb shell (uid 2000, no root).
#
#   sh /data/local/tmp/gl-w1/gl-chain.sh
#
# W1c (the credential write) has been REMOVED from this project: the root chain
# takes its uid-0 process from Magica and its full capabilities from root adbd, so
# nothing here needs a cred write -- nor the kernel-memory cleanup that came with
# it.  The rest of the chain (Magica, the adbd gate, rmmod, ksud late-load) lives
# in the app; see docs/analysis/root-chain-integration.md.
#
# What remains device-side: get SELinux permissive (W1) and leave the exploit
# process parked (it must NOT be killed; a reboot is the clean exit).
DIR=/data/local/tmp/gl-w1

miss=0
for f in "$DIR/ghostlock" "$DIR/profile.bin" "$DIR/w1.sh"; do
    [ -e "$f" ] || { echo "MISSING: $f"; miss=1; }
done
[ "$miss" = 1 ] && exit 2

echo "== versions"
ls -l "$DIR/ghostlock" "$DIR/w1.sh" "$DIR/profile.bin"

echo "== W1 (uid $(id -u))"
# Judge by the current *state*, not by a line in w1.log: the log survives a reboot
# while SELinux comes back enforcing, so a stale "parking after W1" must never
# skip the only step that gets us permissive.
if [ "$(cat /sys/fs/selinux/enforce 2>/dev/null)" = "0" ] && pidof ghostlock >/dev/null 2>&1; then
    echo "already permissive with a parked W1 (pid $(pidof ghostlock)) -- skipping"
else
    sh "$DIR/w1.sh"
fi
grep -qa 'parking after W1' "$DIR/w1.log" 2>/dev/null ||
    echo "WARNING: $DIR/w1.log has no 'parking after W1' line"

if [ "$(cat /sys/fs/selinux/enforce 2>/dev/null)" = "0" ]; then
    echo "== W1 landed: SELinux is permissive, parked pid=$(pidof ghostlock 2>/dev/null)"
    # The exploit rewrites .ghostlock_root.sh as this uid on every start (umask
    # leaves it 0755); keep it world-writable for stages that later run as uid 0
    # without capabilities.  chmod needs ownership, and only this side owns it.
    chmod 666 "$DIR/.ghostlock_root.sh" 2>/dev/null
    exit 0
fi

echo "== W1 did NOT land (still enforcing) -- stop here, check $DIR/w1.log"
exit 1
