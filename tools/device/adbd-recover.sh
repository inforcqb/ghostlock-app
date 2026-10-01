#!/system/bin/sh
# adbd-recover.sh -- bring adbd back after it was killed or ctl.restart'ed away.
#
# Two separate traps on this handset:
#
# 1) adbd is a *disabled* service.  /system/etc/init/hw/init.usb.rc:
#        service adbd /system/bin/adbd --root_seclabel=u:r:su:s0
#            class core
#            socket adbd seqpacket 660 system system
#            disabled          <-- init does not auto-restart it
#            updatable
#            seclabel u:r:adbd:s0
#    so once the process is gone only an explicit start (or the sys.usb.config
#    trigger in init.usb.configfs.rc) brings it back.  `ctl.restart adbd` kills
#    it and leaves it down.
#
# 2) control properties are per-service.  init's CheckControlPropertyPerms()
#    synthesises "ctl.<service>" (legacy model) and "ctl.<action>$<service>"
#    (new model) and then requires property_service:set on one of them.  Per the
#    device's own /system/etc/selinux/plat_sepolicy.cil the ONLY domain granted
#    ctl_adbd_prop is usbd:
#        (allow usbd ctl_adbd_prop (property_service (set)))
#        (allow usbd ctl_default_prop (property_service (set)))
#        (allow usbd init (unix_stream_socket (connectto)))
#    That is why `setprop ctl.restart adbd` fails everywhere else with
#        init: Unable to set property 'ctl.restart' from uid:0 gid:0
#              pid:N: Invalid permissions to perform 'restart' on 'adbd'
#    and why running it as usbd works:
#        init: Control message: Processed ctl.restart for 'adbd' from pid: N
#    Run this script the same way:
#
#        runcon u:r:usbd:s0 /data/local/tmp/gl-w1/adbd-recover.sh
#
# Note that restarting adbd is only about restoring the adb transport: on this
# `user` build adbd's root path is compiled out (ALLOW_ADBD_ROOT=0), so a
# restart never turns adb into a root shell -- and `service.adb.root=1` makes
# adbd exit on start, which init then restart-loops.

echo "== before"
getprop init.svc.adbd; getprop sys.usb.config; getprop sys.usb.configfs
getprop sys.usb.state; getprop service.adb.root; getprop ro.debuggable
ps -A -o PID,NAME | grep -w adbd

if [ "$(getprop service.adb.root)" = "1" ]; then
    echo "== clearing service.adb.root (adbd exits on start while it is 1)"
    setprop service.adb.root 0
fi

echo "== start via ctl.start"
setprop ctl.start adbd
sleep 2

if [ "$(getprop init.svc.adbd)" != "running" ]; then
    echo "== ctl.start did not take; toggling sys.usb.config (the trigger is edge-based)"
    cur=$(getprop sys.usb.config)
    setprop sys.usb.config none; sleep 1
    case "$cur" in
        ""|none) setprop sys.usb.config adb,mtp ;;
        *)       setprop sys.usb.config "$cur" ;;
    esac
    sleep 2
fi

echo "== after"
getprop init.svc.adbd; getprop sys.usb.config; getprop sys.usb.state
ps -A -o PID,NAME | grep -w adbd
echo "== last init messages about adbd"
dmesg | grep -i adbd | tail -12
