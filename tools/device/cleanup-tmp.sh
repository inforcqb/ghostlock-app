#!/system/bin/sh
# Remove this project's leftovers from /data/local/tmp.
#
# Keeps:
#   /data/local/tmp/gl-w1/   the one configuration of W1 that landed on hardware
#                            (ghostlock + profile.bin + w1-selinux.sh)
#   /data/local/tmp/ubuntu2/ the user's Ubuntu chroot -- NEVER touched
# and leaves every other tool's directory alone (they are listed at the end for
# a follow-up decision).
#
# Run with `sh cleanup-tmp.sh` (the removal list is printed before deleting).

T=/data/local/tmp
DRY=0
[ "$1" = "--dry-run" ] && DRY=1

remove_file() {
    [ -d "$1" ] && return 0          # never let a glob reach a directory
    [ -e "$1" ] || return 0
    if [ "$DRY" = "1" ]; then
        echo "  would remove: $1"
    else
        rm -f "$1" && echo "  removed: $1"
    fi
}

remove_dir() {
    [ -d "$1" ] || return 0
    case "$1" in
        "$T/ubuntu2"|"$T/gl-w1") echo "  KEEP: $1"; return 0 ;;
    esac
    if [ "$DRY" = "1" ]; then
        echo "  would remove dir: $1"
    else
        rm -rf "$1" && echo "  removed dir: $1"
    fi
}

echo "== exploit run leftovers (files) =="
for f in \
    .ghostlock_iomem .ghostlock_ksu.log .ghostlock_root.sh \
    active-profile.bin active-profile.mcast.bak \
    profile-qemu.bin profile-zero.bin profile-udp.bin \
    pja110-profile.bin tcp-profile.bin gl-w1-profile.bin \
    gl-run-profile.bin pselect-profile.bin gl-run-w1.bin \
    offsets.json btf_dev.bin kallsyms-full.txt remote-mcast.b64 \
    big.bin kread_min.ko kread_min.c kread_load.sh \
    msfilter_probe tofrag armed.sh ashmem_probe ashmem_fdinfo.sh \
    ghostlock-dev ghostlock-head ghostlock-marker ghostlock-nowalk \
    ghostlock-pja110 ghostlock-qemu ghostlock-local
do
    remove_file "$T/$f"
done

echo "== calibration / run logs =="
for f in "$T"/c32-*.txt "$T"/*.native.log "$T"/*.ksu.log "$T"/run*.log \
         "$T"/serial*.log "$T"/gl-pipe.log "$T"/daemon-serial.log \
         "$T"/copy-*.txt "$T"/copy2-*.txt "$T"/calib* \
         "$T"/gl-*.log "$T"/gl-*.txt "$T"/devrun*.log \
         "$T"/panic_last* "$T"/panic_scan* "$T"/console-ramoops-*.txt \
         "$T"/requeue*.txt "$T"/requeue*.log "$T"/fops_layout*
do
    [ -e "$f" ] && remove_file "$f"
done

echo "== calibration scripts =="
for f in "$T"/calib_*.sh "$T"/gl_*.sh "$T"/probe_*.sh "$T"/dump_*.sh \
         "$T"/measure_candidates*.sh
do
    [ -e "$f" ] && remove_file "$f"
done

echo "== test binaries / profiles of this project =="
for f in "$T"/gl-* "$T"/devrun*.txt
do
    [ -e "$f" ] && remove_file "$f"
done

echo "== our staging directories =="
remove_dir "$T/gl-0925-2136"
remove_dir "$T/ghostlock-app"
remove_dir "$T/dev-profiles"

echo
echo "== kept =="
ls -d "$T/gl-w1" "$T/ubuntu2" 2>/dev/null
echo
echo "== directories left for a follow-up decision (NOT touched) =="
for d in "$T"/*/; do
    case "$d" in
        "$T/gl-w1/"|"$T/ubuntu2/") continue ;;
    esac
    echo "  $d"
done

echo
echo "== loose files NOT touched (not this project's, or unclassified) =="
for f in "$T"/* "$T"/.[!.]*; do
    [ -f "$f" ] || continue
    echo "  $f"
done
