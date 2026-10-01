#!/system/bin/sh
# Purge /data/local/tmp down to:
#   gl-w1/            this project's one working W1 configuration
#   ubuntu2/          the user's Ubuntu chroot
#   its script side   ubuntu.sh (+ .bak-before-*), ubuntu.img, ubuntu-chroot.zip,
#                     chroot_stage_test.sh, magica, magica.d/,
#                     mount/ and offline-bundle/ (root-owned mount points of the
#                     chroot -- Permission denied as shell, never touched),
#                     offline-cacerts/ (its CA store)
#
# Everything else is packed into gl-w1/purged-backup.tar FIRST (pull it to the
# host and it is reversible), then removed.  Usage:
#
#   sh purge-tmp.sh --dry-run      # print the plan
#   sh purge-tmp.sh --backup-only  # pack, delete nothing
#   sh purge-tmp.sh                # pack, then delete

T=/data/local/tmp
MODE=${1:-purge}

KEEP="gl-w1 ubuntu2 ubuntu.sh ubuntu.sh.bak-before-cgroup ubuntu.sh.bak-before-chcon-guard ubuntu.img ubuntu-chroot.zip chroot_stage_test.sh magica magica.d mount offline-bundle offline-cacerts offline-hosts"

# Pattern-based so nothing of the Ubuntu set can slip through under a name this
# script does not enumerate (measured: offline-hosts, the chroot's /etc/hosts
# overlay, was the one an explicit name list missed).
keep() {
    case "$1" in
        gl-w1|ubuntu*|*ubuntu*|chroot*|magica*|mount|offline-*) return 0 ;;
    esac
    for k in $KEEP; do
        [ "$1" = "$k" ] && return 0
    done
    return 1
}

list=""
for e in "$T"/* "$T"/.[!.]*; do
    [ -e "$e" ] || continue
    n=${e##*/}
    keep "$n" && continue
    list="$list $n"
done

if [ -z "$list" ]; then
    echo "nothing to purge"
    exit 0
fi

echo "== to purge ($(echo $list | wc -w) entries) =="
for n in $list; do echo "  $n"; done
echo "== kept =="
for k in $KEEP; do [ -e "$T/$k" ] && echo "  $k"; done

if [ "$MODE" = "--dry-run" ]; then
    exit 0
fi

echo "== packing to gl-w1/purged-backup.tar (best effort) =="
rm -f "$T/gl-w1/purged-backup.tar" "$T/gl-w1/purge-errors.txt"
# Files created by root in an earlier session are NOT readable from the shell
# domain (SELinux denies open, and adb pull cannot fetch them either), so a full
# backup is impossible without root.  Archive what is readable, record the rest,
# and carry on -- unlink itself is allowed because the directory is shell-owned.
( cd "$T" && tar -cf "$T/gl-w1/purged-backup.tar" $list 2>"$T/gl-w1/purge-errors.txt" )
unreadable=$(grep -c "can't open" "$T/gl-w1/purge-errors.txt" 2>/dev/null)
[ -z "$unreadable" ] && unreadable=0
echo "archived as far as permissions allow; entries that could not be read: $unreadable"
[ "$unreadable" != "0" ] && grep "can't open" "$T/gl-w1/purge-errors.txt" | head -10
ls -l "$T/gl-w1/purged-backup.tar"

if [ "$MODE" = "--backup-only" ]; then
    echo "backup only; nothing deleted"
    exit 0
fi

echo "== deleting =="
for n in $list; do
    if [ -d "$T/$n" ]; then
        rm -rf "$T/$n" && echo "  removed dir: $n"
    else
        rm -f "$T/$n" && echo "  removed: $n"
    fi
done

echo "== left in $T =="
ls -a "$T"
