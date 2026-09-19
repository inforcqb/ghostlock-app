# Device support: 5.15.180-android13-8-o-01176-g6333b0dbc8ed

Verified support material for **OPPO PJA110 / OP5943L1** (oplus project 22851,
kalma / SM8550, arm64, 4 KiB pages, 39-bit VA).

The exploit itself works out of the box on this kernel: the offset table in
`src/kernels/5.15.180-android13-8-o-01176-g6333b0dbc8ed/offsets.h` is matched by
exact `uname -r`, so **no `offsets.json` import is required**.

## Files

| File | Purpose |
| --- | --- |
| `verify_ghostlock.py` | Read-only verifier. Confirms the kernel is unpatched and re-derives the whole offset table from on-device sources. |
| `offsets.json` | The same table in the runtime-import schema (`Import offsets.json` / `<GHOSTLOCK_HOME>/offsets.json`). Equivalent to the built-in entry. |
| `ANALYSIS_ZH.md` | Full analysis (Chinese): vulnerability, verification evidence, offset derivation, CI/deployment, risks. |

## Verify this device

Run as root on the device (or inside a chroot over the same kernel):

```sh
python3 verify_ghostlock.py                # defaults to /dev/block/by-name/boot_a
python3 verify_ghostlock.py --json         # also (re)write offsets.json
python3 verify_ghostlock.py --boot /path/to/boot.img
```

It is read-only and performs three independent checks:

1. **Prerequisites** — `CONFIG_FUTEX_PI=y` / `CONFIG_PREEMPT=y` from `/proc/config.gz`.
2. **Patch state** — carves the live `Image` out of the boot partition,
   computes the KASLR slide from `_text`, and disassembles `remove_waiter()`.
   The function is **vulnerable iff its body contains `mrs xN, sp_el0`**
   (i.e. it still reads `current`). This is the identical gate used by
   `tools/extract_rs` (`derive.rs: remove_waiter_uses_current()`), which
   rejects patched kernels with exit code 6.
3. **Offsets** — symbol offsets rebased on `_text` from `/proc/kallsyms`,
   plus `task_struct` / `cred` / `rt_mutex_waiter` field offsets from
   `/sys/kernel/btf/vmlinux`, cross-checked against the immediate operands
   emitted by the compiler in the disassembly.

Exit status is `0` when the kernel is exploitable and the offsets verify.

### Expected result on this device

```
CONFIG_FUTEX_PI=y   : yes
remove_waiter reads current (mrs sp_el0): YES
  ==> VULNERABLE to CVE-2026-43499 (rtmutex remove_waiter UAF)
  cross-check: pi_lock from BTF = 0x884
RESULT: EXPLOITABLE / offsets verified
```

## How the table was measured

* `symbols` — `/proc/kallsyms` as root, rebased on `_text`
  (`_text = 0xffffffed04600000` at measurement time, `_stext = _text + 0x10000`).
* `structure` — `/sys/kernel/btf/vmlinux`
  (md5 `67e85746de90ae6386685dae1d3c99b4` on this build).
* `kernel_phys_load` = `0xa8000000` — `/proc/iomem` reports
  `Kernel code a8010000`, i.e. `_stext`, so `_text` loads at `0xa8000000`.
* `compact_waiter = 1` — `rt_mutex_waiter` is the flat layout (size `0x58`),
  which selects the TCP-zerocopy route by default.
* `pselect_waiter_shift = 0` is **not measured**; the TCP route is the default.
  `GHOSTLOCK_TCP_ROUTE=0` falls back to the pselect route with unverified
  geometry.
* `task_usage = 0x38` — this 5.15 field order differs from the 6.x layouts
  (`0x40`), hence the per-device field.

Re-running `verify_ghostlock.py --json` after a kernel update regenerates the
table; a kernel whose `remove_waiter()` no longer reads `current` is patched and
cannot be attacked.
