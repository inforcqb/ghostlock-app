# Third-party notices — `app/src/main/jni`

Scope: everything the `libmagica2.so` JNI library compiles. Origins and licences
as they stand in the tree *today*; the open item is spelled out at the bottom.

| Path | Origin | Licence header in the file |
|---|---|---|
| `magica.cpp` | ported from the Magica fork (`.scratch/magica-upstream`, branch `v21-adbroot-fix`; upstream Magica v2.1) | none — Magica upstream is **Unlicense** (public domain) |
| `logging.h` | Magica upstream, `TAG` retargeted | none — Unlicense |
| `android_filesystem_config.h` | AOSP (`system/core/include/private/android_filesystem_config.h`) | **Apache-2.0**, kept intact |
| `system_properties/**` | vendored AOSP `libcutils`/`libbase` properties fork (this is the bundled resetprop: `__system_property_find/update/add/delete/set`) | **BSD-3-Clause / Apache-2.0**, kept intact (every `.cpp`/`.h` carries its own AOSP header) |
| `lsplt/syscall.hpp` | Google / AOSP `syscall` wrapper | **BSD-3-Clause**, kept intact |
| `lsplt/**` (rest: `lsplt.cc`, `elf_util.cc/.hpp`, `logging.hpp`, `include/lsplt.hpp`) | **LSPlt**, an LSPosed project, vendored via Magica | **no licence header at all** |
| `Android.mk`, `Application.mk` | Magica/bionic-convention build files, adapted | n/a (build description, not shipped in the APK) |

The vendored files carry the licence headers they arrived with; **do not strip
those headers** when touching the files (in particular everything under
`system_properties/**` and `android_filesystem_config.h`).

Keep-this-in-mind facts about the vendored copies:

* `system_properties/**` is a *fork* of AOSP (it patches around the platform's
  restrictions, see `include/api/hacks.h`), so it is not a verbatim AOSP copy even
  though the headers are AOSP's.
* `lsplt/**` is used for exactly one hook: `capset` in
  `/system/lib64/libandroid_runtime.so` (see `JNI_OnLoad` in `magica.cpp`). If the
  licensing is not settled, that hook is the only thing that has to be rewritten —
  a self-written PLT/GOT patcher for one symbol is a small, contained piece of work
  (read the ELF, find the `.rela.plt` entry for `capset`, mprotect the page
  writable, store the replacement address, flush the instruction cache).

## Also shipped in the APK: KernelSU's `ksud` and its manager app

Neither is compiled here. The build step `Stage the pinned ksud + manager` copies two files out of
`prebuilt/kernelsu-3.3.0-69-gdf03912f/` (their sha256 is asserted there, and the provenance is in
that directory's README) into the APK:

* `lib/arm64-v8a/libksud.so` — the standalone `ksud`; the chain invokes it as `ksud resetprop …`
  (busybox style), by absolute path, from the app's copy at `/data/local/tmp/gl-w1/ksud`.
  Pinned: `tiann/KernelSU` CI run `37882323514`, HEAD `df03912f70d9` (`git describe`
  `v3.3.0-69-gdf03912f`, 2026-10-09), artifact `ksud-aarch64-linux-android`, sha256
  `a14b5980d4b857542c920a3a22625cbba34edd6ea4741230bb1d25d93516c4ce`, 6310288 bytes.
* `assets/device/sukisu-manager.apk` — KernelSU's manager APK from the same run
  (`KernelSU_v3.3.0-69-gdf03912f_32670-release.apk`, sha256
  `9acd811cd611b7f4d95fdfcd06d0bb228c2807606fd66d24915a08b5cc6dcde3`), so a device that cannot reach
  GitHub still gets a manager: the chain pushes it and runs `pm install -r` with root. Its package
  is `me.weishu.kernelsu`, which is what `ChainSpec.KSU_MANAGER_PACKAGE` names.

Earlier builds fetched the *latest* SukiSU-Ultra release instead; that is no longer possible for this
pair (KernelSU publishes no release for that commit, and its manager bundles no `ksud`).

**Licence: GPL-3.0** (KernelSU family) for both. GPL-3.0 is copyleft, so redistributing an APK that
carries these binaries obliges the distributor to the GPL's terms (source offer and licence text).
It is recorded here so that decision is made on purpose — the same reason the LSPlt item below is
still open.

## TODO(licence) — must be settled before redistribution

**LSPlt (`app/src/main/jni/lsplt/**`, excluding `syscall.hpp`) is vendored with no
licence header and no settled licence for this tree.** Upstream LSPlt is an LSPosed
project; its licence terms have to be confirmed and recorded here (and a notice
added to `lsplt/**` and to the APK's own notices) **or** the library has to be
replaced by a self-written PLT/GOT patcher as described above. Until then this code
is prototype-grade and must not be redistributed in a release build.
