# Pinned KernelSU build: `v3.3.0-69-gdf03912f`

`ksud` and `kernelsu-manager.apk` here are the two artifacts the build needs, taken from one
KernelSU build and pinned in the tree.

| file | what it is | bytes | sha256 |
|---|---|---|---|
| `ksud` | the standalone `ksud` for aarch64 (ELF 64-bit PIE executable, `e_machine=0xB7`) | 6310288 | `a14b5980d4b857542c920a3a22625cbba34edd6ea4741230bb1d25d93516c4ce` |
| `kernelsu-manager.apk` | the manager app the chain installs with `pm install -r` | 3769389 | `9acd811cd611b7f4d95fdfcd06d0bb228c2807606fd66d24915a08b5cc6dcde3` |

Provenance: `tiann/KernelSU`, CI run **37882323514**, head **`df03912f70d92ff2aa9762ef82d607033d37e1da`**
(`git describe`: `v3.3.0-69-gdf03912f`, 2026-10-09 04:07 UTC). Artifacts `ksud-aarch64-linux-android`
and `manager-gradle` from that run; the APK's own file name is
`KernelSU_v3.3.0-69-gdf03912f_32670-release.apk`.

## Why they are committed instead of fetched

The project used to run `gh release download --repo SukiSU-Ultra/SukiSU-Ultra` on every build. That
does not work for this pair:

* KernelSU publishes **no release** for `v3.3.0-69` — that build exists only as CI artifacts, and
  downloading another repository's artifacts needs a token with access to it, which a workflow's own
  `GITHUB_TOKEN` is not;
* upstream's manager APK does **not** bundle `ksud` (`lib/arm64-v8a/` holds `libkernelsu.so` and
  `libadbroot.so` only), so the `ksud` here is the standalone artifact, not something extracted from
  the APK the way it used to be.

The build step therefore copies these two files and verifies the sha256 above, so what lands in the
APK cannot drift silently. KernelSU is **GPL-3.0**; the attribution lives in
`app/src/main/jni/THIRD_PARTY_NOTICES.md`.

## Updating this pin

1. Pick the build (a tag, or a `git describe` name such as `v3.3.0-69-gdf03912f`) and note its run id.
2. `gh run download <run-id> --repo tiann/KernelSU -n ksud-aarch64-linux-android -D /tmp/ksu`
3. `gh run download <run-id> --repo tiann/KernelSU -n manager-gradle -D /tmp/ksu`
4. Replace `ksud` and `kernelsu-manager.apk` here, update the table above, and update
   `KSUD_SHA256` / `MANAGER_SHA256` in `.github/workflows/build.yml`.
5. Check the chain still works on the device: the bundled `ksud` is invoked as `ksud resetprop …`
   (an absolute path; it carries `resetprop` the way busybox carries its applets), and the manager's
   package id must match `ChainSpec.KSU_MANAGER_PACKAGE`.
