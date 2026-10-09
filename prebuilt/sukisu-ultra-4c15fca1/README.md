# Pinned SukiSU-Ultra build: `main@4c15fca1` (v4.2.0 / 40965)

`ksud` and `sukisu-manager.apk` here are the two artifacts the build needs, taken from one
SukiSU-Ultra CI build and pinned in the tree.

| file | what it is | bytes | sha256 |
|---|---|---|---|
| `ksud` | the standalone `ksud` for aarch64 (ELF 64-bit PIE executable, `e_machine=0xB7`) | 6965184 | `a27b0842d31ae34028dff556308c194ac8fb4eaf7732696fbf9bcf8507d49c71` |
| `sukisu-manager.apk` | the manager app the chain installs with `pm install -r` (`com.sukisu.ultra`) | 16718549 | `d3b07d2638745e79faa765c9bfe9281269414399e0550a13cc186a88e645fbb4` |

Provenance: `SukiSU-Ultra/SukiSU-Ultra`, CI run **37934517573**, branch `main`, head
**`4c15fca1`**, 2026-10-09 13:06 UTC. Artifacts `ksud-aarch64-linux-android` and `Manager` from
that run; the APK's own file name is `SukiSU_v4.2.0_40965-release.apk`.

That run is still shown as *in progress*, and that is expected: **every build job in it succeeded**
(`build-ksud`, `build-lkm` for all eight KMIs, `build-manager`, `repack-manager`) and the only
job still running is `upload-telegram`, which is stuck on its upload step and has nothing to do
with the artifacts used here.

`ksud` carries the kernel module: the LKM built for a KMI is packed **inside** it (`pack_lkm`), so
there is no separate `.ko` to download — the `aarch64-android13-5.15-lkm` artifact in that same run
is only needed if a device's `late-load` ever reports a module/KMI mismatch.

The run also publishes a `Manager-spoofed` variant
(`SukiSU_v4.2.0_40965-release-spoofed.apk`, sha256
`bf46f997a9f170d9ba952ca68207c070ca7004743603130e2eb262fa023c92c2`). The plain `Manager` is what is
pinned here; switching is one file plus one sha256 in `.github/workflows/build.yml`.

## Why they are committed instead of fetched

Downloading another repository's **CI artifacts** needs a token with access to that repository,
which a workflow's own `GITHUB_TOKEN` is not — the same reason
`prebuilt/kernelsu-3.3.0-69-gdf03912f/` (the previous pin, kept in git history) was committed
rather than fetched. A pinned pair also makes the build reproducible: the sha256s asserted in
`.github/workflows/build.yml` fail the build if the files ever change silently.

## Licence

GPL-3.0 (SukiSU-Ultra / KernelSU family), for both files. See
`app/src/main/jni/THIRD_PARTY_NOTICES.md`, which records what redistributing an APK with these
binaries means.
