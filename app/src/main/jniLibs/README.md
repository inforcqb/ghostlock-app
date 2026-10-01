# jniLibs/ — 内置的 adb 命令行

`arm64-v8a/libadbcli.so` **不是**共享库，而是 **Android platform-tools 的 `adb` 可执行文件**
（重命名成 `lib*.so` 才会被 AGP 打进 APK 并解压到 App 的 `nativeLibraryDir` —— 那里是唯一
允许 App 执行自己文件的位置；`/data/data` 下的文件被 SELinux 禁止执行）。

* 来源：`lzhiyong/android-sdk-tools` release **34.0.3** 的 `android-sdk-tools-static-aarch64.zip`
  里的 `platform-tools/adb`（静态链接 aarch64，`e_machine=0xB7`，无 `PT_INTERP`），
  许可证 **Apache-2.0**（platform-tools 的 `NOTICE`）。把 `NOTICE` 的归属信息保留在这里。
* **为什么用 34.0.3 而不是更新的 35.0.2**：35.0.2 的这份静态构建在 Android 上跑
  **adb server 会崩** —— 真机实测（PJA110）无论 `start-server` 还是
  `-L tcp:5037 fork-server server --reply-fd` 都在加载密钥后 `Aborted`
  （`fdsan: failed to exchange ownership of file descriptor`，`adb.2000.log` 里可见）；
  34.0.3 的 server 正常启动，且 `pair` / `connect` / `shell` / **退出码透传** 全部实测通过。
  换版本前请先在设备上验证 `start-server` 能起来。
* `app/build.gradle.kts` 里对 `**/libadbcli.so` 设了 `keepDebugSymbols`，避免 AGP 用 NDK 的
  `llvm-strip` 动这个可执行文件。

## `arm64-v8a/libksud.so` —— 内置的 `ksud`

同样是**可执行文件而不是共享库**（ELF 64-bit LSB pie executable, ARM aarch64），
由 App 在跑链之前推送到设备的 `/data/local/tmp/gl-w1/ksud`（0755），链里**用绝对路径**调用。

* 来源：从本机（PJA110，2026-10-01 已 root）的 `/data/adb/ksud` 读出的原样副本，
  **sha256 `9f57222b06222f461bbb69b24e40a293e34708eeb7b1bbb065110651f7b9c991`**，5326360 字节。
  设备上 `/data/adb/ksu/bin/resetprop` 就是指向它的符号链接 —— 即 `ksud` 内置 `resetprop`
  （busybox 式：`ksud resetprop …`）。许可证：**GPL-3.0**（KernelSU / ReSukiSU / KowSU 家族）。
* 为什么打进 APK：链的第 8b 步要把 `ro.secure` / `ro.debuggable` 写回去，而**裸 `resetprop`
  不在 `adb shell` 的 PATH 里**（真机实测：只有 KernelSU 安装目录里那个符号链接）；
  `ksud resetprop` 是绝对路径可寻址、且与版本无关的写法。实测（同一台机器）：
  `/data/local/tmp/gl-w1/ksud resetprop ro.secure` → `1`，
  `su -c '… -Z ro.secure'` → `u:object_r:userdebug_or_eng_prop:s0`。
* `ksud late-load` **不用**这份副本，仍走设备自己的 `/data/adb/ksud`：late-load 需要找到
  真正安装在那台机器上的模块负载，而 `resetprop` 与版本无关。
* `app/build.gradle.kts` 里同样对 `**/libksud.so` 设了 `keepDebugSymbols`。
* 推送失败（或缺失）时链会退回 `/data/adb/ksud` 并在日志里说明。

