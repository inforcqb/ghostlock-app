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

## `arm64-v8a/libksud.so` —— `ksud`（构建时从官方最新 release 取，**不committed**）

同样是**可执行文件而不是共享库**（ELF 64-bit LSB pie executable, ARM aarch64），
由 App 在跑链之前推送到设备的 `/data/local/tmp/gl-w1/ksud`（0755），链里**用绝对路径**调用。
`app/build.gradle.kts` 里对 `**/libksud.so` 设了 `keepDebugSymbols`（别让 llvm-strip 动它）。

* **来源（每次编译现取，不硬编码版本）**：CI 的 `Fetch ksud + the SukiSU-Ultra manager from the
  latest release` 步骤用 `gh release download --repo SukiSU-Ultra/SukiSU-Ultra --pattern '*.apk'`
  取**最新** release 的管理端 APK，再从里面解出 `lib/arm64-v8a/libksud.so` 放到这里。
  所以它跟着上游走 —— 国内网络到 GitHub 不稳，这一步放在 CI 而不是设备上。
* 该文件**不提交进仓库**（`.gitignore` 已忽略）；本地手工构建要自己取一份：

  ```sh
  gh release download --repo SukiSU-Ultra/SukiSU-Ultra --pattern '*.apk' --dir /tmp/sukisu --clobber
  unzip -p /tmp/sukisu/*.apk 'lib/arm64-v8a/libksud.so' > app/src/main/jniLibs/arm64-v8a/libksud.so
  ```

  实测（v4.2.0，2026-10-01）：这样取出来的 `libksud.so` 与设备 `/data/adb/ksud` 的
  **sha256 逐字节相同**（`9f57222b06222f461bbb69b24e40a293e34708eeb7b1bbb065110651f7b9c991`，5326360 B）。
* 为什么打进 APK：链的第 8b 步要把 `ro.secure` / `ro.debuggable` 写回去，而**裸 `resetprop`
  不在 `adb shell` 的 PATH 里**（真机实测：设备上只有管理端安装目录里那个符号链接
  `/data/adb/ksu/bin/resetprop -> /data/adb/ksud`）；`ksud resetprop` 是绝对路径可寻址、
  且与版本无关的写法。实测：`…/ksud resetprop ro.secure` → `1`，
  `su -c '… -Z ro.secure'` → `u:object_r:userdebug_or_eng_prop:s0`。
* `ksud late-load` **不用**这份副本，仍走设备自己的 `/data/adb/ksud`：late-load 要找到真正安装在
  那台机器上的模块负载。推送失败（或缺失）时链会退回 `/data/adb/ksud` 并在日志里说明。
* 许可证：**GPL-3.0**（SukiSU-Ultra / KernelSU 家族），见 `app/src/main/jni/THIRD_PARTY_NOTICES.md`。

## `assets/device/sukisu-manager.apk` —— 管理端（同样构建时取最新）

CI 的同一步还会把那份**最新的 SukiSU-Ultra 管理端 APK** 复制到
`app/src/main/assets/device/sukisu-manager.apk`（也不提交进仓库）。链的第 7b 步把它推到
`/data/local/tmp/gl-w1/sukisu-manager.apk` 并用 root `pm install -r` 装上，
这样设备侧不需要访问 GitHub 就能拿到管理端（`su` 授权、模块管理）。


