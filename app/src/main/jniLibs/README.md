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
