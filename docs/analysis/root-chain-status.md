# 交接状态：root 链 app 集成（2026-09-27：CI 双绿 + 打包自检通过）

> 明天从这里继续。本文只讲"现在到哪了 / 下一步做什么"，链的原理见
> `docs/analysis/root-chain-integration.md`，设备侧的冻结命令见
> `docs/analysis/current-chain-20260926.md`。

## 1. 一句话状态

**链本身已端到端跑通**（2026-09-26 一次 boot 内完成，见下）；**app 集成代码已全部落地并推送**
到分支 `w1c-cred-copy`；**CI 已全绿**（`Bin` 与 `Build` 均在 `35dc055` 上 success，
Build = run `36298541927`），**APK 打包自检也已通过**：下载 artifact 后确认
`lib/arm64-v8a/` 下正好含 `libghostlock.so`、`libmagica2.so`、`libextract.so`，且**没有**
`libc++_shared.so`（native 日志同步打印 `OK: .build/jni/libmagica2.so needs no libc++_shared.so`）。
**只剩真机首跑**（§3）与两个已知 TODO（lsplt 许可、Magica 提权前提）。

## 2. 已完成（按提交）

| 提交 | 内容 |
|---|---|
| `94ce83b` | 冻结设备侧 runbook：命令白名单 + 每步验证 + 坑 + **黑名单** |
| `1ad1345` | **移除 W1c**：伪造 cred 补丁（6 个源文件）、W1c 阶段、`w1c*.sh`、W1c 文档；`gl-chain.sh` 收敛成"只跑 W1" |
| `278a6da` | 链核心：`chain/RootChain.kt`（原命令逐字 + 状态机）、`adb/AdbClient.kt`、`root/RootChannel.kt`；Shizuku 侧新增 `runW1Only()`/`execShell()`；仓库/用例接线 + `RunRootChainUseCase` |
| `6796333` | UI：一键 root 按钮（与原来那个共用一行、均分宽度）+ 执行面板里的步骤卡片 + VM 状态与 `onRunRootChain()`；中英 strings 各 +12 |
| `a479f45` | `settings.gradle.kts` 加 JitPack（**当前用不到**，只为将来切方案 (a) 时预留，注释里写明了） |
| `13bd423` | **Magica 端口**：`app/src/main/jni/**`（`magica.cpp` + vendored `system_properties`/`lsplt`）、`root/RootShellService.kt`、`root/AppZygote.kt`、`IRootShellService.aidl`、manifest（zygotePreload + isolated service）、Makefile `magica2jni`、根/app Gradle 接线、R8 keep、`THIRD_PARTY_NOTICES.md`；顺手修掉 `AdbClient.exec` 的 `Long/Int` 编译错 |
| `3b7680f` | **native 编译修复**：`app/src/main/jni/bionic_compat.h` 补 `__BIONIC_ALIGN`（bionic 私有宏，NDK 公共头没有），Makefile `JNI_CFLAGS` 加 `-include`；vendored 文件保持原样 |
| `35dc055` | **manifest 修复**：`<!-- … service -- see … -->` 里的连续连字符是非法 XML，导致 `processReleaseMainManifest` 解析失败（AGP 不给 SAX 细节）；顺带全仓 11 个 XML 良构性普查通过 |

设备侧仍然可用的工具（未改）：`w1.sh`、`gl-chain.sh`（现在只跑 W1）、`adbd-recover.sh`、
`cleanup-w1.sh` + `cleanup-parked.sh`（W1 park 的安全网，链本身不做收尾）。

## 3. 下一步（按顺序）

1. ~~重跑 CI 确认绿~~ **已完成** ✅（`35dc055`：`Bin` success，`Build` success = run `36298541927`）：
   ```
   gh workflow run bin.yml   --repo inforcqb/ghostlock-app --ref w1c-cred-copy   # 编 native
   gh workflow run build.yml --repo inforcqb/ghostlock-app --ref w1c-cred-copy   # 编 APK
   ```
   两个看过的点：① `compileReleaseKotlin` 已无 `e: file://…`（只剩若干 warning）；② native 日志里
   `make magica2jni` 的检查行是 `OK: .build/jni/libmagica2.so needs no libc++_shared.so` ✅。
2. ~~确认 APK 里三个 .so 都在~~ **已完成** ✅（防"编过了但没打进包"）：
   ```
   gh run download 36298541927 --repo inforcqb/ghostlock-app -n GhostLock-release.apk -D .build/ci-apk
   ```
   注意两点：artifact 名**带扩展名** `GhostLock-release.apk`（upload-artifact v7 + `archive: false`）；
   `gh run download` 会把 APK 自身当 zip 解开，所以直接看到的就是**包内结构**——
   `lib/arm64-v8a/{libextract.so 1686.7 KB, libghostlock.so 250.2 KB, libmagica2.so 105.4 KB}`，
   且 `libc++_shared.so` 不在包内 ✅。
3. **真机首跑（app 内一键）**，前置：
   ```
   adb shell mkdir -p /data/local/tmp/gl-w1 && adb shell chmod 777 /data/local/tmp/gl-w1
   ```
   然后：Shizuku 里授权本 app → 装 APK → 点"一键 root"。要盯的四点：
   Shizuku 段是否拿到 `uid=2000 / Seccomp=0`（`GhostlockUserService` 会校验）；
   step W1 之后 `getenforce` 是否 Permissive；step OPEN_ADB_GATE 是否 `runcon` 成功
   （失败通常是"此刻不是 permissive"，说明顺序被破坏）；step ADB_CONNECT 的 `CapEff` 是否
   `0x1ffffffffff`。
4. 真机验证完再回到 §5 的 TODO。

## 4. 链路关键事实（别忘）

* 目标只有两件事：`rmmod oplus_security_guard` + `/data/adb/ksud late-load`；**不做收尾**
  （门开着、park 留着，靠重启还原）——这是用户明确要求的。
  * 但要区分"**链内不做收尾**"与"**跑完之后关闸**"：用户要求利用期间允许开放 5555，
    跑完必须关掉。最干净的做法是 **host 侧 `adb usb`** —— adbd 自己切回 USB-only，
    `service.adb.tcp.port` 变 `0`、5555 监听消失（2026-09-27 实测：
    `restarting in USB mode` → 重新 `adb connect 192.168.0.113:5555` 得 `10061 目标计算机积极拒绝`，
    USB `4dfb5f3f` 保持在线）。它比"写属性 + 借 usbd 域 `ctl.restart adbd`"简单，
    且**在 Enforcing 下同样有效**（adbd 自己改自己的监听模式，不需要那两条域授权）。
    收尾后 host 侧如需清理条目：`adb disconnect <ip>:5555`。
  * **判据陷阱（2026-09-27 实测）**：不要只看 `getprop service.adb.tcp.port`——属性被清成 `0`
    或空之后，**已经在跑的 adbd 仍会继续监听 5555**（当时实测到"属性为空、但
    `192.168.0.113:5555` 仍显示 `device`"的状态）。真正的判据是**重连被拒**
    （`cannot connect … 10061`，即无人监听），或者从设备侧看监听表。
    `adb usb` 会重启 adbd，所以属性与监听才会一起复位。
* 命令必须**逐字**复用（§1 白名单）；"简化写法"（`ksud resetprop service.adb.tcp.port`、
  legacy 域触发 `ctl.*`、省掉 `am hang`、重排）一律禁止。
* 第 5/6 步的借域（`runcon u:r:adbd:s0` / `runcon u:r:usbd:s0`）**只在 Permissive 下成立**，
  所以必须夹在 W1 与 `ksud late-load` 之间；`ksud late-load` 之后 SELinux 回 Enforcing 是预期。
* W1 的 park 进程不能 kill；W1 偶发 panic 的规律仍未查明（已搁置）。
* isolated service 没有 IP socket、uid 0 但没有 cap：所以通道是 AF_UNIX、且
  `/data/local/tmp/gl-w1` 必须由设备侧预先建好并 chmod 777。
* 构建侧（今天新增）：vendored `system_properties` 依赖 bionic 私有宏，靠
  `app/src/main/jni/bionic_compat.h` + `JNI_CFLAGS` 的 `-include` 兜住；**改 vendored 文件前先想
  shim**。XML 里注释**不能含连续连字符**，Gradle 不报细节，所以**推 CI 前先本地 parse**。
* **W1 的写入形态与隐患明细见 `docs/analysis/w1-report.md`**（逐字节副产物、H1–H9 隐患、
  日志判读方法；按用户指示**只记录、不处理**）。结论一句话：链只依赖
  `enforcing == 0x00` 且 `initialized != 0x00`，其余字节写脏不影响提权，正常值事后手动 kread 回填。

## 5. 已知风险 / TODO（按优先级）

1. **真机首跑未做**：app 内一键链只在 CI 层面验证过（编译 + 打包），设备行为待验；
   Magica 段若 `root()` 失败，先看 `logcat -s GhostlockRoot`。
2. **lsplt 许可证未决**：`app/src/main/jni/lsplt/**`（除 `syscall.hpp`）没有许可头，
   upstream 是 LSPosed 项目 → 要么落实许可，要么自己写一个只替换 `capset` 的 PLT/GOT patcher。
   记录在 `THIRD_PARTY_NOTICES.md` 与 `magica.cpp` 头注释里。
3. **Magica 提权的前提**：只在"无 SafeSetID + 未装 setuidgid seccomp 过滤器 + Permissive"下成立；
   upstream 说 Android 17 会挡（本 app targetSdk 37）。真机首跑时若 `root()` 返回 false，
   先看 `logcat -s GhostlockRoot`。
4. **Kotlin/JNI 名字对齐**：`FindClass("com/ghostlock/app/root/RootShellService")` 与类名、
   `System.loadLibrary("magica2")` ↔ `libmagica2.so` 必须一致；改动任一处都要同步。
5. `Makefile`/`app/build.gradle.kts` 的 jniLibs 生成链路是"预构建产物"模式：
   `app/src/main/jniLibs` 在 gitignore 里，clone 后必须先跑一次 Gradle（CI 里由 `preBuild` 保证）。
6. **本地无 SDK/NDK**：Kotlin/UI 的类型错误只能靠 CI 发现；但**能本地做的静态校验一定要做**
   （XML 良构性、Kotlin 签名与 import 人工核对、C 宏用宿主 g++ 探针）。

## 6. 设备与仓库现状

* 设备：SELinux **Enforcing**、`oplus_security_guard` 已卸（另一次手跑留下的）、`kernelsu` 在、
  Magica 进程在、无 ghostlock 存活（W1 的 park 早已消失）；adb 走 USB `4dfb5f3f`。
  下一次真机验证前建议**重启一次**，用干净状态跑（guard 会随之回来，正好验第 8 步）。
* 仓库：分支 `w1c-cred-copy` 已推送，远端 = 本地 = `35dc055`；工作树干净；
  `Bin`/`Build` 双绿、APK 打包自检通过；`main` 未合并（等真机验证后再议）。
