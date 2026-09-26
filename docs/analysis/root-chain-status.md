# 交接状态：root 链 app 集成（2026-09-26 收工）

> 明天从这里继续。本文只讲"现在到哪了 / 下一步做什么"，链的原理见
> `docs/analysis/root-chain-integration.md`，设备侧的冻结命令见
> `docs/analysis/current-chain-20260926.md`。

## 1. 一句话状态

**链本身已端到端跑通**（2026-09-26 一次 boot 内完成，见下）；**app 集成代码已全部落地并推送**
到分支 `w1c-cred-copy`；**GitHub CI 还在收尾**：首轮 APK 编译抓到 1 个编译错（已修），
需要在明天的第一件事里重跑一次确认绿。

## 2. 已完成（按提交）

| 提交 | 内容 |
|---|---|
| `94ce83b` | 冻结设备侧 runbook：命令白名单 + 每步验证 + 坑 + **黑名单** |
| `1ad1345` | **移除 W1c**：伪造 cred 补丁（6 个源文件）、W1c 阶段、`w1c*.sh`、W1c 文档；`gl-chain.sh` 收敛成"只跑 W1" |
| `278a6da` | 链核心：`chain/RootChain.kt`（原命令逐字 + 状态机）、`adb/AdbClient.kt`、`root/RootChannel.kt`；Shizuku 侧新增 `runW1Only()`/`execShell()`；仓库/用例接线 + `RunRootChainUseCase` |
| `6796333` | UI：一键 root 按钮（与原来那个共用一行、均分宽度）+ 执行面板里的步骤卡片 + VM 状态与 `onRunRootChain()`；中英 strings 各 +12 |
| `a479f45` | `settings.gradle.kts` 加 JitPack（**当前用不到**，只为将来切方案 (a) 时预留，注释里写明了） |
| `13bd423` | **Magica 端口**：`app/src/main/jni/**`（`magica.cpp` + vendored `system_properties`/`lsplt`）、`root/RootShellService.kt`、`root/AppZygote.kt`、`IRootShellService.aidl`、manifest（zygotePreload + isolated service）、Makefile `magica2jni`、根/app Gradle 接线、R8 keep、`THIRD_PARTY_NOTICES.md`；顺手修掉 `AdbClient.exec` 的 `Long/Int` 编译错 |

设备侧仍然可用的工具（未改）：`w1.sh`、`gl-chain.sh`（现在只跑 W1）、`adbd-recover.sh`、
`cleanup-w1.sh` + `cleanup-parked.sh`（W1 park 的安全网，链本身不做收尾）。

## 3. 明天第一步（按顺序）

1. **重跑 CI 确认绿**（上一轮 `Build` 失败在 `RootChain.kt:267` 的 `Long/Int`，已修未验）：
   ```
   gh workflow run bin.yml   --repo inforcqb/ghostlock-app --ref w1c-cred-copy   # 编 native
   gh workflow run build.yml --repo inforcqb/ghostlock-app --ref w1c-cred-copy   # 编 APK
   ```
   看两个点：① `compileReleaseKotlin` 是否还有 `e: file://…` 报错（尤其 Miuix/Compose 调用签名，
       见 §5）；② native 日志里 `make magica2jni` 的 `libc++_shared.so` 检查行是否为 `OK:`。
2. **确认 APK 里两个 .so 都在**（构建产物的自检，防"编过了但没打进包"）：
   `unzip -l GhostLock-release.apk | grep 'lib/arm64-v8a/lib'` → 必须有
   `libghostlock.so`、`libmagica2.so`、`libextract.so`。
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

## 4. 链路关键事实（明天别忘了）

* 目标只有两件事：`rmmod oplus_security_guard` + `/data/adb/ksud late-load`；**不做收尾**
  （门开着、park 留着，靠重启还原）——这是用户明确要求的。
* 命令必须**逐字**复用（§1 白名单）；"简化写法"（`ksud resetprop service.adb.tcp.port`、
  legacy 域触发 `ctl.*`、省掉 `am hang`、重排）一律禁止。
* 第 5/6 步的借域（`runcon u:r:adbd:s0` / `runcon u:r:usbd:s0`）**只在 Permissive 下成立**，
  所以必须夹在 W1 与 `ksud late-load` 之间；`ksud late-load` 之后 SELinux 回 Enforcing 是预期。
* W1 的 park 进程不能 kill；W1 偶发 panic 的规律仍未查明（已搁置）。
* isolated service 没有 IP socket、uid 0 但没有 cap：所以通道是 AF_UNIX、且
  `/data/local/tmp/gl-w1` 必须由设备侧预先建好并 chmod 777。

## 5. 已知风险 / TODO（按优先级）

1. **CI 未绿**：`compileReleaseKotlin` 里 Miuix/Compose 调用签名是本轮最可能的下一个报错点
   （UI 子任务无法在本地类型检查，只能靠 CI）。
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

## 6. 设备与仓库现状（收工时刻）

* 设备：SELinux **Enforcing**、`oplus_security_guard` 已卸（另一次手跑留下的）、`kernelsu` 在、
  Magica 进程在、无 ghostlock 存活（W1 的 park 早已消失）；adb 走 USB `4dfb5f3f`。
  下一次真机验证前建议**重启一次**，用干净状态跑（guard 会随之回来，正好验第 8 步）。
* 仓库：分支 `w1c-cred-copy` 已推送；工作树干净；`main` 未合并（等 CI 绿 + 真机验证后再议）。
