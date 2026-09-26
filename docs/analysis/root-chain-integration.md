# GhostLock → 持久 root：整条链与 app 集成设计（2026-09-26）

本文是**规格书**：先描述已端到端验证过的链，再描述要把它集成进 `ghostlock-app` 的设计。
设备侧的操作清单见 `docs/analysis/current-chain-20260926.md`（命令白名单 runbook）。

---

## 0. 背景与目标

* 设备：OPPO PJA110 / `OP5943L1`，SM8550，`5.15.180-android13-8-o-01176-g6333b0dbc8ed`，
  `ro.build.type=user`，bootloader green/locked，SELinux **开机 Enforcing**，
  `oplus_security_guard` / `oplus_secure_harden` / `oplus_security_keventupload` **开机必载**。
* 旧链的前提是"**fastboot 阶段注入 SELinux 宽容**"的那个洞，**2026.3 修复**。
* 目标：不依赖它，仍然拿到 **KernelSU 持久 root**。
* 分工（关键设计结论）：

  > **幽灵锁只负责 W1：`Enforcing → Permissive`。**
  > 提权、uid-0 通道、adbd patch 由 **Magica** 提供；最后两个特权动作从 **root adbd** 执行。

---

## 1. 为什么是这两段（取舍与依据）

| 事实（本机实测） | 推论 |
|---|---|
| `oplus_security_guard` 的 root 策略只比对 **uid 跳变**（`old->uid.val` vs `new->uid.val`），且豁免"**本来就是 root 的进程再涨 cap**" | ⇒ 绝不能走"给 uid 2000 的进程写 cred"这条路（旧 W2/W1c 那一类）：那是它唯一会杀+上报的形态 |
| 它按 **tracepoint 采样 syscall** 判决，命中即 `Kill the process of escalation` 并连坐同 tgid 线程 | ⇒ 任何"先变 root、再慢慢做事"的设计都要把暴露窗口压到最短 |
| Magica 提权后的进程：`uid=0 u:r:isolated_app:s0`，**`CapEff=0x1c0`、`CapBnd=0`、`NoNewPrivs=1`** | ⇒ 它有 uid 0，但**永久拿不到 `CAP_SYS_MODULE`**（bounding set 为 0 不可逆，exec 与文件 capability 都救不回） |
| root adbd 的 shell：`uid=0`、**`u:r:su:s0`**、**`CapEff/CapBnd = 0x1ffffffffff`** | ⇒ **它是链里唯一稳定提供满 cap 的上下文**，`rmmod` + `finit_module` 只能在这里做 |
| `ctl_adbd_prop` 在 `plat_sepolicy.cil` 里只授予 `usbd`；`service.adb.tcp.port` 属 `adbd_config_prop`（只有 `adbd` 域） | ⇒ "开门"要**借域**；而借域（`dyntransition`）只在 **Permissive** 下放行 ⇒ 必须在 W1 之后、ksud 之前 |
| `ksud late-load` 会重新加载 SELinux 策略，把 `enforcing` 写回 1 | ⇒ **SELinux 回到 Enforcing 是预期行为**，不是故障；此后特权操作用 KSU 的 `su`（`u:r:ksu:s0`） |

**被移除的备选：W1c**（在 Magica 的 born-root 进程里给自己写 cred 拿到满 cap）。
它能在 app 内自洽（不需要 adb），但会留下**必须事后用内核读写清理的伪造 PI 状态**（"雷"），
用户决定移除，改走"root adbd"这条已验证的路。

---

## 2. 整条链（逐步，命令逐字照抄）

| # | 执行者（身份 / 域） | 原命令 | 验证 |
|---|---|---|---|
| 1 | Shizuku 或 adb：`uid=2000`、`u:r:shell:s0`、`Seccomp: 0` | `sh /data/local/tmp/gl-w1/w1.sh` | `getenforce` → `Permissive`；`w1.log` 末尾 `parking after W1 … (pid=N)` |
| 2 | 同上 | `am hang --allow-restart` | `cmd: Failure calling service activity: Broken pipe` 是预期输出 |
| 3 | 用户：启动 Magica 并点"启用 rootshell" | `am start -n io.github.vvb2060.puellamagi/.MainActivity` | Magica 的 isolated service `uid=0` |
| 4 | 上述 uid-0 通道 | `sh /data/local/tmp/gl-w1/rshell` | `id` → `uid=0 … u:r:isolated_app:s0`；`CapEff=0x1c0` |
| 5 | 通道内，借 adbd 域 | `runcon u:r:adbd:s0 sh` → `setprop service.adb.tcp.port 5555` | `getprop service.adb.tcp.port` → `5555` |
| 6 | 通道内，借 usbd 域 | `runcon u:r:usbd:s0 sh` → `setprop ctl.restart adbd` | `ss -lnt` → `LISTEN *:5555`；`init.svc.adbd=running` |
| 7 | PC / app：adb 客户端连 `<IP>:5555` | `adb connect <IP>:5555` | `id` → `uid=0 … u:r:su:s0`；`CapEff=0x1ffffffffff` |
| 8 | 该 root shell | `rmmod oplus_security_guard` | `lsmod \| grep oplus_security_guard` → 空 |
| 9 | 该 root shell | `/data/adb/ksud late-load` | `lsmod \| grep kernelsu` → 在；`su -c id` → `u:r:ksu:s0` |

不变量：

* 第 1 步的 **park 进程不能 kill**（退出时内核走伪造 PI 状态会 wedge）；实践上 `am hang` 与
  `ksud late-load` 之后它常常已经不在了，机器没事（2026-09-26 两次都如此）。
* 第 8 步每个 boot 都要重做（guard 开机必回）。
* **整链不做收尾**（用户决定）：门开着（`*:5555`）、park 留着；`service.adb.tcp.port` 与
  `resetprop` 改的 `ro.*` 都**不持久**，重启自然还原。

---

## 3. app 集成设计（`ghostlock-app`）

### 3.1 三段结构

```
┌── Shizuku 段（uid 2000 / Seccomp 0）──────────────────────────────┐
│  GhostlockViewModel.runW1() → RunExploitUseCase(invoke, W1-only)   │
│   → AndroidGhostlockRepository.runExploitWithShizuku()             │
│    → ShizukuExploitRunner.run()  → GhostlockUserService.runExploit │
│     → ProcessBuilder(libghostlock.so, --profile …, env W1_ONLY=1)  │
└───────────────────────────────────────────────────────────────────┘
┌── root 段（uid 0 / isolated service，搬 Magica）──────────────────┐
│  RootService（isolatedProcess）: 提权到 uid 0                       │
│  RootChannel: unix socket（rshell.sock + token）→ uid-0 shell       │
│  控制面 AIDL: IRootService{ startRoot, openChannel, adbdPatch, … }  │
└───────────────────────────────────────────────────────────────────┘
┌── adb 段（app 自己当 adb 客户端）─────────────────────────────────┐
│  AdbClient: TCP 127.0.0.1:5555 → CNXN/AUTH/OPEN("shell:<cmd>")      │
│  命令白名单：rmmod oplus_security_guard / /data/adb/ksud late-load  │
└───────────────────────────────────────────────────────────────────┘
```

### 3.2 接口分工（回答"用 AIDL 还是 native-bridge"）

| 面 | 手段 | 理由 |
|---|---|---|
| 控制面（起/停/状态/是否已 patch） | **新增 AIDL** `IRootService`（isolated service 里实现） | binder 天生适合状态+回调，与现有 `IGhostlockUserService` 一致 |
| 命令执行面（`setprop`/`runcon`/清理等 shell 命令） | **沿用 Magica 的 unix socket 根 shell** | 命令是 shell 层的东西，不必为每条命令定义 AIDL；天然支持长会话 |
| 需要独立进程的活（跑 ELF、`ksud`） | **native-bridge（ProcessBuilder）** | 与现有 `GhostlockUserService` 相同；满 cap 进程只能这样起 |

### 3.3 新增/修改文件（app 侧）

| 文件 | 动作 | 职责 |
|---|---|---|
| `app/src/main/aidl/com/ghostlock/app/root/IRootService.aidl` | 新增 | 控制面：`startRoot()` / `openChannel()` / `channelToken()` / `patchAdbd()` / `stopRoot()` |
| `app/src/main/aidl/.../IRootCallback.aidl` | 新增 | 日志/状态回调（与 `IGhostlockCallback` 同型） |
| `app/src/main/kotlin/com/ghostlock/app/root/RootService.kt` | 新增 | `isolatedProcess=true` 服务；搬 Magica 的提权与通道启动 |
| `app/src/main/kotlin/com/ghostlock/app/root/RootChannel.kt` | 新增 | unix socket 客户端：读 `rshell.token`、连 `rshell.sock`、跑命令、回收输出 |
| `app/src/main/kotlin/com/ghostlock/app/adb/AdbClient.kt` | 新增 | 最小 adb 协议客户端（见 3.5） |
| `app/src/main/kotlin/com/ghostlock/app/chain/RootChain.kt` | 新增 | 链状态机：步骤表 + 每步输出 + 失败即停 |
| `app/src/main/kotlin/com/ghostlock/app/chain/ChainCommands.kt` | 新增 | **命令白名单常量**（§2 逐字）+ 黑名单注释 |
| `app/src/main/kotlin/com/ghostlock/app/ui/GhostlockViewModel.kt` | 修改 | 增加 `runRootChain()` + `chainSteps` 状态；复用现有日志回调 |
| `app/src/main/kotlin/com/ghostlock/app/ui/*Ui.kt` | 修改 | "一键 root" 入口 + 步骤进度 + 日志（复用现有面板） |
| `app/src/main/kotlin/com/ghostlock/app/shizuku/GhostlockUserService.kt` | 修改 | 增加 W1-only 模式（env `GHOSTLOCK_W1_ONLY=1`）与成功判定 |
| `app/src/main/AndroidManifest.xml` | 修改 | 注册 isolated root service（`android:isolatedProcess="true"`） |
| `app/build.gradle(.kts)` | 修改 | AIDL/新模块 + Magica native 库（`jniLibs`/CMake） |
| `tools/device/*`（assets 或 staged） | 复用 | `w1.sh` / `profile.bin`（W1 只用这两样） |

### 3.4 状态机（伪代码）

```
steps = [
  Preflight      : 检查 Shizuku READY、profile、文件布局、记录初始状态
  W1             : runW1() → 等 "Write 1 complete" + enforce==0
  MagicaRoot     : amHang(); startMagica(); 等 isolated service uid==0
  OpenAdbGate    : RootChannel: runcon adbd → tcp.port=5555; runcon usbd → ctl.restart adbd
  AdbConnect     : AdbClient.connect(127.0.0.1:5555) → 校验 uid==0 && CapEff 满
  RemoveGuard    : AdbClient.shell("rmmod oplus_security_guard")
  KsuLateLoad    : AdbClient.shell("/data/adb/ksud late-load")
  Verify         : lsmod 有 kernelsu；su 可用（可选）
]
每个 step: 记录开始/输出/结果；失败 ⇒ 停在当前步并保留日志（**不做收尾**）
```

### 3.5 adb 客户端（最小实现）

因为链在第 5 步就把门开成了 `ro.adb.secure=0`（**门禁在利用期间开放**，用户明确要求），
协议侧可以跳过 RSA 签名：

1. TCP 连 `127.0.0.1:5555`；
2. `CNXN`（version `0x01000001`，`maxdata` 256 KiB，payload `host::features=shell_v2`）；
3. 若收到 `AUTH`，回 `AUTH` type 2（signature）或直接等 `CNXN`——secure=0 时 adbd 直接放行；
4. `OPEN`（local-id，`shell:<command>`）；读 `WRTE` 直到 `CLSE`/`OKAY` 组装输出；
5. 超时/重连策略：连接 5 s、命令 30 s；失败即报当前步。

> 若将来发现 `ro.adb.secure` 无法保持为 0，再退回"随 app 生成一对密钥 + 首次授权一次"。

### 3.6 命令白名单 / 黑名单

**白名单（app 必须逐字复用）**：§2 表中第 1、2、4、5、6、8、9 步的命令。

**黑名单（已提出并否决，禁止引入）**：

* `ksud resetprop service.adb.tcp.port 5555` 之类"绕过 adbd 域"的捷径；
* 用 `resetprop` 写 `service.*`；用 legacy 通用域（`surfaceflinger`/`crash_dump`…）触发 `ctl.*`；
* 任何"省一步/合并一步"的重排（例如省掉 `am hang`）。

---

## 4. 失败模式与回退

| 现象 | 判断 | 回退 |
|---|---|---|
| 第 1 步后 `getenforce` 仍为 Enforcing | W1 没落地（或自检拒绝后重试用尽） | 重跑 `w1.sh`；`w1.log` 里看 `prepare_kernel_page retry` 次数 |
| 屏幕冻结 / adb 掉线（W1 偶发 panic） | 已知未解规律的故障 | 重启；把现象（停在哪一步、dmesg/pstore）记入样本 |
| 第 4 步通道连不上 | Magica 的 isolated service 没起来（`am hang` 没做成 / 被 SELinux 拦） | 重做第 2、3 步；必要时重启系统再试 |
| 第 6 步 `ss` 没有 `*:5555` | 借域失败（此刻非 permissive）或 adbd 没起 | 确认 `getenforce=Permissive`；用 `tools/device/adbd-recover.sh` 的思路救 adbd |
| 第 7 步连不上 | `ro.adb.secure` 没关 / 端口没监听 / adbd 还没重启完 | 依次核对 `getprop`、`ss -lnt`、`init.svc.adbd` |
| 第 8 步 `rmmod` 失败 | guard 已被别的路径卸掉，或 refcount 非 0 | `lsmod` 确认；`rmmod -f`（谨慎）；已不在就算成功 |
| 第 9 步 `ksud late-load` 失败 | `ksud` 路径/kmi 不匹配 | 校验 `/data/adb/ksud` 存在与 `--kmi`；看 `late-load` 输出 |

---

## 5. 验收与 OTA 后复核

**今天（2026-09-26）的端到端证据**：一次 boot 内完成 1→9，最终 `su -c id` 得到
`uid=0 context=u:r:ksu:s0`；链中每一段的日志/状态见 `docs/analysis/current-chain-20260926.md`。

**OTA 之后必须复核**：

1. 新内核里 CVE 特征是否还在（窗口期说明里的 `remove_waiter()` 特征）；
2. 重出 profile（W1 只需 MW route 几何 + `selinux_state` 偏移这一小块）；
3. guard / harden 行为有没有变严（只能上机测）。

---

## 6. 文档地图

| 文档 | 内容 |
|---|---|
| `docs/analysis/current-chain-20260926.md` | 设备侧 runbook：冻结的命令白名单 + 验证 + 坑 + 黑名单 |
| **本文** | 整条链的原理、取舍、app 集成设计、失败模式、验收 |
| `tools/device/README.md` | 设备脚本（`w1.sh` 等）的部署与用法 |

> **W1c 已在 2026-09-26 移除**：相关补丁、阶段代码、脚本与文档全部删除，只留在 git 历史里。
> 本文 §1 保留了"为什么不用它"的取舍记录。
