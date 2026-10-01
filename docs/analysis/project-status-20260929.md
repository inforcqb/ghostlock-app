# GhostLock App —— 项目进度（2026-09-29 快照）

> 本文是**当前 app 状态的快照文档**，配套分支 `app-snapshot-20260929`。
> 工作分支仍是 `w1c-cred-copy`（后续开发继续在上面走）。
> 每日原始记录在 `<workspace>/memory/2026-09-2*.md`，本文是精炼版。

---

## 1. 目标与现状一句话

**目标**：OPPO PJA110（kernel `5.15.180-android13-8-o-01179-g408877dae2c9`，OS_PATCH_LEVEL 2026-08）上，
用 app 一键完成：`W1（SELinux→Permissive）→ 拿 uid 0 → 打开 adbd 门 → rmmod oplus_security_guard → ksud late-load`。

**现状**：链条除最后一步"我们的 adb 客户端与 root adbd 握手"之外**全部打通并用真机证据确认** ✓；
最后一步已定位在客户端侧（设备侧由 PC 实测证明完全正常 ✓）。

---

## 2. 链的形态（当前实现）

```
① 现场事实判定     cat /sys/fs/selinux/enforce + cat /proc/self/status 的 Seccomp:
                  enforce==0 && Seccomp==0 ⇒ 无条件跳过 W1 与 am hang（不看标记文件）
② W1              Shizuku(uid 2000) 起引擎，GHOSTLOCK_W1_ONLY + GHOSTLOCK_PARK_AFTER_W1
                  profile 全固定偏移（不依赖 kallsyms）；引擎带"碰撞质量门"（见 §4）
③ uid-0 通道      内置 Magica 端口：RootShellService(isolatedProcess+useAppZygote)
                  bindIsolatedService(instance="ghostlockRoot")；AppZygote 预载 libmagica2.so
④ 打开 adbd 门    通道内两条逐字命令：
                  runcon u:r:adbd:s0 setprop service.adb.tcp.port 5555
                  runcon u:r:usbd:s0 setprop ctl.restart adbd      ← 会杀掉 uid 2000（预期）
⑤ 连 root adbd    libadb-android 连 127.0.0.1:5555（AUTH 由库完成；我们提供密钥+自签证书）
⑥ 收尾            rmmod oplus_security_guard → /data/adb/ksud late-load → 校验 kernelsu
```

**架构硬约束（用户定，必须遵守）**：
* **uid 2000（Shizuku）只能用于启动 W1**。`ctl.restart adbd` 会杀掉 shell 一族（含 Shizuku）
  ⇒ 第 ④ 步之后**只用** app 自己的 uid-0 通道 + app 内 adb 客户端。
* **`setuid(1000)` 的执行体必须用完即退**（`fork → setresuid(1000) → 写 → _exit(0)`），
  **绝不提权回 uid 0**（回切会被安全监控盯上）。

---

## 3. 已验证（真机证据）

| 项 | 证据 |
|---|---|
| CVE 原语在新内核仍在 | 提取器与逐指令比对：`remove_waiter` 仍清 `current->pi_blocked_on` ✓ |
| W1 能落地 | `W1: SELinux target=0xffffff802b3f9990` → `enforce 0` → `parking after W1` ✓ |
| 隔离 root 服务**能绑上** | `bindIsolatedService(instance=ghostlockRoot) -> true`、`ensureRoot=ok`、`startChannel=ok` ✓ |
| uid-0 通道**能用** | app 直连 socket 得到 `uid=0(root) … context=u:r:isolated_app:s0` ✓（客户端时序必须照设备侧 `rshell`：token→1s→命令→2s→exit） |
| **公钥推送成功** | `adb 公钥已交给 adbd（adb_keys，幂等）：true` ✓（JNI fork/setuid(1000)/幂等/_exit ✓） |
| **adbd 门确实打开** | PC 侧 `adb connect <IP>:5555` → `adb shell id` = `uid=0 … u:r:su:s0` ✓✓ |
| 跳过规则正确 | `现场事实 enforce=0 + Seccomp=0 ⇒ 无条件跳过 W1 与 am hang` ✓ |

## 4. 唯一未通的一环

```
[!] adb 客户端连 127.0.0.1:5555 failed: Unable to establish a new connection.
```
* PC 侧同端口**能连且是 root** ✓ ⇒ 问题 100% 在客户端 ✗。
* 已排除：公钥行格式（改为经同包桥接调用 libadb 的 `AndroidPubkey.encodeWithName` ✓）。
* 已加但**尚未真机复测**：连接重试 6 次 + `Builder.setApi(Build.VERSION.SDK_INT)`（v487 ✓）。
* 若仍失败，下一刀：加回 `conscrypt-android` + `-dontwarn org.conscrypt.**`（排除连接层依赖 ✗）。

---

## 5. 已知的、绕不开的环境事实

* **Magica 的 uid 0 依赖 `am hang` 后的"全新 app zygote"** ✓：
  跳掉 hang 时实测 `onCreate: uid=90001` + `SIGSYS, setresuid fail` + `ensureRoot()==false` ✗
  （hook 是生效的：日志有 `Skip capset` ✓，被 seccomp 拒的是 `setresuid` ✗）。
* **`am hang --allow-restart` 实测约 93 s** 才被 watchdog 收尾（t≤80s pid 不变，t=95s 全部换新 ✓）。
* **SusFS 是实验杀手** ✗：装了它时改内核会触发**无日志重启**，且**指纹仍可解锁**（TEE 未丢 ✓）；
  卸载后现象消失 ✓。机制：watchdog 类复位（`qcom_wdt_core ← gh_virt_wdt`，Gunyah/EL2 ✓）+
  `phx_rus_conf.recovery_method=2`（复位经 qcom 安全世界 ⇒ EL1 重置、EL3 未重置 ✓）。
  **`kallsyms`/`dmesg`/`.ko`/`pstore` 探针一律走离线（镜像里拆）** ✗。
* 签名：仓库**没有配置签名 secrets** ⇒ CI 每轮用随机 debug keystore ⇒ 每次更新都要卸载重装 ✗（用户说先不管 ✓）。

---

## 6. 未完成项（按优先级）

1. **配对 + 连接**（新方向，用户 2026-09-29 定稿）：用 libadb 的
   `io.github.muntashirakon.adb.android.AdbMdns` 发现 `_adb-tls-pairing._tcp` / `_adb-tls-connect._tcp` ✓，
   加"**通知里输入配对码**"✓，配对后连接 ⇒ 得到 uid 2000 的 shell 通道 ✓
   （= 取代 Shizuku 的角色 ✓；待验证 **adbd shell 的 `Seccomp: 0`**，这是 W1 硬前提 ✓）。
2. **修复 libadb 握手**（§4）。
3. **砍 UI，只留一个 root 入口**；**未配对时只显示一个"跳转无线调试"的快捷按钮**：
   `com.android.settings/.Settings$WifiDebuggingActivity` → `android.settings.WIRELESS_DEBUGGING_SETTINGS`
   → `Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS`（逐级 `resolveActivity` 回退 ✓）。
4. `am hang` 并入 W1 步骤（**只合并呈现**，命令与次序不变 ✓）。
5. 通道自检那句一次性提示并进第 3 步 ✓。

---

## 7. 代码与构建要点（踩过的坑）

* 依赖：`libadb-android:3.1.1`（JitPack ✓，Apache-2.0 分支 ✓）、`sun-security-android:1.1`（自签证书 ✓）。
  `conscrypt-android` 已移除：它只服务配对 TLS，且其 KitKat 适配类会让 R8 报 missing class ✗。
* 不能用的隐藏 API：`ServiceInfo.isolatedProcess/useAppZygote`（@hide ✗ ⇒ 用 `flags` 位：
  `FLAG_ISOLATED_PROCESS=1<<1`、`FLAG_USE_APP_ZYGOTE=1<<3`，正确声明实测 `flags=0xa` ✓）；
  `AndroidPubkey` 是**包内私有** ✗ ⇒ 同包桥接 `io.github.muntashirakon.adb.AdbPubkeyBridge` ✓。
* `bindIsolatedService` 的 **instanceName 必须是纯标识符** ✗（`"ghostlock-root"` 会抛
  `IllegalArgumentException: Illegal instance name` ⇒ 现用 `"ghostlockRoot"` ✓）。
* Shizuku 调用必须**有超时**（否则永久挂死 ✗），且传输失败要返回 `TRANSPORT_FAILURE=-1`
  并打异常类名 ✗（原先把 `error: null` 当"输出为空" ✗）。
* CI 构建相关：`tools/device/*.sh` 必须 **LF** ✓（`.gitattributes` 已钉 ✓，CRLF 会让设备 mksh 报
  `unexpected 'do'` ✗）；`Extractor 与 Gradle 的 --features http 指纹不一致` 会重复编译 ~75 s ✗（未修 ✓）。

---

## 8. 产物与位置

| 项 | 位置 |
|---|---|
| 仓库 / 工作分支 | `inforcqb/ghostlock-app` @ `w1c-cred-copy` |
| 本快照分支 | `app-snapshot-20260929` |
| 工作副本 | `C:\Users\ASUS\dsh\.scratch\glw1-fix` |
| 最新包 | versionCode **487**（`BE846B27…`，含 libadb + 重试 + `setApi`） |
| CI | `.github/workflows/build.yml`（`skip_extractor=true` 只编 app ✓） |
| 设备侧工具 | `/data/local/tmp/gl-w1/`（16 个脚本 `sh -n` 全通过 ✓；引擎 `ghostlock` 已是最新，`grep -c colliders`=1 ✓） |
| 采集 | `C:\Users\ASUS\dsh\.scratch\run-*\logcat.txt`、`watch.txt` |
| 记忆 | `<workspace>/memory/2026-09-29.md`（§1–§10，含施工单与新方向） |
