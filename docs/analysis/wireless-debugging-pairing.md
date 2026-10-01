# 无线调试通道（配对 → uid-2000 shell）——取代 Magica / am hang / Shizuku

> 分支：`wireless-pairing`（基于 `app-snapshot-20260929`）。
> 依据：`project-status-20260929.md` §6.1/§9、`memory/2026-09-29.md` §9。
> 状态：代码完成，CI 构建通过后由用户真机验证（见文末验收项）。

---

## 1. 为什么换这条路

Magica 的 uid-0 通道**依赖 `am hang --allow-restart` 之后的"全新 app zygote"**
（v487 实测：hook 生效 `Skip capset`，但隔离进程仍是 `uid=90001`，
`setresuid` 被 seccomp 拦 `SIGSYS`）。用户 2026-09-29 决定放弃这条线，改为：

> **用无线调试配对拿到 uid 2000 的 shell 通道，用它取代 Shizuku 原来的角色。**

好处（用户 2026-10-01 补充的关键一条）：

* **不需要 `setuid(1000)` 去写 `/data/misc/adb/adb_keys`** —— 配对握手本身就是
  "adbd 登记我们公钥"的官方路径（等价于 `adb pair`）。旧方向里那套
  `fork → setresuid(1000) → 幂等写 → _exit`（`IsolatedRootShell.pushAdbKey()` +
  `magica.cpp:push_adb_key`）**对新链完全不需要**；本轮**不删**（旧路还在树上），
  但它是待删死代码。
* 配对登记的密钥不随 adbd 重启丢失 ⇒ 第 ④ 步 `runcon u:r:usbd:s0 setprop ctl.restart adbd`
  之后的 **root adbd（5555）仍然认这把密钥**，链的收尾（`rmmod` + `ksud late-load`）
  继续可用。
* 整条链不再需要 Magica / `am hang` / Shizuku / uid-0 通道的任何一环。

## 2. 新链形态（本轮只做到"通道就绪"）

```
① 配对      AdbMdns 发现 _adb-tls-pairing._tcp → 通知里输入 6 位配对码
            → PairingConnectionCtx 完成 SPAKE2+TLS 握手（adbd 记下我们的公钥）
② 建通道    AdbMdns 发现 _adb-tls-connect._tcp → libadb 连接（TLS + AUTH 用配对密钥）
③ 自检      shell 里跑 `id`（要 uid=2000）与 `cat /proc/self/status`（要 Seccomp: 0）
            —— 这两个事实是 W1 引擎的硬前提
── 以下留给后续卡 ──
④ W1        在这条 shell 通道里跑（取代 ShizukuExploitRunner 的 UserService 路径）
⑤ 开门      runcon u:r:adbd:s0 setprop service.adb.tcp.port 5555
            runcon u:r:usbd:s0 setprop ctl.restart adbd        ← 通道会随之死掉（预期）
⑥ 收尾      连 127.0.0.1:5555（root adbd）→ rmmod oplus_security_guard → ksud late-load
```

**本轮不动冻结的链**：配对/连接留在链状态机之外，先独立验证（用户 §9.3 的顺序）。

## 3. 代码地图

| 文件 | 职责 |
|---|---|
| `app/src/main/kotlin/com/ghostlock/app/wireless/WirelessAdb.kt` | mDNS 发现、配对握手、TLS 连接、`shell:` 执行（都带看门狗超时） |
| `.../wireless/WirelessPairingController.kt` | 状态机：发现→配对→连接→自检；配对结果持久化；日志（主线程回调） |
| `.../wireless/WirelessNotifications.kt` | 配对码通知（`RemoteInput` 直接回复）、状态通知、通知渠道 |
| `.../wireless/PairingCodeReceiver.kt` | 收通知里的配对码，转交控制器（`exported=false`，靠自己的 PendingIntent 投递） |
| `.../ui/wireless/WirelessDebuggingActivity.kt` | 新通道界面：未配对时**只有一个**"打开无线调试"按钮 |

实现要点（都是踩过/想清楚的点）：

* **`FLAG_MUTABLE`**：带 `RemoteInput` 的 `PendingIntent` 必须是可变的，否则回复送不进来。
* **通知权限**：`POST_NOTIFICATIONS`（API 33+）是运行时权限；拒绝时界面才出现
  "页内输入配对码"的兜底控件（这是配对前唯一会出现的第二个控件）。
* **跳转三级回退**：`com.android.settings/.Settings$WifiDebuggingActivity` →
  `android.settings.WIRELESS_DEBUGGING_SETTINGS` → `APPLICATION_DEVELOPMENT_SETTINGS`，
  每级先 `resolveActivity` 再用 `runCatching` 启动，失败就提示手动路径。
  `<queries>` 里补了两个 `<intent>`，否则 Android 11+ 的包可见性会让 `resolveActivity` 恒为 null。
* **超时**：libadb 的配对与流读取本身没有超时 ⇒ 统一用守护线程 + `CountDownLatch` 看门狗，
  避免"端点死了但链永远挂着"。
* **不改共享私钥**：本实现不继承 `AbsAdbConnectionManager`（它的 `close()` 会
  `PrivateKey.destroy()`，会毁掉 `AdbKey` 的缓存密钥），直接用
  `PairingConnectionCtx` 与 `AdbConnection.Builder`。
* **不依赖 conscrypt**：`SslUtils` 在 SDK ≥ 29 用平台
  `com.android.org.conscrypt.Conscrypt#exportKeyingMaterial`（本 app `minSdk=34`）。

## 4. 真机前置条件（缺一不可）

1. **Wi-Fi 已连**（无线调试面板要能显示 IP；mDNS 要有网络接口）。
2. 系统"开发者选项 → 无线调试"**已打开**（`_adb-tls-connect` 才会广播）。
3. 配对时必须**保持"使用配对码配对设备"对话框打开**（`_adb-tls-pairing` 只在这时存在），
   配对码也只在那个对话框期间有效。

## 5. 怎么验（证据口径）

界面上（或 logcat 里，tag `GhostlockWireless`）应看到：

```
[*] 查找 adb-tls-pairing ...
[*] 配对端点 192.168.x.x:41234
[*] 配对成功：adbd 已登记本应用的公钥（无需 setuid 写 adb_keys）
[*] 查找 adb-tls-connect ...
[*] 连接端点 192.168.x.x:37xxx
[*] adb 已连接（TLS + AUTH，用的是配对登记的密钥）
$ id
uid=2000(shell) gid=2000(shell) ... context=u:r:shell:s0
[*] 通道身份：uid=2000 Seccomp=0
[*] 通道就绪 ✓ uid=2000 且 Seccomp: 0 ⇒ 可用来跑 W1
```

对外可复核的旁证（PC 侧同一条 adbd）：

```powershell
adb connect <设备IP>:<无线调试端口>   # 配对后 PC 也能连（同一套密钥体系）
adb shell id
```

失败时界面上的 `wireless_pair_no_service` / `wireless_connect_no_service` 直接指明
缺的是配对对话框还是无线调试开关。

## 6. 真机上踩到的四个坑（2026-10-01，PJA110 / Android 16 / SDK 36）

1. **平台 conscrypt 的导出密钥是隐藏 API** ✗
   `NoSuchMethodException: com.android.org.conscrypt.Conscrypt.exportKeyingMaterial`
   ⇒ 配对协议要用 RFC 5705 导出密钥把 SPAKE2 口令绑到 TLS 通道上，而 Android 16 上这个平台方法是
   hidden API（`hiddenapi: ... api=blocked`）。**修法**：打包 `org.conscrypt:conscrypt-android:2.5.3`，
   让 libadb 走它优先的 `org.conscrypt` 路径（普通库方法）；R8 另需两条 `-dontwarn`
   （`com.android.org.conscrypt.SSLParametersImpl`、`org.apache.harmony.xnet.provider.jsse.SSLParametersImpl`
   —— 就是 2026-09-29 那次放弃 conscrypt 的确切原因）。

2. **`AdbConnection.Builder.connect(...)` 的判断是反的** ✗（上游 libadb 3.1.1 的 bug）
   ```java
   if (adbConnection.connect(timeout, unit, throwOnUnauthorised)) {
       throw new IOException("Unable to establish a new connection.");   // 成功时反而抛
   }
   ```
   实例方法 `connect(...)` 的语义是"成功返回 true"（javadoc + `AbsAdbConnectionManager` 的用法都这样），
   而这个 Builder 包装器把布尔取反了。真机日志的特征是：每次重试都先 `Handshake succeeded.`（TLS 升级完成）
   再抛 `Unable to establish a new connection.`。
   **修法**：一律 `Builder(...).build()` 后用实例 `connect(...)` 判真假。
   **这条同时是 `project-status-20260929.md` §4「唯一未通的一环」的真正根因**（旧链的
   `LibAdbClient` 走的就是这个包装器）⇒ 旧方向第 ⑤ 步也一并修好了。

3. **失败/中断的那次连接必须关掉** ✗
   上面那个 bug 让"其实已建立"的连接被当成失败，而失败路径又不关闭它 ⇒ 泄漏的会话和它的读线程一直留着，
   后续重试在与它竞争（用户观察到的"第一次连接成功后没有释放，导致后面的连接失败"）。**修法**：
   `connect()` 的每次尝试用 `finally` 兜底，凡不交还调用方的连接一律 `close()`。

4. **通知的生命周期** ✗
   配对码通知曾被设成 `setOngoing(true)`（拖不掉），且配对成功后没有释放 ⇒ 用户报告"通知框 bug"。
   **修法**：提示类通知改 `setOngoing(false)` + `setAutoCancel(true)`；收到配对码、以及整条流程结束时
   （成功或失败）都 `cancel`；整条流程**只留一条**结果通知（去掉中间那条"配对成功"）。

## 7. 签名 key：为什么仓库里放了一把 key

`keystore/ghostlock-dev.jks` 是**刻意提交**的（细节与安全提示见 `keystore/README.md`）。原因：
仓库没有签名 secrets ⇒ CI 走 AGP 的 debug key ⇒ **每个 runner 现生成** ⇒ 每次构建签名都不同 ⇒
覆盖安装 `INSTALL_FAILED_UPDATE_INCOMPATIBLE` ⇒ 必须卸载 ⇒ **卸载清掉 app 私有目录里的
`adbkey.pk8` 与配对记录** ⇒ 每装一个构建都要重新配对。仓内固定 key 之后，构建之间 `adb install -r`
直接可用，密钥与配对状态都保留。解析顺序：`local.properties` → 环境变量/secrets → 仓内 key（secrets 优先）。

5. **同一身份的第二条连接会被 adbd kick** ✗
   第二次点「连接并自检」时，新连接刚建好，自检的第一条命令就抛 `IOException: Stream closed.`。
   adbd 侧日志（`adb logcat -s adbd`）说明了一切：
   ```
   I/adbd: kicking transport 0xb400007c5746d180 host-25
   E/adbd: [server]: SSL_read failed [invalid library (0)]
   I/adbd: ADB wifi device disconnected
   W/System.err: java.io.IOException: Stream closed
   ```
   即：**以同一客户端身份再建一条连接，adbd 会 kick 掉一条 transport**，而被 kick 的正是自检刚打开流的
   那条。原先的实现是"先建新连接、再关旧连接"，等于瞬间存在两条同身份连接。**修法**：能复用就复用
   （`isConnected && isConnectionEstablished`），必须重连时**先关旧、再连新**；自检失败则丢弃连接、
   自动重连一次再自检，绝不留半死连接在字段里。

## 9. 通道管理：`AdbService`（持有连接 + 保活）与 `AdbCommand`（发命令）

设备上的失败分两类，而"一条命令一条通道"只解决了一类：

* 每命令一条通道 ⇒ **连接次数暴增**，而同一客户端身份的每次新连接都有被 adbd kick 的风险（adbd 在
  同身份出现第二条连接时会 kick 一条 transport），实测约一半的新连接首条命令就 `Stream closed.`；
* 持有一条会话 ⇒ 不会再撞这个竞争，但会话会**悄悄变成僵尸**：被 kick 的 transport 在 libadb 里
  `isConnected`/`isConnectionEstablished` 仍然是 true，而读线程再也不返回。

因此按用户 2026-10-01 的定稿改成两层：

* **`wireless/AdbService.kt`** —— 会话的所有者：开一条连接并**持有**它；每 5s 跑一次往返探针
  （`true`，5s 预算）**主动**发现僵尸并丢弃/重连（`everConnected` 之后才重连，避免用户还没配对时刷日志）；
  会话只能有一条，重连前先关旧的；所有操作走同一个 `Mutex`，所以保活探针不会和长命令（例如 W1）打架。
* **`wireless/AdbCommand.kt`** —— 薄壳：`exec(command)` / `exec(command, retries)`，把命令交给
  `AdbService`。第二个可选参数 = **通道失败**的重试轮数（默认 3）：一轮 = 拿到可用会话 + 执行一次命令，
  失败则丢弃会话、等待、换新会话再来；命中 `ChainSpec.NON_IDEMPOTENT` 的命令只跑一轮
  （验证一次、执行一次、绝不重复）。

配套修掉的解析 bug：`cat /sys/fs/selinux/enforce` **输出不带换行**，原来的 `echo MARK$?` 会接在同一行
（`1__GHOSTLOCK_EXIT__0`），按行解析就找不到标记、把成功的命令判成通道失败。现在先 `echo` 补一个换行，
并且解析改为**从最后一次出现的标记处取数字**，标记之前的内容全部算命令输出。

## 10. 仍未验证 / 风险

* **root adbd 是否认配对密钥**：本轮之后必须真机证实（第 ④ 步开门后连 5555）。
  推理上成立（adb_keys 不随 adbd 重启丢失），但**没有实测证据**，属于假设。
* 无线调试通道的 uid 依赖 adbd 的运行模式；若 adbd 正处于 root 模式（`service.adb.root=1`），
  `id` 会返回 `uid=0`，此时"uid=2000"判据会失败 —— 界面会明确报出来，不会被当成成功。
* OPPO/ColorOS 上 mDNS 的广播行为（是否在配对对话框期间真的广播 `_adb-tls-pairing`）
  需要在真机上确认；这是本条路唯一"依赖厂商行为"的地方。

## 11. W1 与 adb 公钥：2026-10-01 定稿（app 用自己的引擎与 profile）

### 11.1 W1 不再跑设备上的 `w1.sh`

原先第 1 步是 `sh /data/local/tmp/gl-w1/w1.sh`，也就是**设备上恰好放着的那份 `ghostlock`**。
2026-10-01 查到证据：那份是 2026-09-28 推的版本，日志里仍然是
`gate: >=9 colliders, >=50% coverage`，而 app 自己的引擎早已把质量门提到 100%
（提交 `97276f9`，`KERNELSNITCH_EARLY_MIN_COVERAGE_PCT = 100`）。于是"app 在跑 W1"这句话
实际上从来没跑过 app 的引擎 —— 这正是用户报的"为什么还是 50%"。

现在由 **`chain/W1Stage.kt`** 做 `w1.sh` 做过的事，但源文件是 app 自己的：

| 步骤 | 命令/文件 |
|---|---|
| 1 | 推送 `<nativeLibraryDir>/libghostlock.so` → `/data/local/tmp/gl-w1/gl-engine`（两侧 `sha256sum` 比对，一致就跳过；推完重新读回哈希） |
| 2 | app 为当前内核合成的 profile → `/data/local/tmp/gl-w1/gl-profile.bin`（同样按 sha256 增量推送） |
| 3 | `cd /data/local/tmp/gl-w1; export GHOSTLOCK_HOME=… GHOSTLOCK_W1_ONLY=1 GHOSTLOCK_PARK_AFTER_W1=1 GHOSTLOCK_MCAST_SOCKET=tcp6; rm -f gl-w1.log; setsid ./gl-engine --profile /data/local/tmp/gl-w1/gl-profile.bin >gl-w1.log 2>&1 &` |
| 4 | 轮询 `gl-w1.log`（1s 一次，最长 90s），出现 `Write 1 complete` 即落地；引擎 5s 后就不在了且没有落地 ⇒ 立刻判失败 |

照搬脚本自带的四条约束：`--profile` **必须是绝对路径**；进程必须 `setsid` 分离（否则 adb shell
会话结束会带走它）；引擎**写文件而不是管道**（这个进程不允许因为 EPIPE/SIGPIPE 死掉）；**park 的进程
永远不 kill**（只有重启能清掉）。落地的进程名是 `gl-engine`（`pidof` 用它判活）。

推送走 `AdbCommand.push`（`adb push`）而不是设备侧 `cp`：PJA110 上 uid 2000 **列不出**
`/data/app/<pkg>/lib`（实测 `ls: No such file or directory`），app 的私有目录对 shell 不可见。

### 11.2 adb 公钥相关逻辑整条删除

用户定稿：**"adb 公钥的所有逻辑，当前 adb 已经 pair，不需要这个逻辑"**。于是：

* 删除 `adb/AdbKey.kt`、`adb/AdbClient.kt`、`adb/LibAdbClient.kt`、
  `io/github/muntashirakon/adb/AdbPubkeyBridge.kt`、`wireless/WirelessAdb.kt`；
* 删除 `IRootShellService.pushAdbKey()`（AIDL id=4）、`RootShellService.push_adb_key`、
  以及 `magica.cpp` 里的 `glk_push_adb_key`（`fork → setresgid/setresuid(1000) → 追加
  /data/misc/adb/adb_keys → _exit`）与它的 JNI 注册；
* 依赖里移除 `libadb-android`、`conscrypt-android`、`sun-security-android`，proguard 里随之删掉
  Conscrypt 的 `-keep`/`-dontwarn`（这些只为 libadb 的 TLS exporter 存在）。

理由是配对本身就把密钥交给了 adbd（§1：`adb pair` 会登记公钥并写入 adb_known_hosts），
第 5/6 步重启 adbd 也不会丢掉 `/data/misc/adb/adb_keys`。

### 11.3 第 7-9 步改用内置 adb CLI（`RootAdbd`）

`chain/RootAdbRunner` 是新的接口，实现 `wireless/RootAdbd`：`adb connect 127.0.0.1:5555`
（最多 6 轮、1.5s 间隔，因为 adbd 刚重启完还没监听），随后每条命令都用 `-s 127.0.0.1:5555`。
`AdbService` 记住这个 **root serial**：它优先于无线通道，且保活循环改为看守它 ——
否则保活会去重连已经死掉的无线 transport，而那会 kick 掉链后面几步正在用的 root 会话。

### 11.4 重试次数上调（全部只作用于通道失败）

| 位置 | 原值 | 现值 |
|---|---|---|
| `RootChain.sh` 默认 | 1 | 3（`ChainSpec.TRANSPORT_RETRIES`） |
| `AdbCommand.DEFAULT_RETRIES` | 3 | 5 |
| `AdbService.connectAdvertised` 轮数 | 3 | 5 |
| `ChainSpec.ROOT_CONNECT_ROUNDS` | – | 6 |
| `ChainSpec.BOOT_FACTS_ATTEMPTS` | 4 | 6 |
| `ChainSpec.HANG_ATTEMPTS`（am hang） | 2 | 3 |

`NON_IDEMPOTENT`（`am hang`、`rmmod`、`ksud late-load`、`setprop` 两步、以及新增的
`GHOSTLOCK_PARK_AFTER_W1`）**仍然只执行一次**：重试只发生在"命令很可能没跑"的通道失败上。

### 11.5 本节引入的新假设（必须真机验证）

* **adbd 在 5555 上必须接受配对时登记的那把密钥**。这是 §10 早已列出的未验证项；现在它成了
  第 7 步能否成功的唯一前提（以前是 libadb 用自签密钥再写一次 adb_keys）。失败时现象是
  `adb connect` 报 `device unauthorized` / `failed to authenticate`，UI 日志会直接给出该行。
* W1 用 app 自己的引擎之后，日志里应当出现 **100%** 的质量门（`>=100% coverage`），
  这是判断"真的换了引擎"的现场证据。

### 11.6 2026-10-01 追加（用户定稿）

* **`ksud late-load` 只看返回码**：`ksud` 装载成功后会**重启 adbd**，所以它之后任何走 adb 的读取都必然
  失败。原先的 `VERIFY` 步骤（`/proc/modules` 里找 `kernelsu`）正是这样把成功读成失败 —— 已整步删除，
  枚举 `ChainStep` 也从 8 步减到 7 步；`KSU_LATE_LOAD` 现在要求 `exit code == 0`，否则报退出码失败。
* **两件设备工具打进 app**：`assets/device/kread_min.ko`（302344 B，取自设备 `/sdcard/kread_min.ko`）
  与 `assets/device/fix-selinux.sh`（2384 B，取自 `/data/local/tmp/gl-w1/fix-selinux.sh`）。
  `chain/DeviceSync.kt` 在链开始前按 sha256 增量推送到 `/data/local/tmp/gl-w1/`（`ko` 644、`sh` 755），
  失败只警告不中断链。资产不能直接 push，先落到 `cacheDir` 再推。
* **步骤列表不再显示 detail**：成功之后那行小字（步骤最后一条命令/输出）会被截断，看起来像坏掉；
  UI 现在只显示步骤名 + 状态图标，完整输出仍在日志面板与 `chain-state.txt` 里。

### 11.7 2026-10-01 首次用自家引擎跑 W1 的现场记录（未完成，待复跑）

`/data/local/tmp/gl-w1/gl-w1.log`（2742 B，16:05）证明**用的确实是 app 的引擎**：质量门是
`gate: >=9 colliders, >=100% coverage`（旧引擎同一行是 50%）。但该次运行停在
`[T+9029ms] heap spray done`，没有 `Write 1 complete`，`gl-engine` 进程随后不在，
`getenforce` 仍是 `Enforcing`。随后（16:07）设备上出现了用户手动 `w1.sh` 的运行记录（`w1.log` 6564 B），
且 `gl-engine`/`gl-profile.bin` 被清理 —— 因此**不能断定**是引擎崩溃：也可能是那次清理脚本把 park 进程
与文件一起删了。复跑一次（重新点「一键 root」）即可区分：成功时日志里应出现 `Write 1 complete`，
并且 `pidof gl-engine` 有 pid、SELinux 变 Permissive。

## 12. 无线调试界面改成本 app 的主题（2026-10-01）

用户反馈：点开无线调试那个界面「太单调」。原来它是 Android 原生控件堆出来的诊断页
（`TextView`/`Button`/`ScrollView`），和 app 的 miuix 主题完全无关。现在：

* `ui/wireless/WirelessScreen.kt`（新）：Compose + `MiuixTheme(light/darkColorScheme())`，
  结构是「状态卡 → 动作卡 → 手动配对码卡（仅通知不可用时）→ 通道详情卡 → 日志面板」；
* 状态卡沿用主界面激活卡的调色板：**未配对=琥珀**（`#FFF1D6`/`#3B2715`）、**已配对=蓝**
  （`#DCE9FF`/`#16243A`）、**通道就绪=绿**（`#DFFAE4`/`#173923`），右下角是同一个大状态图标；
* 日志复用主界面的 `LogPanel`（`GhostlockUi.kt` 里由 `private` 改 `internal`），
  `FormatLogUseCase` 把引擎输出解析成 tone 再映射成同一套颜色，并加了复制按钮；
* `WirelessDebuggingActivity` 只留宿主职责：状态（`mutableStateOf` + `WirelessStateListener`）、
  通知权限、系统栏，其余全在 `WirelessScreen` 里。

真机验证（PJA110，versionCode 524）：`uiautomator dump` 里能看到「已配对 / 已配对。点「连接并自检」/
打开无线调试 / 连接并自检 / 忘掉配对 / 通道详情 / 端点 192.168.0.113:42509 / 日志 / 无线调试」；
截图取色：状态卡 `#16243A`（深色主题下的"已配对蓝"）、动作卡 `#242424`、日志面板 `#0B1220`
（与主界面日志面板同色）⇒ 主题与调色板确实生效（设备当前是深色模式）。

## 13. 利用路径按 am hang 分成 Part 1 / Part 2（2026-10-01）

用户定稿：「把当前利用路径替换为 part1 和 part2，不在本阶段的步骤不显示，然后通过 selinux 和
Seccomp 判断当前阶段（以 `am hang --allow-restart` 命令分界，之前的 part1，之后是 part2，
pre 不在规则之内）」。

* `ChainStep` 现在带 `phase`：`PREFLIGHT` 为 **null**（不属于分段，永远显示）；
  **Part 1** = `W1` + `AM_HANG`（新增独立步骤，`am hang --allow-restart` 就是分界线本身）；
  **Part 2** = `MAGICA_ROOT`（启动 uid-0 服务）→ `OPEN_ADB_GATE` → `ADB_CONNECT` →
  `REMOVE_GUARD` → `KSU_LATE_LOAD`。原来 `am hang` 挤在 Magica 那一步里，现在拆开，
  分界点才和图上的步骤一一对应。
* 阶段判定 `ChainPhaseRule.of(enforce, seccomp)`：`enforce == 0` **且** `Seccomp: 0`
  ⇒ **PART2**（W1 留下的状态，framework 重启不会撤销），其余（enforcing / 读不到 / seccomp 非 0）
  ⇒ **PART1**。两个事实由仓库在 `snapshot()` 里通过无线通道读
  （`cat /sys/fs/selinux/enforce` + `/proc/self/status` 的 `Seccomp:` 行），
  读失败或还没配对时保留上一次的值（`lastChainPhase`）—— 刚被 `am hang` 重启的实例可能还没连上通道，
  这时退化成 PART1 会把当前那一半藏起来。阶段变化会往 logcat（`GhostlockWireless`）打一行，
  附带它依据的两个事实。
* UI：`RootChainStepPanel` 只渲染 `phase == null || phase == 当前阶段` 的步骤，
  标题是「root 链路 · Part 1 / Part 2」；ViewModel 在每次 snapshot 时按当前阶段播种步骤列表，
  所以 `am hang` 重启后重新打开 app 就能直接看到 Part 2。

## 14. 防呆、属性恢复、主界面精简（2026-10-01）

### 14.1 预检里的防呆：已经有 root 就不跑链

`PREFLIGHT` 现在多做一件事：通过同一条 uid-2000 通道跑 `su -c id`（`ChainSpec.SU_PROBE`，
20s 预算）。拿到干净的 `uid=0` 就**当场结束并报成功**，不做 W1、不 `am hang`：

```
[+] 预检：`su -c id` 拿到了 uid=0 ⇒ 本机已有 root，不必执行利用链
[+] root 可用（su -c id 返回 uid=0）—— 利用链已跳过，没有伪造任何内核状态。
```

理由：这条链每一步都在改内核状态（伪造 waiter、挂 system_server、重启 adbd），在已经拿到 root
的机器上跑它只有代价没有收益。判据只认「干净 uid=0」：命令没跑（通道失败）、超时、退出码非 0 都按
「没有 root」处理 —— 这个方向的误判只是多跑一次链，反向误判会让用户什么都拿不到。
（如果希望这种情况报"异常"而不是"成功"，改 `run()` 里那一处的返回值即可。）

### 14.2 rmmod → ksud 之间的属性恢复（新步骤）

新增 `ChainStep.HARDEN_PROPS`（Part 2，位于 `REMOVE_GUARD` 与 `KSU_LATE_LOAD` 之间）。
窗口是用户给的：安全模块已经卸载、ksud 还没重新加载策略，此时 `resetprop` 可用。
命令按顺序逐条执行并通过 root adbd 执行（`resetprop` 在 adb root shell 的 PATH 里，用户的
`resetprop --help` 就是在 `:/ #` 里跑的）：

| # | 命令 | 作用 |
|---|---|---|
| 1 | `resetprop -c u:object_r:userdebug_or_eng_prop:s0` | **重建** `ro.secure`/`ro.debuggable` 所在的属性区（`-c/--rebuild`），否则后面的写入可能被该区的状态吞掉 |
| 2 | `resetprop ro.secure 1` | 恢复 ro.secure |
| 3 | `resetprop ro.debuggable 0` | 恢复 ro.debuggable |
| 4 | `echo 0 > /proc/sys/fs/suid_dumpable` | 恢复 suid_dumpable |
| 5 | `resetprop -c` | 不带名字 = 重建**全部**属性区（收尾） |

每条命令的退出码都会打日志；**失败不阻断**后面的 `ksud late-load`（那才是持久 root 的来源），
只把失败条数与命令名报出来。

### 14.3 ksud 打进 app（2026-10-01 晚，用户定稿）

用户：「要用绝对地址，把 ksud 集成到 app 内，ksud 内置 resetprop，使用方式类似 busybox，`ksud resetprop`」
——这是对 §14.2 的修正：那一步原来写的是裸 `resetprop`，而**裸 `resetprop` 不在 adb shell 的 PATH 里**
（设备上只有 `/data/adb/ksu/bin/resetprop -> /data/adb/ksud` 这个符号链接）。

* `app/src/main/jniLibs/arm64-v8a/libksud.so` = 从本机 `/data/adb/ksud` 读出的原样副本，
  5326360 字节，sha256 `9f57222b06222f461bbb69b24e40a293e34708eeb7b1bbb065110651f7b9c991`，
  **与原文件逐字节一致**（APK 里也没有被 llvm-strip 动过：`keepDebugSymbols += "**/libksud.so"`）。
  GPL-3.0，已登记在 `app/src/main/jni/THIRD_PARTY_NOTICES.md`（再分发前需要履行 GPL 义务）。
* 链开始前 `DeviceSync.pushKsud()` 按 sha256 增量推送到 `/data/local/tmp/gl-w1/ksud`（0755），
  第 8b 步用**绝对路径**：`$DEVICE_DIR/ksud resetprop …`；推送失败退回 `/data/adb/ksud` 并打日志。
* 真机验证（PJA110，推送后的副本）：`/data/local/tmp/gl-w1/ksud resetprop ro.secure` → `1`；
  `… resetprop ro.debuggable` → `0`；`su -c '… resetprop -Z ro.secure'` →
  `u:object_r:userdebug_or_eng_prop:s0`（与 `HARDEN_CONTEXT` 完全一致）。
* **`ksud late-load` 仍用设备自己的 `/data/adb/ksud`**：late-load 需要找到那台机器上真正安装的
  模块负载，而 `resetprop` 与版本无关 —— 这正是内置副本的用途。
