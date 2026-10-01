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

## 8. 仍未验证 / 风险

* **root adbd 是否认配对密钥**：本轮之后必须真机证实（第 ④ 步开门后连 5555）。
  推理上成立（adb_keys 不随 adbd 重启丢失），但**没有实测证据**，属于假设。
* 无线调试通道的 uid 依赖 adbd 的运行模式；若 adbd 正处于 root 模式（`service.adb.root=1`），
  `id` 会返回 `uid=0`，此时"uid=2000"判据会失败 —— 界面会明确报出来，不会被当成成功。
* OPPO/ColorOS 上 mDNS 的广播行为（是否在配对对话框期间真的广播 `_adb-tls-pairing`）
  需要在真机上确认；这是本条路唯一"依赖厂商行为"的地方。
