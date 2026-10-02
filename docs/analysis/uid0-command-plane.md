# uid-0 命令平面：三个原生动作（2026-10-02）

链在 Magica 步骤之后要做的事，全部发生在**我们自己的隔离 uid-0 进程**里：它 `CapEff=0x1c0`、
`CapBnd=0`（没有 `CAP_DAC_OVERRIDE`），SELinux 当时是 permissive，所以它能 `setresuid(0)`、
能读 `/proc/self/attr/current`，但没有能力去"随便"操作别的 uid 的文件。

这份文档记的是**命令怎么送进去**，以及为什么它换过三次形状。

## 1. 现在的形状

| AIDL（`IRootShellService`） | 原生（`app/src/main/jni/magica.cpp`） | 它替代的原命令 |
|---|---|---|
| `channelIdentity() = 4` | `channel_identity` | `id` |
| `setPropInDomain(domain, name, value) = 5` | `channel_set_prop` | `runcon <domain> setprop <name> <value>` |
| `waitForPort(port, timeoutMs) = 6` | `channel_wait_port` | `ss -lnt \| grep :<port>` |

调用方是 `RootChannel`（binder 薄客户端）→ `RootChain.chanIdentity / chanSetProp / chanWaitPort`。
三个动作**都是原生实现、都在服务进程内执行**：没有 `fork`，没有 `execve`，没有管道，没有命令字符串。

`setPropInDomain` 内部就是 `setcon(<domain>)` → `property_set(name, value)` → `setcon(切回)`，
即 `runcon` 子进程做的事，只是不再需要那个子进程。域借用本身必须保留：
`service.adb.tcp.port` 的标签是 `adbd_config_prop`，`ctl.restart` 是 `ctl_adbd_prop`。

## 2. 为什么不是 socket，也不是 shell 字符串

两次被真机否掉，都是有记录的事实，不是我推断的：

* **AF_UNIX socket + token**（第一版）：需要"两边都能到达的文件系统路径"。部分设备上父目录
  不存在、隔离域动不了那个 SELinux 标签、或 token 另一侧读不到 ⇒ `bind/listen failed`。
  换到 app 数据目录要两次 chmod + permissive，仍然脆（`.sock` 在一些设备上就是不工作）。
* **shell 字符串走 binder**（第二版，`execShell`）：看起来等价，实际不等价——
  * 隔离进程的 `ProcessBuilder` 子进程**会掉到 app uid**（真机实测：隔离进程自己是 uid 0，
    子进程 `id` 打印 `uid=90000(u0_i0)`）⇒ `sh -c runcon …` 里的 `runcon` 根本没以 uid 0 跑；
  * 缓存的进程会被 freezer 冻住，冻住时"发命令"这件事本身就没有意义；
  * 命令字符串还得在对面再解析一遍，等于把同一件事做两次。

## 3. ★ `setcon` 之后，属性写必须走 property_service

这是本轮最要紧的一条，也是链里唯一"静默失效"过的环节。

`magica.cpp` 包含 `<api/system_properties.h>`，而那个头文件包含 `hacks.h`，里面写着：

```c
#pragma redefine_extname __system_property_set __system_property_set2
```

后果：**这个编译单元里所有 `__system_property_set` 引用都被改名**，绑到 vendored 的 AOSP
libcutils 客户端上——它直接写属性区（shmem），**从不通知 property_service**。
而 `ctl.*` 是**由 init 处理的控制消息**，不经过 property_service 就等于没发生。

这正是 `adb_root()` 里那条注释的由来（"ctl.restart does not fire on this handset: measured
twice… while adbd kept its pid"），也是它后面要补 `pkill -9 adbd` 的原因。

所以 `channel_set_prop_in_domain` 用 `platform_property_set()` 从 **libc 自己的符号表**取平台客户端
（`dlopen("libc.so")` + `dlsym`），**并且刻意不设回退**：回退到 vendored 客户端就是复现那个静默 no-op，
宁可让这一步直接报错。符号在**域切换之前**解析（`dlopen`/`dlsym` 是 loader 的活，不该在借来的域里做）。

写完之后用同一个平台客户端**读回**并打进日志（`read-back="…"`）。读回**只记录、不判定**：
`ctl.*` 是控制消息，可以不落进属性区，所以"读回为空"不是失败；对 `service.adb.tcp.port`
这类真属性，读回值就是 property_service 收下的值。

## 4. 监听探测为什么返回三种答案

隔离进程**没有 IP socket**（真机实测：`socket(AF_INET)` 返回 -1，同时 Seccomp 显示 mode 2 / 3 filters；
文件顶部那句 "No TCP code may be added to this file" 就是这条测量事实）。所以
`connect(127.0.0.1:5555)` 这种探针**不可用**，只能用读内核表的方式，即
`/proc/net/tcp` + `/proc/net/tcp6` 里找 `st == 0A`（LISTEN）且端口匹配的条目——
`ss -lnt` 打印的就是同一张表。

答案故意是**字符串**而不是布尔，因为有三种，而只有两种跟 adbd 有关：

| 返回 | 含义 | 链的反应 |
|---|---|---|
| `listening: …` | 表里有 LISTEN | 立刻结束等待，算证据 |
| `not-listening: …` | 表读到了，没有该端口 | 只记日志，交给 `adb connect` |
| `unreadable: …` | 表根本读不到（errno 附在文本里） | 只记日志，交给 `adb connect` |

"我看不到"和"它不在"是两个不同的陈述，判定权交给 app 进程里的 `adb connect`
（它在正常进程里，`ROOT_CONNECT_ROUNDS = 6` 轮重试）。

## 5. 仍然留在 adb 侧的步骤

`selinuxRepairCommands()`（`insmod kread_min.ko` / `sh fix-selinux.sh` / `rmmod kread_min`）、
管理端安装、属性恢复（`ksud resetprop …` / `suid_dumpable`）、`ksud late-load` 都还在 adb 侧：
那时链已经持有 root adbd（uid 0 + `CapEff 0x1ffffffffff`），这些活它做得比隔离进程干净，
而且它们本来就是设备侧工具的职责。

**一个已知的悬留项**：`RootShellService.adbRoot()`（移植自上游 Magica 的 adbd patch）内部用
`system()` fork shell，并 `pkill -9 adbd`。链**不依赖**它的结果（门是用 `chanSetProp` 开的），
但它每次 `IsolatedRootShell.launch()` 都会跑一遍，会在门的旁边额外杀一次 adbd。
要不要删掉这个调用，等这一轮真机结果出来再定。

## 6. 怎么读日志（`adb logcat -s GhostlockRoot`）

原生侧：

```
channel: __system_property_set resolved from libc at 0x…
channel: setprop service.adb.tcp.port=5555 in u:r:adbd:s0 -> rc=0 read-back="5555"
channel: setprop ctl.restart=adbd in u:r:usbd:s0 -> rc=0 read-back=""
channel: wait_port 5555 -> listening: /proc/net/tcp{,6} holds a LISTEN on 5555
channel identity: uid=0(root) gid=0(root) groups=0(root) context=u:r:isolated_app:s0
```

链侧（UI 日志同源）：

```
[*] u:r:adbd:s0 → service.adb.tcp.port=5555：service.adb.tcp.port=5555 (in u:r:adbd:s0) read-back="5555"
[*] u:r:usbd:s0 → ctl.restart=adbd：ctl.restart=adbd (in u:r:usbd:s0) read-back=""
[+] adbd 已在 5555 上监听（listening: …）
```

失败形态对照：

| 日志 | 含义 |
|---|---|
| `__GHOSTLOCK_EXEC_FAILED__: libc's __system_property_set is not resolvable` | 拿不到平台客户端（不再回退，直接停） |
| `__GHOSTLOCK_EXEC_FAILED__: property_set(…) rc=N in <domain>` | property_service 拒了这次写 |
| `channel: setcon(<domain>) failed` | 域没借到（SELinux 不是 permissive？） |
| `not-listening: …` / `unreadable: …` | 见 §4，判定权在 `adb connect` |
| `通道自检 第 N/3 次：uid=0(root) … context=u:r:isolated_app:s0` | 通道自检通过的样子 |

## 7. 验证状态

* CI：构建 + release 通过（见提交 `3f25933`）。
* 真机：**待跑**。要看的四条就是 §6 里的原生日志行——尤其是
  `__system_property_set resolved from libc`（说明绕开了 vendored 客户端）和
  `ctl.restart … rc=0` 之后 `adb connect 127.0.0.1:5555` 是否拿到 uid 0。
