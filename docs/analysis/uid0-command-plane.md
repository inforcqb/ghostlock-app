# uid-0 命令平面：为什么是命令（2026-10-02 实测）

链在 Magica 步骤之后要做的事，全部发生在**我们自己的隔离 uid-0 进程**里：它 `CapEff=0x1c0`、
`CapBnd=0`（没有 `CAP_DAC_OVERRIDE`），SELinux 当时是 permissive。

**结论（先写在这里）**：命令平面就是**一条命令字符串**，由隔离进程 `fork` + `execve` 一个
`/system/bin/sh -c` 去跑。**不做进程内原生动作**——不是保守，是实测证明做不到（下一节）。
所以 AIDL 上只有 `String execShell(String command, int timeoutMs)`，链侧只有 `chan(command)`。

## 1. 现场证据

2026-10-02 那次运行，链走到「提权环境恢复」的第一步就失败，原生日志是：

```
channel: __system_property_set resolved from libc at 0x79af8b8cb8     ← 平台属性客户端拿到了（不是它的问题）
channel: __system_property_get resolved from libc at 0x79af8b8b78
channel: setcon(u:r:adbd:s0) failed (13: Permission denied)           ← 域根本没借到
channel: setprop service.adb.tcp.port=5555 in u:r:adbd:s0 -> rc=-1 read-back=""
[!] 提权环境恢复 failed: 通道执行失败：__GHOSTLOCK_EXEC_FAILED__: property_set(service.adb.tcp.port, 5555) rc=-1 in u:r:adbd:s0
```

同一台设备、同一次开机，用 adb（uid 2000，`u:r:shell:s0`）做对照实验：

| 实验 | 结果 |
|---|---|
| `runcon u:r:adbd:s0 id` | `context=u:r:adbd:s0` ✓（exec 型域转换可用） |
| `echo u:r:adbd:s0 > /proc/self/attr/current` 然后 `cat` | `u:r:adbd:s0` ✓（单线程 shell 里，setcon 也可用） |
| `setprop service.adb.tcp.port 5555`（shell 域直接写） | `Failed to set property`，rc=1 ✗ |
| `cat /sys/fs/selinux/enforce` | `0`（permissive） |

最后一行值得注意：**permissive 并没有让那次 `setprop` 通过**。属性写入的判定在本机确实会按
调用方的上下文拒绝（是 property_service 的 MAC 检查，还是属性区/持有者检查，这次没有进一步区分）——
"permissive 兜底"不能当作设计前提。

## 2. 两个机制原因（都不依赖 SELinux 是否 permissive）

**(a) `/proc/self` 指向线程组 leader。** 我们的服务是多线程的（binder 线程池），AIDL 调用落在非
leader 线程上，而 `/proc/self/attr/current` 解析到的是**进程 leader** 的属性文件；内核只允许任务写
**自己**的属性（`current != task` ⇒ 返回 **EACCES**）。观察到的 `13: Permission denied` 正好是这个，
而且 logcat 里**没有 `avc: denied`** —— 它根本没走到 SELinux 判定。对照实验里单线程的 shell 能写成功，
也印证了这一点。

**(b) 就算切换成功也没用：property_service 看的是进程上下文。** 它取调用方的
`/proc/<tgid>/attr/current` 做授权，即**线程组 leader 的标签**。在服务进程内部 `setcon`（哪怕成功）
改的是某个线程的标签，init 侧检查的仍然会是 `isolated_app`。要让它看到 `adbd`/`usbd`，这个域必须属于
**一个独立的进程** —— 也就是 `runcon` + exec 的子进程，这正是最初 runbook 里那条链的形状。

## 3. 现在的形状

| 步骤 | 命令（逐字） |
|---|---|
| step 4 通道自检 | `id` |
| step 5 开 adb 门（域：adbd_config_prop） | `runcon u:r:adbd:s0 setprop service.adb.tcp.port 5555` |
| step 6 重启 adbd（域：ctl_adbd_prop） | `runcon u:r:usbd:s0 setprop ctl.restart adbd` |
| 等待监听 | `ss -lnt`（轮询，**判定权在 `adb connect`**） |

执行方式：`RootChannel.exec(command, timeoutMs)` → binder → `RootShellService.execShell` →
JNI `exec_shell`：`fork` + `execve("/system/bin/sh", ["sh","-c",cmd])`，stdin=/dev/null，
stdout+stderr 走管道，带 deadline，超时 SIGKILL；spawn 失败/超时在返回文本里带
`__GHOSTLOCK_EXEC_FAILED__: <reason>`，调用方不会误判成"跑了但没输出"。

子进程继承本进程的 uid 0 与（0x1c0 的）capabilities。**JVM 的 `Runtime`/`ProcessBuilder` 会掉到
app uid（实测 `uid=90000(u0_i0)`），但 `fork`+`execve` 不会** —— 这两件事经常被混为一谈。

监听轮询是**建议性**的：`ss -lnt` 跑在隔离进程的子进程里，它的 `/proc/net` 视图未必是 adbd 所在的
那个；真正的判定是紧接着的 `adb connect`（`ROOT_CONNECT_ROUNDS = 6` 轮）。所以轮询读不到只记日志，
不再中止步骤。

## 4. 被撤回的方案（留个记性）

同一天早些时候试过把这些步骤做成 .so 里的原生动作（`channel_identity` /
`channel_set_prop_in_domain`（`setcon` + 平台 `__system_property_set`）/ `channel_wait_port`
（读 `/proc/net/tcp{,6}`）），想法是"没有 shell、没有 fork、没有可冻结的东西"。其中两条本身没问题
（身份读取、监听表读取都工作），但**域借用那一步在架构上就不成立**（§2），而域借用正是这一步的全部意义。
用户当天的指示是「命令能跑就用命令，而不用原生的」，方案据此撤回，代码回到 `4d0ab23` 的命令平面。

顺带记下那条仍然有价值的发现：`magica.cpp` 包含 `<api/system_properties.h>`，它带进 `hacks.h` 的
`#pragma redefine_extname __system_property_set __system_property_set2`，于是这个编译单元里所有
`__system_property_set` **引用**都会绑到 vendored 客户端（直写属性区、不通知 property_service）——
这就是 `adb_root()` 里 `ctl.restart` "成功但没反应"、要靠 `pkill` 兜底的原因。要从这里写属性，
必须自己 `dlopen("libc.so")` + `dlsym` 取平台客户端；**但链本身不需要它**（链是命令，走 `setprop`）。
