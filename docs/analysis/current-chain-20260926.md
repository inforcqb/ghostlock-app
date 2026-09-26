# 当前可用链（2026-09-26 冻结）与 app 集成的命令白名单

背景：fastboot 阶段注入 SELinux 宽容的那个洞在 **2026.3** 被修；本链用幽灵锁的 **W1**
补上"宽容"这一环，其余继续走已跑通的旧路径，最终拿到 KernelSU 的持久 root。

状态：**已经端到端跑通**（2026-09-26，一次 boot 内完成：W1 → Magica → root adbd →
`rmmod oplus_security_guard` → `ksud late-load` → `su` 得到 `u:r:ksu:s0`）。

---

## 1. 冻结的命令序列

> **app 集成时必须逐字复用下表命令。** 不要改用"简化命令"（见 §3 的黑名单），
> 也不要在链里插入未验证的等价写法：这台机器上任何未验证的改动都可能换来一次重启。

| # | 执行者（身份/域） | 原命令（逐字） | 作用 |
|---|---|---|---|
| 1 | adb shell / Shizuku：`uid=2000`，`u:r:shell:s0`，`Seccomp: 0` | `sh /data/local/tmp/gl-w1/w1.sh` | W1：`Enforcing → Permissive`；跑完脚本返回，**exploit 进程 park** |
| 2 | adb shell（uid 2000） | `am hang --allow-restart` | 让 system_server 挂掉并允许重启，Magica 的 zygote 才能正常起来 |
| 3 | 用户在设备上 | 启动 Magica（`am start -n io.github.vvb2060.puellamagi/.MainActivity`），点"启用 rootshell" | 拿到 `u:r:isolated_app:s0` 的 **uid 0 通道**（`CapEff=0x1c0`，**无 caps**） |
| 4 | 上述 uid 0 通道 | `sh /data/local/tmp/gl-w1/rshell` | 进入根通道 shell（unix socket + token） |
| 5 | 通道内，**必须借 adbd 域** | `runcon u:r:adbd:s0 sh` → `setprop service.adb.tcp.port 5555` | `service.adb.tcp.port` 属 `adbd_config_prop`，只有 adbd 域有 `set` |
| 6 | 通道内，**必须借 usbd 域** | `runcon u:r:usbd:s0 sh` → `setprop ctl.restart adbd` | `ctl_adbd_prop` 只授予 `usbd`（`plat_sepolicy.cil`） |
| 7 | PC/app：adb 连 `<设备IP>:5555` | `adb connect <IP>:5555` | 得到 root adbd shell：`uid=0`、`u:r:su:s0`、`CapEff=0x1ffffffffff` |
| 8 | 该 root shell | `rmmod oplus_security_guard` | **本链的真正目标之一**（要满 cap） |
| 9 | 该 root shell | `/data/adb/ksud late-load` | **目标之二**：装载 KSU，得到持久 root |

第 5、6 步能成功的前提是第 1 步已经把 SELinux 打成 **Permissive**（借域＝`dyntransition`
在 permissive 下才放行）。第 9 步会**重新加载策略**，把 SELinux 拉回 Enforcing —— 这是
**预期行为**，不是故障；此后特权操作用 KSU 的 `su`（`u:r:ksu:s0`）。

---

## 2. 每一步怎么验证

```sh
# 1) W1 落地
sh /data/local/tmp/gl-w1/w1.sh --status      # 期望 enforce=Permissive + 一个 parked ghostlock
getenforce                                   # Permissive

# 2/3) 通道
sh /data/local/tmp/gl-w1/rshell id           # 期望 uid=0 ... context=u:r:isolated_app:s0
cat /proc/self/status | grep -E 'Cap(Eff|Bnd)'   # 期望 0x1c0 / 0  —— 所以它做不了 rmmod

# 5/6) 门开了
getprop service.adb.tcp.port                 # 5555
getprop init.svc.adbd                        # running
ss -lnt | grep 5555                          # LISTEN *:5555

# 7) 满 cap 到了
adb shell id                                 # uid=0 ... context=u:r:su:s0
adb shell cat /proc/self/status | grep Cap   # CapEff/CapBnd = 0x1ffffffffff

# 8/9) 结果
lsmod | grep -E 'oplus_security_guard|kernelsu'   # guard 不在、kernelsu 在
su -c id                                          # uid=0 context=u:r:ksu:s0
```

---

## 3. 命令黑名单（**app 里不许用**）

下面这些是"看起来更省事"的等价写法，用户明确否决：**做 app 时一律用 §1 的原命令。**

| 被否决的写法 | 为什么被否决 |
|---|---|
| `ksud resetprop service.adb.tcp.port 5555`（绕过 adbd 域） | 未经真机验证的捷径；链已经能跑，不做替换 |
| 用 `resetprop` 写 `service.*` / 用 legacy 通用域（`surfaceflinger`/`crash_dump`…）触发 `ctl.*` | 同上：绕门禁的写法一律不引入 |
| 任何"少一步/合并一步"的重排（例如省掉 `am hang`） | 每一步都是实测出来的，重排未验证 |

Magica 内部自己做的事（`ro.debuggable`、`service.adb.root`、adbd patch）**保持原样**，
不在链里重写。

---

## 4. 不变量与已知坑

* **guard 三件套每次开机都会回来**（`oplus_security_guard` refcount 0 / `oplus_secure_harden`
  1 used-by guard / `oplus_security_keventupload` 2）：所以第 8 步每个 boot 都要重做。
* **第 1 步的 park 进程不能 kill**（内核 exit 时走伪造 PI 状态会 wedge）；但实测 `am hang`
  与 `ksud late-load` 之后它常常已经不在了，机器没事（两次都如此）。
* **W1 偶发 panic**：规律未查明，暂搁置。
* **pid 复用**：不要用旧日志里的 pid 认进程（`w1.log` 里的 `13777` 已变成
  `thermal-engine-v2`）。相关工具（`cleanup-w1.sh`）已按 `comm` 做身份校验。
* **USB gadget 可能没绑**（`/config/usb_gadget/g1/UDC` 为空 ⇒ USB 侧完全没反应）：
  走 TCP（第 5~7 步本来就走 TCP）；救回 USB 用 `adbd-recover.sh`。
* **门开了没人关**：`service.adb.tcp.port` 绑 `*:5555`，且此时是 root shell。当前接受这个
  窗口（用户明确说不做收尾）；`service.adb.tcp.port` 与 `resetprop` 改的 `ro.*` 都**不持久**，
  重启自然还原。
* **KSU 之后 SELinux 回 Enforcing** 是预期；别把它当异常去"修"。

---

## 5. 分支/仓库状态

* **主线**：本文件描述的链。**不使用 W1c。**
* **W1c 已移除**（2026-09-26）：伪造 cred 补丁（`GHOSTLOCK_CRED_FROM_COPY` 以及
  `payload_builder` / `util.cpp` / `target*.h` 的改动）、`exploit_stages.cpp` 里的 W1c 阶段、
  还有 `tools/device/{w1c.sh, w1c-adbd.sh, w1c-self.sh}` 全部删除；那套分析只留在 git 历史里。
  `gl-chain.sh` 相应收敛成"只跑 W1"的驱动。
* **保留的设备侧工具**：`w1.sh`（W1）、`adbd-recover.sh`（USB gadget/`UDC` 空时救 adbd）、
  `cleanup-w1.sh` + `cleanup-parked.sh`（W1 park 的安全网；链本身不做收尾）。
* **进行中**：app 内一键集成（Shizuku 跑 W1 + 搬 Magica + app 内 adb 客户端）。
  设计见 `docs/analysis/root-chain-integration.md`；命令集严格按 §1。
