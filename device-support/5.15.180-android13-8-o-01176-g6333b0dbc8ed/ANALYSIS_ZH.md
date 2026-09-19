# GhostLock (CVE-2026-43499) 本机提权可行性分析报告

| 项目 | 值 |
| --- | --- |
| 设备 | OPPO PJA110 / OP5943L1（oplus 项目号 22851，kalama / SM8550，arm64） |
| 内核 | `5.15.180-android13-8-o-01176-g6333b0dbc8ed`（2025-12-12 构建） |
| 页面/VA | 4 KiB 页；39-bit VA；`CONFIG_ARM64_4K_PAGES` |
| SELinux | 启动参数 `androidboot.selinux=permissive`（**已处于宽容模式**） |
| 当前环境 | Android 内核上的 Ubuntu 24.04 chroot，uid=0 真 root，但**非 Android 域** |
| 结论 | ✅ **漏洞真实存在，本机内核未修补，可提权** |

---

## 1. 漏洞本体

CVE-2026-43499（NebuSec 命名为 **GhostLock**，kernelCTF 获奖）是
`kernel/locking/rtmutex.c: remove_waiter()` 中一个存在约 **15 年**
（Linux 2.6.39-rc1 → 7.1-rc1）的 **use-after-free**：

- `remove_waiter()` 原本为「自己阻塞自己」的慢路径编写，因此一直清的是
  **`current->pi_blocked_on`**；
- 但 requeue-PI 代理路径（`rt_mutex_start_proxy_lock()` ← `futex_requeue()`）
  是**代表另一个睡眠任务**入队，此时 `current` 是 *requeuer* 而不是 *waiter*；
- 当代理入队命中 `-EDEADLK` 回滚时，`remove_waiter()` 把**错误任务**的
  `pi_blocked_on` 清空，真正的 waiter 任务带着仍然指向自己
  `FUTEX_WAIT_REQUEUE_PI` 栈帧 `rt_mutex_waiter` 的 `pi_blocked_on`
  **返回用户态**——该栈帧在 syscall 返回瞬间即被释放；
- 之后任何 PI 链遍历都会顺着这个悬垂指针走，构成 UAF。

**触发前提（极少）**：只需 `CONFIG_FUTEX_PI=y`。
**不需要**：任何 capability、user namespace、网络、内核地址泄露前置条件。
普通线程 + futex 系统调用即可，因此这是一个 **unprivileged local root**。

---

## 2. 本机验证（硬证据）

`/proc/config.gz`：

```
CONFIG_FUTEX=y
CONFIG_FUTEX_PI=y     <-- 唯一的必要条件
CONFIG_PREEMPT=y
CONFIG_RT_MUTEXES=y
CONFIG_KALLSYMS_ALL=y
```

**直接从 boot 分区反汇编活内核的 `remove_waiter()`**（KASLR slide 由
kallsyms 的 `_text` 精确求出）：

```
_text (runtime) = 0xffffffed04600000
KASLR shift     = 0x2c84600000        (即 static 0xffffffc080000000)
remove_waiter   = runtime 0xffffffed0623dfc0  ->  static 0xffffffc081c3dfc0
```

函数体内出现修补版本绝不会有的指令：

```asm
mrs  xN, sp_el0          ; 读取 current
add  xD, xN, #0x884      ; &current->pi_lock      (task_pi_lock = 0x884)
str  xzr, [xN, #2224]    ; current->pi_blocked_on = NULL  (0x8b0)
```

这**正是** `tools/extract_rs` 用来拒绝已修补内核的判定式
（`derive.rs: remove_waiter_uses_current()`：命中 `mrs xN, sp_el0` 即判定存在
漏洞，修补版永不读取 `current`，预检会以 **exit 6** 拒绝）。本机命中了。
独立复核结论：**未修补 = 可被利用**。

> 交叉验证：fork 在 `offsets.h` 注释中记录的
> BTF md5 `67e85746de90ae6386685dae1d3c99b4`
> 与本机 `/sys/kernel/btf/vmlinux` 的 md5 **完全一致**，证明该偏移表就是在本机
> 这台设备上实测得到的。

---

## 3. 本机 per-device 偏移表（已独立复现）

用 `/sys/kernel/btf/vmlinux`（完整 BTF，5936975 字节）+ `/proc/kallsyms`
（`CONFIG_KALLSYMS_ALL=y`，root 可读）在本机重新推导，与 fork 已提交的
`src/kernels/5.15.180-.../offsets.h` **逐字段完全一致**：

| 字段 | 本机 BTF/符号实测 | fork 表 | |
| --- | --- | --- | --- |
| `init_task` | `0x03286400` | 同 | ✅ |
| `init_cred` | `0x0323f3e8` | 同 | ✅ |
| `root_task_group` | `0x033d3580` | 同 | ✅ |
| `selinux_enforcing` (`selinux_state`) | `0x033f9990` | 同 | ✅ |
| `selinux_blob_sizes` | `0x02613d88` | 同 | ✅ |
| `security_hook_heads` | `0x02611900` | 同 | ✅ |
| `nfulnl_logger` | `0x031424f0` | 同 | ✅ |
| `loggers[0][1]` | `0x03142418` | 同 | ✅ |
| `sysctl_bootid` | `0x03516bd1` | 同 | ✅ |
| `task_prio` | `0x7c` | 同 | ✅ |
| `task_normal_prio` | `0x84` | 同 | ✅ |
| `task_sched_task_group` | `0x400` | 同 | ✅ |
| `task_pi_lock` | `0x884` | 同 | ✅ |
| `task_pi_waiters` | `0x898` | 同 | ✅ |
| `task_pi_top_task` | `0x8a8` | 同 | ✅ |
| `task_pi_blocked_on` | `0x8b0` | 同 | ✅ |
| `task_pid` | `0x5d8` | 同 | ✅ |
| `task_tgid` | `0x5dc` | 同 | ✅ |
| `task_atomic_flags` | `0x598` | 同 | ✅ |
| `task_real_cred` | `0x790` | 同 | ✅ |
| `task_cred` | `0x798` | 同 | ✅ |
| `task_comm` | `0x7a8` | 同 | ✅ |
| `task_tasks` | `0x4d0` | 同 | ✅ |
| `task_seccomp` | `0x860` | 同 | ✅ |
| `task_usage` | `0x38` | 同 | ✅ |
| `kernel_phys_load` | `0xa8000000`（`/proc/iomem`: Kernel code `a8010000` = `_stext`） | 同 | ✅ |
| `compact_waiter` | `1`（`rt_mutex_waiter` size `0x58`，扁平布局） | 同 | ✅ |
| `mm_struct_sz` | `0x400`（BTF size `0x3e0`，cacheline 对齐 stride） | 同 | ✅ |

**关键点**：本机 `task_struct` 与 6.x 布局差异极大
（`task_cred` 0x798 vs 6.1 的 0x838；`task_pi_lock` 0x884 vs 0x924），
所以**绝对不能**套用上游自带的 6.1/6.6/6.12 表——必须使用本机实测表。

另注：5.15 中 `selinux_enforcing` 已静态化为 `selinux_state` 结构体首字段，
但 **`selinux_state` 本身在 kallsyms 中可见**（`0xffffffed079f9990`，
rebased = `0x033f9990`），因此该偏移同样是本机实测值，无需猜测。

---

## 4. 三条利用链与本机适配

| 阶段 | 作用 | 本机适配情况 |
| --- | --- | --- |
| **W1** | 写 `selinux_state.enforcing = 0`（置宽容） | 内核 `selinux_enforcing` 偏移已实测；且本机启动即为 permissive，W1 属**冗余保险** |
| **W2** | 把子进程 `cred` 指向 `init_cred` 的直接映射别名 → uid 0 | 需要 `init_cred` + `task_cred` + `kernel_phys_load`，均已实测 |
| **W3** | 清 `TIF_SECCOMP` + `seccomp.mode` 绕过 seccomp | 需要 `task_seccomp`，已实测 |

两条竞态路线：

- **TCP zerocopy 路线**（`getsockopt(TCP_ZEROCOPY_RECEIVE)` 打洞页；
  6.1 compact-waiter 默认）→ 本机 `compact_waiter = 1`，**默认走这条**；
- **pselect 路线**（6.6/6.12 tree-waiter 默认）→ 需
  `pselect_waiter_shift`，fork 表中**未实测**（填 0），可用
  `GHOSTLOCK_TCP_ROUTE=0` 强制回退。

`kernel_phys_load` 是所有地址换算的基准：
`p0_data_alias(img) = ((phys_load + off) - 0x80000000) | 0xffffff8000000000`。
本机 `/proc/iomem` 显示 `Kernel code a8010000`（即 `_stext`，而
`_text = _stext - 0x10000 = 0xa8000000`），与表一致。

**关于 KASLR**：fork-main 新增 `resolve_runtime_text_base()` 从
`/proc/kallsyms` 读 `_text`，但作为普通 app（untrusted_app）读 kallsyms 会得到全 0，
此时会退回默认 `0xffffffc080000000`——而本机正是这个基址，因此不受影响。
真正绕过 KASLR 的是直接映射别名 + KernelSnitch（futex hash 桶计时侧信道，
用于定位 `mm_struct`），与 KASLR slide 无关。

---

## 5. 构建与部署（CI 优先）

**CI 已具备且已成功**：fork `inforcqb/ghostlock-app` 的 `main` 分支已包含完整
5.15/PJA110 支持（领先上游 8 个 commit）。最近一次 push 构建
（run `35448644021`）**全部成功**，产物：

| Artifact | 说明 |
| --- | --- |
| `GhostLock-release` | `GhostLock-release.apk`（2,153,758 B） |
| `ghostlock` | 独立 arm64 可执行文件（81,992 B） |
| `ghostlock-extract-android-arm64` | 设备端偏移提取器 |
| `ghostlock-extract-linux-x86_64` / macos / windows | 桌面端提取器 |

APK 内容已核验，**同时打包了两个原生二进制**：

```
lib/arm64-v8a/libghostlock.so   81992 B   <- 漏洞利用二进制
lib/arm64-v8a/libextract.so   1758120 B   <- 偏移提取器
```

app 运行逻辑：`AndroidGhostlockRepository.kt:231` 取
`applicationInfo.nativeLibraryDir/libghostlock.so`，`require(binary.isFile)`
后以应用自身 uid（无 `su`）直接 `ProcessBuilder` 执行；root 脚本再按需
late-load KernelSU 模块。

构建要点：

- 工作流 `.github/workflows/build.yml`（fork 与上游**逐字节相同**），
  触发条件仅 `main` 分支 push / PR / `workflow_dispatch`；
  **`very-not-stable-dev` 分支不会触发构建**。
- **无需签名密钥**：`SIGNING_KEY` 等 4 个 secret 缺失时
  `keystore.jks` 为 0 字节，`app/build.gradle.kts` 自动回退 debug 签名，
  `assembleRelease` 仍成功并输出 `GhostLock-release.apk`。
- 原生二进制由 Gradle 自己构建：`app/build.gradle.kts:179` 的
  `preBuild → prepareGhostlockJniLibs → buildGhostlockNative(make ghostlock)`
  再 rename 成 `libghostlock.so`，因此 CI 里那步 `make ghostlock` 只是冗余。
- 构建必须联网 `github.com` git（Rust 依赖
  `payload-extract` 走 git rev，ONDK 走 GitHub Release），
  **本机因 443 被封无法复现，必须走 CI**——正是你要求 CI 编译的原因。

### 部署步骤（手机端）

1. 下载 CI 产物 `GhostLock-release.apk`（或 `pre-release` 页）。
2. 安装 APK（debug 签名，需允许未知来源）。
3. 打开 GhostLock；顶部应显示内核匹配
   `5.15.180-android13-8-o-01176-g6333b0dbc8ed`。
4. 点 **Run**。成功后获得 uid 0；若已装 KernelSU/ReSukiSU/KowSU，
   会额外 late-load 模块。
5. 如默认 TCP 路线不稳定，可尝试 `GHOSTLOCK_TCP_ROUTE=0`
   回退 pselect 路线（但 `pselect_waiter_shift` 未实测，成功率不确定）。

---

## 6. 风险与限制

1. **内核崩溃风险**：利用成功后子进程会永久停在被改写的 `init_cred` 上
   （`init_cred` 无引用计数），属于预期行为；但竞态失败可能触发
   `kernel.panic_on_rcu_stall=1` 导致**重启**。
2. `pselect_waiter_shift = 0` 未实测，pselect 回退路线未验证。
3. `selinux_enforcing` 偏移已由 kallsyms 的 `selinux_state`
   （`0x033f9990`）独立确认；如换机请重新运行 `verify_ghostlock.py`。
4. chroot 内的 root **不是** Android root：无法访问 `su`/init 域，
   仍需在 Android 侧执行该 app 才能完成真正的提权落地。
5. 上游/该 fork 的 `prerelease` job 会自动把 **debug 签名**的 APK
   发布成公开 pre-release（`contents: write`），注意来源可信性。

---

## 7. 复现命令

```bash
# 1) 在本机（或该设备 chroot）内独立验证漏洞与偏移
python3 verify_ghostlock.py            # -> RESULT: EXPLOITABLE / offsets verified

# 2) 触发 fork 的 CI 构建
gh workflow run build.yml --repo inforcqb/ghostlock-app --ref main

# 3) 拉取产物
gh api repos/inforcqb/ghostlock-app/actions/runs/<RUN_ID>/artifacts \
  --jq '.artifacts[] | "\(.name) \(.id)"'
```

## 8. 参考

- [NebuSec — CVE-2026-43499 IonStack part II](https://nebusec.ai/buglist/CVE-2026-43499/)
- [Ubuntu CVE-2026-43499（确认 5.15 受影响并已修复）](https://ubuntu.com/security/CVE-2026-43499)
- [YuKongA/ghostlock-app（上游）](https://github.com/YuKongA/ghostlock-app)
- [inforcqb/ghostlock-app（本 fork，含 5.15.180 支持）](https://github.com/inforcqb/ghostlock-app)
