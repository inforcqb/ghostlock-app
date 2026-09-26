# W1c: 把"伪造 cred"从摆设变成真 cred（2026-09-26）

## 背景：credential 写的附带写落在哪

`WriteMode::Credential` 存的 word **同时**充当伪造 rb 树的 child 指针，所以那次 relink
除了 `*(target) = value` 之外，还会把 8 字节写进 **value 指向的对象里**：

| route | stamp | 附带写 |
| --- | --- | --- |
| MulticastWaiter（本机用的是这条） | `{pc = (target-8)&~3, rb_right = value, rb_left = 0}` | `*(value) = target-8` |
| TCP zerocopy | `{pc = value, rb_right = 0, rb_left = target}` | `*(value+8) = target` |

现在 `value = init_cred alias`，于是附带写打在**全局 `init_cred`** 上。`init_task.cred ==
&init_cred`，且每个 `prepare_kernel_cred(NULL)` 的拷贝都继承这些字节 —— guard 的 kevent
记录 `curr_uid@@-118`（= `target-8` 的高半）就是这次污染的现场，用户态
`oplus_kevent -> IAntiRootDialog -> PowerManager.reboot` 随后把机器重启。

这也是为什么会出现"多加一次 `WriteMode::Zero` repair + 2 个 refcount keeper"：
repair 把 `init_cred.usage` 一起清成 0，于是必须再 fork 两个子进程把计数顶回去。

## 页里那份 cred 拷贝（`fill_profile_cred_copy`）为什么不能直接用

`payload_write_layout()` 目前只把它接到 `layout.fops` 上，没接 `layout.right`。直接换过去
还会踩两个坑：

1. **profile 的引用表整体错位一格**。设备 profile（`5.15.180-...conf`）里：
   `copy_size = 176`（因为 `struct cred` 的 `usage` 是 `atomic_long_t`，8 字节 ⇒ 结构 0xb0），
   字段实际是 `security@0x80 / user@0x88 / user_ns@0x90 / ucounts@0x98 / group_info@0xa0`；
   而 ref 的目标偏移是 `128/136/144/152`（= security/user/user_ns/ucounts），
   来源却是 `init_cred+0x80 / init_user_ns / init_ucounts / init_groups`。
   ⇒ `security` 拿到的是 `&init_cred.security`（指向字段本身）、`user_ns` 拿到 `init_ucounts`。
   后果：`cap_capable()` 永远匹配不上 `&init_user_ns`（**满 cap 拿不到**），
   `cred_sid()` 读出的 sid 是指针的半截 → sidtab 查不到 → **每个过 SELinux hook 的系统调用
   返回 -EINVAL**（permissive 只免判决，不解引用/不兜底）。
2. **`caps_count = 3` 没填 `cap_bset`**（0x48）。bset 为 0 时 `execve` 会剥掉全部 cap，
   `PRE_CMD` 里那个 fork+exec 的 `rmmod` 子进程会是**零 cap**，卸载必然失败。
   另外 `security` 必须是**有效**的 `task_security_struct`（静态 profile 无法携带运行期的
   blob 指针），最省事的做法是在页里放一个 `{osid = sid = SECINITSID_KERNEL}` 的假 blob。

## 本分支做了什么

`GHOSTLOCK_CRED_FROM_COPY=1`（默认关闭）时：

- `payload_write_layout()`：`layout.right = credential_fops`（= 页内 cred 拷贝地址），
  于是 `*(target) = 页内拷贝`，附带写落在**我们自己的页**里（拷贝的 +0 = `usage`），
  `init_cred` 完全不被碰；
- `fill_profile_cred_copy(..., as_credential=true)`：
  - 把这 3 个 static 全局**重新摆到内核真正读的字段**上：`user_ns@0x90 = init_user_ns`、
    `ucounts@0x98 = init_ucounts`、`group_info@0xa0 = init_groups`（`user@0x88` 留 0，
    它在最终 `put_cred` 之前不会被读，而 `usage` 被附带写成一个巨大值 ⇒ 永不归零）；
  - `security@0x80` = 页内假 blob（`copy + 0xc0`，`osid = sid = SECINITSID_KERNEL`）；
  - `cap_bset@0x48` = 满 cap；
  - 并把 `usage/bset/security/user_ns/ucounts/group_info` 打进日志，便于下一次跑的时候直接核对。
- `exploit_stages.cpp`：`credential_install_from_copy()` 为真时**不再发 init_cred repair**、
  不再 fork keeper；`PRE_CMD` / `LOAD_KO` 一律提到 repair 之前，把"满 cap → guard 被卸载"
  之间的窗口压到最短（`ROOTCHECK-RC` 会在采样到的下一个 syscall 上杀这个进程）。

## 怎么验

1. 编译 + 推二进制；`tools/device/w1c.sh` 里把 `#export GHOSTLOCK_CRED_FROM_COPY=1` 打开；
2. 看日志：
   - `cred copy: usage=... security=0xffffff8... user_ns=0xffffff8... ...` 里
     `security/user_ns/ucounts/group_info` 必须都是 `0xffffff8...` 的直映射地址；
   - 两次 `multicast route status=0 ... success=1` 之后，`/proc/<pid>/status` 的
     `CapEff` 应该是 `000001ffffffffff`（w1c.sh 的自证行）；
   - 之后 `PRE_CMD: rc=0`、`LOAD_KO: finit_module(...) rc=0 errno=0`；
   - **`W1c: forged credential installed; init_cred repair not fired`** —— 且
     `dmesg | grep ROOTCHECK` 不应出现 `curr_uid@@-118` 这类污染记录。
3. 反例（如果拷贝不对）：不会有 panic 级别的问题（所有指针都是已映射的内核静态地址或
   我们自己的页），典型现象是 SELinux hook 返回 -EINVAL、`capable()` 不成立 —— 即
   日志停在某一步、`rmmod`/`insert` 失败。这时把该环境变量去掉即可回到当前行为。

## 仍未解决

- `cred_ref0_image` 那格（`security`）在**没有** `GHOSTLOCK_CRED_FROM_COPY` 时仍然是错的，
  只是以前没人把它当真 cred 用。要不要顺手把 profile 的引用表按符号重出一版
  （security 用页内 blob 的占位、user 用 `root_user`），是下一步的事。
- 那页 cred 必须**长期存活**：`GHOSTLOCK_CRED_FROM_COPY=1` 之后，最后一次写用的 payload 页
  就是 cred 本体，不能被 `cleanup_page_prepare_state()` / `close_reclaim_sockets()` 回收
  （当前的 stage 顺序满足这一点，因为 repair 已经不再发新的写）。
- guard 的 `ROOTCHECK-RC` 判据本身还没定：现在只能确认"它按 syscall 采样、与 uid 跳变无关"，
  以及"命中即杀进程（同 tgid 连坐）"。
