# W1 报告：SELinux permissive 注入的写入形态与隐患清单

> 范围：本文只做**记录与判读**。所有隐患**本迭代一律不处理**（边界见 §7），
> 链的命令与步骤保持 2026-09-26 冻结版本不变。
>
> **产物登记**：类型 = 分析报告（W1 写入形态 / 隐患清单 / 判读方法 / 依赖视图 + 逻辑视图）；
> 状态 = **已交付，只记录不处理**；日期 = 2026-09-27；
> 位置 = `docs/analysis/w1-report.md`；分支/提交 = `w1c-cred-copy` / `67ac079`（正文）、
> `9470c10`（两张视图）；关联产物 = app 集成链（`root-chain-status.md`、`current-chain-20260926.md`）。
>
> 相关文档：`root-chain-integration.md`（链设计）、`current-chain-20260926.md`（设备侧冻结 runbook）、
> `root-chain-status.md`（交接状态）。

## 1. W1 在链里的位置与触发条件

* 链的第 2 步（`ChainStep.W1`）。触发身份：uid 2000 + `Seccomp: 0`（Shizuku user service），
  **无 root、无 KSU**。
* 设备侧：`sh /data/local/tmp/gl-w1/w1.sh`（`tools/device/w1-selinux.sh`）；
  app 侧：`GhostlockUserService.runW1Only()` 起 `libghostlock.so`，env
  `GHOSTLOCK_W1_ONLY=1` + `GHOSTLOCK_PARK_AFTER_W1=1`
  （`app/src/main/kotlin/com/ghostlock/app/shizuku/GhostlockUserService.kt:156-168`）。
* 目的：把 SELinux 从 Enforcing 推到 Permissive，供链的第 5/6 步用 `runcon` 借
  `adbd`/`usbd` 域。`ksud late-load` 之后回到 Enforcing 是**预期行为**，不是失败。

## 2. 写入原语的本性：8 字节整字，值还兼任 walk 指针

* 两条传输走同一个语义：`*(target) = value`，waiter 的三个字是
  `{pc = value, right = 0, left = target}`，节点为 RED 所以没有颜色修复
  （`src/core/exploit_ops.cpp:237-239`）。
* **关键约束**：这个 `value` 同时就是 PI walk 要解引用的伪造 rb-tree child pointer
  （`exploit_ops.cpp:255-259`），所以它**必须是可解引用的内核地址（或 0）**。
  这一条决定了字的形状，也决定了下面 H4/H5 的存在。
* 目标地址 = `alias(selinux_state) + off_selinux_enforcing`。本机（OPPO PJA110 /
  5.15.180-android13-8）该 alias 是 `0xffffff802b3f9990`，且 W1 的字正好落在 `+0`
  （`exploit_stages.cpp:240-264`）。

## 3. 我们这条链实际写进去的字

**走的是非 resident 路线**：`multicast_resident_enabled` 默认 `false`，只有
`GHOSTLOCK_5X_RESIDENT` 才打开（`src/core/session/runtime_config.cpp:128,142-143`），
而 `w1.sh`（`tools/device/w1-selinux.sh:57-60`）与 app 侧 env 都没设它。
所以值不是 resident 分支的空零页 alias，而是喷出页推导出来的：

```
layout.right = (mode == Zero) ? page_base + 0x100 : init_cred_alias
```

（`src/core/memory/payload_builder.cpp:79-82`；`page_base` = 喷出页的内核线性别名，4 KiB 对齐。）

逐字节落到 `selinux_state` 的字段（字段顺序依据 `exploit_ops.cpp:260-261` 的注释与实测）：

| 字偏移 | 我们链里的值 | 字段 | 后果 |
|---|---|---|---|
| +0 | `00`（页对齐 ⇒ 低字节必 0） | `enforcing` | **= 0，permissive ✅ 这就是 W1 的全部目的** |
| +1 | `01`（`page_base` 低两字节 00 00，+`0x100` ⇒ 恒为 01） | `checkreqprot` | 被写成 **1**，且**每次都一样**（不是随机）→ H2 |
| +2 | 奇数（页规则强制） | `initialized` | 保住非零 ✅ → H1 说明为什么必须这样 |
| +3..+5 | 页地址中段字节 | `policycap[0..2]` | 污染 → H3 |
| +6..+7 | `FF FF`（canonical 顶部；本机 alias 是 `0xffffff80…`，实测为三个 FF） | `policycap[3..4]` | 污染 → H3 |

即 LE 内存序形如 `00 01 <odd> .. .. .. FF FF`——与"`00 any any … FF FF`"这个记忆一致，
其中第二个字节其实恒定是 `01`。

**byte2 必须是奇数**由非 resident 的页规则保证：`prepare_good_kernel_page()` 抽到偶数
byte2 的页就丢弃重抽（`src/core/util.cpp:765-772` → `payload_write_layout_accepts_page()`，
`payload_builder.cpp:120-124`，日志 `page … stores an even byte over
selinux_state.initialized; taking another`）。resident 分支不喷页，改用把地址按 `0x10000`
步进最多 8 次把 bit16 顶成 1（`exploit_ops.cpp:271-280`，日志
`resident word 0xffffff80035a2000 -> 0xffffff80035b2000 (byte 2 made odd)`，见
`memory/2026-09-23.md:353`）。

### 3.1 依赖视图（谁产出字节，谁依赖哪个字节）

读法：左半是"要给足什么才能写出这个字"，右半是"哪些字节真的有人依赖"。要点是
**只有 `+0` 与 `+2` 有依赖方**，`+1`/`+3..+7` 是无人依赖的残值。

```mermaid
flowchart LR
  subgraph IN["输入 / 前提"]
    direction TB
    I1["Shizuku user service<br/>uid 2000 + Seccomp 0"]
    I2["env: GHOSTLOCK_W1_ONLY=1<br/>GHOSTLOCK_PARK_AFTER_W1=1"]
    I3["profile.bin<br/>off_selinux_enforcing / route=3 / mcast 参数"]
    I4["GHOSTLOCK_5X_RESIDENT 未设<br/>⇒ multicast_resident_enabled = false"]
    I5["喷出页 page_base<br/>页规则：byte2 必须为奇"]
  end

  W["W1 写入：8 字节整字<br/>*(alias(S) + 0) = page_base + 0x100"]

  subgraph OUT["落字节 +0..+7"]
    direction TB
    O0["+0 enforcing = 00"]
    O1["+1 checkreqprot = 01"]
    O2["+2 initialized = 奇"]
    O3["+3..+7 policycap[0..4]<br/>= 页地址字节"]
  end

  V["判据 check_selinux_off()<br/>/sys/fs/selinux/enforce == '0'"]

  subgraph DEP["依赖方"]
    direction TB
    D1["步骤 5/6：runcon adbd / usbd<br/>（唯一硬依赖）"]
    D2["所有 SID 查询<br/>（隐式硬依赖）"]
    D3["ksud late-load 之后回 Enforcing"]
    D4["无人依赖：残值<br/>事后用 kread 回填"]
  end

  P["park 进程驻留<br/>（不可 kill：退出即楔死）"]

  I1 --> W
  I2 --> W
  I3 --> W
  I4 --> W
  I5 --> W
  W --> O0
  W --> O1
  W --> O2
  W --> O3
  O0 --> V
  V --> D1
  O0 --> D3
  O2 --> D2
  O1 --> D4
  O3 --> D4
  W -.->|"写成功但进程不能退出"| P
  P -.->|"整机存活才有后续步骤"| D1
```

### 3.2 逻辑视图（W1 的判定与分支）

读法：这是我们这条链（非 resident）实际走的路径；右列是 resident 才有的分支，
以及"保险失效"的那条灾难分支（H1）。注意 `enforce` **不可读**时按 enforcing 处理并照跑 W1。

```mermaid
flowchart TD
  S["W1 入口（uid 2000 / Seccomp 0）"] --> Q0{"check_selinux_off()<br/>enforce 可读且为 0 ?"}
  Q0 -->|"是：已经 permissive"| X0["SELinux already permissive<br/>跳过 W1"]
  Q0 -->|"否：enforcing，或 enforce 不可读<br/>（不可读按 enforcing 处理）"| Q1{"multicast_resident_enabled ?<br/>（只有 GHOSTLOCK_5X_RESIDENT 打开）"}
  Q1 -->|"否：我们这条链"| P1["prepare_good_kernel_page()<br/>抽页，layout.right = page_base + 0x100"]
  Q1 -->|"是：resident"| P2["空零页 alias 派生写入字"]
  P1 --> C1{"payload_write_layout_accepts_page()<br/>byte2 为奇 ?"}
  C1 -->|"否"| R1["page … even byte over initialized<br/>taking another（丢弃，重新抽页）"]
  R1 --> P1
  C1 -->|"是"| W
  P2 --> C2{"byte2 为奇 ?"}
  C2 -->|"否"| R2["地址按 +0x10000 步进（最多 8 次）"]
  R2 --> C2
  C2 -->|"是"| W["8 字节整字写<br/>*(alias(S) + 0) = 写入字"]
  W --> C3{"写后 check_selinux_off()<br/>enforce == 0 ?"}
  C3 -->|"否"| F["Write 1 failed<br/>停 resident 路线 → StageResult::Failed"]
  C3 -->|"是"| RP{"resident ?"}
  RP -->|"否：我们这条链"| R3["W1b: private scratch repair<br/>quarantine → repair → release<br/>（修 scratch 页的 poison，不碰 selinux_state）"]
  RP -->|"是"| R4["W1 policycap repair<br/>在 S+4 再写一个字（& ~0x1fffff）"]
  R3 --> Z{"GHOSTLOCK_W1_ONLY ?"}
  R4 --> Z
  Z -->|"是"| Z1["W1-only diagnostic complete<br/>→ park 驻留，进程不退出"]
  Z -->|"否"| Z2["继续 W1c / W2 / W3<br/>（echo 0 &gt; checkreqprot 的 fixup 在这一段里）"]
  W -.->|"byte2 偶数的灾难分支（H1）"| BAD["permissive but smashed<br/>没有 [+] SELinux permissive<br/>→ 楔死，本节流程救不回"]
```

## 4. 隐患清单（**全部不处理**）

每条给：机制 / 证据 / 影响 / 为什么不处理。

### H1 `initialized`（byte2）落到偶数 ⇒ "permissive but smashed"，楔死

* 机制：偶数 byte2 把 `selinux_state.initialized` 清成 0，之后**每一次 SID 查询都失败**；
  表现为 enforcing 确实变成 0 但**没有** `[+] SELinux permissive`，随后机器卡死/重启。
* 证据：2026-09-22 21:21 那次跑（用户自己跑 C++ calib 版）：8 字节落在 `+0`，实测
  `checkreqprot←0x20`、`initialized←0x3a`、`policycap[0..4]←2b 80 ff ff ff`
  （`memory/2026-09-22.md:157-162`）；该次直接导致楔死，正是注释里的 "permissive but smashed"。
* 现有保险：非 resident 的页规则 / resident 的 0x10000 步进。**保险失效就同归于尽**
  （没有第二道判据会在落地后救回来）。
* 不处理：已在链内自动规避；再加固意味着改页规则/引擎，收益与风险不成比例。

### H2 `checkreqprot` 被写成 1（byte1，恒定）

* 机制：值 = `page_base + 0x100` ⇒ byte1 恒 `0x01`，而 byte1 落在 `checkreqprot`。
  该字段是 deprecated，语义是"用请求的 prot 而不是实际 prot 做 AVC 检查"。
* 证据：代码推导（`payload_builder.cpp:79-82`）+ 同类落字节实测（`0x20` 那次，
  `memory/2026-09-22.md:161`）。
* 影响：window 内可能出现与预期不同的 AVC 判定（偏严或偏松都取决于具体操作），
  但我们链需要的操作（`runcon` 借域、`setprop ctl.*`、adb、`rmmod`、`ksud late-load`）
  在 2026-09-26 的验证跑里都没受影响。
* 为什么没人修：能修它的那句 `echo 0 > /sys/fs/selinux/checkreqprot` 在
  **W2/W3 的 fixup 脚本**里（`exploit_ops.cpp:444-445`），而 W1-only 在
  `exploit_stages.cpp:468-470` 就提前 return 了 ⇒ **我们这条链从来不执行它**。
* 不处理：回填属于"提权之后写回正常值"的范畴，用户手动 kread 处理，且不影响判定（§6）。

### H3 `policycap[0..4]` 被页地址字节污染，且我们这条链**没有**修复枪

* 机制：+3..+7 五个字节 = 喷出页地址的中段与顶部字节。**非 resident 分支没有 policycap
  修复**——那个"W1 policycap repair"（在 `enforcing+4` 再写一个 `& ~0x1fffff` 的字）是
  **resident 专属**（`exploit_stages.cpp:449-466`）；非 resident 跑的是
  `W1b: private scratch repair`，修的是私有 scratch 页里的 poison，不是 `selinux_state`
  （`exploit_stages.cpp:419-448`）。
* 影响：`policycap[]` 每个 cap 最终是 0 还是非 0，取决于**当次页选择与 KASLR 滑动** ⇒
  同一套代码在不同 run 上可能给出不同的 capability 集合（某个 cap 关掉 = 该类操作多出拒绝）。
* 这是"W1 偶发异常"的**候选解释之一，但未证实**（我们目前没有任何一次 run 的完整
  policycap 落值 + 对应失败现象），明确标注为假设。
* 不处理：同上，回填交给手动 kread；链只要求 §6 那两个条件。

### H4 不能用"精确常量"当写入值

* 机制：值兼任 walk 指针，塞非指针常量会在 PI walk 里被当 child pointer 解引用。
* 证据：2026-09-22 用 `0x0101000000000000` 试了三次，全部在 `mcast prep done` 之后、
  `resident write` 之前立刻 panic（`exploit_ops.cpp:286-291`）。
* 影响：想要"只改第一个字节"的简洁方案在当前引擎里不可用；必须把"存入的字"与
  "walk 用的指针"解耦（老引擎的做法是 `pselect_w1_shift_word` 把 `fake_right` 覆盖成
  可解引用地址，见 `payload_builder.cpp:111-115` 对 `util.c:758` 的引用）。
* 不处理：解耦要改引擎核心 + 重跑真机验证，而当前形态已验证可用。

### H5 把目标往前挪也解决不了（`-7` 从来就是无效的）

* 机制：store 地址只保证 **4 字节对齐**（`parent = target - 8` 且 stamp 里 `(target-8) & ~3`）
  ⇒ `S-7` 取整成 `S-8`，**根本碰不到 `enforcing`**；而 `S-4` 虽然能对齐，但要让
  enforcing 收到 0x00 就必须让字里 byte4 = 0x00，而"页对齐指针"的 byte4 恒为 `0x80..0xff`
  （`exploit_stages.cpp:222-230`）。
* 证据：calib 分支注释写的是 "shift the target back by 7 … so nothing else is touched"，
  但打印出来的 target 是**未偏移的** `…9990` —— 注释与表达式不一致（实现 bug），
  于是 8 字节仍落在 `+0`，这就是 2026-09-22 那次楔死的直接原因（`memory/2026-09-22.md:157-162`）。
  真正可行的是 `S-4` + 精确词方案（分支 `w1-shift4`，commit `c7d203b`，`BinW1` run
  `35733460268` success）：落 `[S-4..S-1]=0 / [S]=0 / [S+1]=0 / [S+2]=01 / [S+3]=01`，
  `policycap[1..4]` 完全不碰、不需要修复枪（`memory/2026-09-22.md:167-173`）。
* 不处理：那是另一套引擎（原始 C 版）的补丁，当前 C++ 引擎没合，且 H4 决定它在这里要先解耦。

### H6 W1 之后那个 park 进程不能 kill

* 机制：进程退出时内核会沿伪造的 PI/futex waiter 做清理 ⇒ 楔死/重启。
* 证据：脚本与文档里明确 `parking after W1: forged PI state kept alive (pid=…);
  do NOT exit/kill this process`（`tools/device/w1-selinux.sh:22-24`）。
* 影响：唯一的干净退出是重启；这也意味着"失败重试"要整机重启，不是重跑脚本。
* 不处理：链按用户要求不做收尾（park 留着，靠重启还原）。

### H7 平台反制 / 上报

* 机制：`oplus_security_guard`（uid/gid 转换策略，命中即 kill + `KEVENT_ROOT_EVENT`）、
  `oplus_secure_harden`（原语特征启发式 → `KEVENT_HARDEN_EVENT`）、
  `oplus_security_keventupload`（genl → userspace → dump/reboot）三层。
* 证据：实测有过"W1 落地后不久系统被重启"；这也是 W1 之后必须**尽快**做掉两条特权命令、
  不允许拉长 permissive 窗口的原因。
* 不处理：反制不在本迭代范围（另见链的设计文档）。

### H8 状态不持久

* 机制：重启后 `oplus_security_guard` 等模块回归，SELinux 回 Enforcing，`selinux_state`
  也复位。
* 影响：**每次 boot 都要重跑整条链**（app 内一键的意义就在这里）。
* 不处理：这是已知设计约束。

### H9 残留污染窗口：W1 → `ksud late-load` / 重启

* 窗口内 `checkreqprot` = 1、`policycap[]` = 页地址字节，直到策略重载或重启；
  `enforcing` 由 `ksud late-load` 回 1（预期），`initialized` 本来就保住。
* 不处理：见 §6——判定只看 enforcing/initialized；正常值回填用手动 kread 做。

## 5. 判读方法（从日志反推这次落了什么）

| 日志行 | 含义 |
|---|---|
| `W1: SELinux target=0x… (8-byte word, byte 2 made odd)`（`exploit_stages.cpp:264`） | 本次目标地址（相对 alias 无偏移即 `+0`） |
| `page … stores an even byte over selinux_state.initialized; taking another`（`util.cpp:766-767`） | H1 的保险在重抽页（说明确实有页被丢弃） |
| `resident word 0x… -> 0x… (byte 2 made odd)`（`exploit_ops.cpp:277`） | **只有 resident 分支**才打印；出现即说明这次不是我们链的路线 |
| `W1 policycap repair failed`（`exploit_stages.cpp:462`） | resident 专属修复枪失败（非 resident 不会有这行） |
| `Write 1 complete` 且**同时**有 `[+] SELinux permissive` | 真正成功；只有前者没有后者 = H1 的 "permissive but smashed" |

## 6. 为什么这些隐患不影响链（判定充分条件）

* 链对 W1 的**唯一判据**是 `check_selinux_off()`：读 `/sys/fs/selinux/enforce` 是否为 `'0'`
  （`src/core/exploit_ops.hpp:32-41`）。
* 之后所有特权动作依赖的是"SID 查询可用"，也就是 `initialized != 0`。
* 因此结论（用户 2026-09-27 确认，与代码一致）：**只要 `enforcing == 0x00` 且
  `initialized != 0x00`，其余字节写脏不影响提权逻辑**；需要正常值时事后写回即可
  （用户手动用 kread 回填，实测无副作用）。

## 7. 边界：明确不做的事

1. 不改 W1 的目标地址、写入字、页规则与步进逻辑。
2. 不给 app 链增加"回填/收尾"步骤（沿用 2026-09-26 用户指令：不需要考虑收尾）。
3. 不把 §4 的任何隐患做成自动修复；正常值回填一律手动 kread。
4. 若将来要处理（**仅记录，不实施**）：最少改动是把 resident 的 policycap 修复与
   `echo 0 > /sys/fs/selinux/checkreqprot` 前移到 W1 之后——但那会动到冻结链，
   必须重跑一次真机验证；彻底的方案是 H4 的解耦 + `S-4` + 精确词。

## 8. 证据索引

* 代码：`src/core/exploit_ops.cpp:237-239,255-297,444-445`、
  `src/core/session/exploit_stages.cpp:216-264,419-470`、
  `src/core/memory/payload_builder.cpp:70-83,108-126`、
  `src/core/util.cpp:738-785`、`src/core/session/runtime_config.cpp:128,142-143`、
  `src/core/exploit_ops.hpp:32-41`、
  `tools/device/w1-selinux.sh:22-24,36-60`、
  `app/src/main/kotlin/com/ghostlock/app/shizuku/GhostlockUserService.kt:156-168`。
* 实测记录：`memory/2026-09-22.md:107-116,138-142,157-173`、`memory/2026-09-23.md:353`、
  `MEMORY.md:281`。
* 设备/构建事实：route=3 MulticastWaiter、`mcast_waiter_off=32`、tcp6 carrier、
  `alias(selinux_state)=0xffffff802b3f9990`（`tools/device/w1-selinux.sh:6-10`）。
