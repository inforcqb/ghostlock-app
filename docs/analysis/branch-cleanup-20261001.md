# 分支清理（2026-10-01）

`main` 之外的远端分支在这次清理中全部处理完毕。原则：**不丢提交** —— 每条分支先以
`git merge -s ours --allow-unrelated-histories` 落进 `main`（只记录父提交，**不回退 main 的树**），
确认它们的提交已成为 `main` 的祖先之后再删分支引用。

| 分支 | 处理前 HEAD | 与 main 的关系 | 处置 |
|---|---|---|---|
| `wireless-pairing` | `b1de9bf` | 已并（双亲合并 `fc4dae9`） | 删分支 |
| `app-snapshot-20260929` | `5656a00` | 已并（是上面那条线的祖先） | 删分支 |
| `w1c-cred-copy` | `5656a00` | 同上 | 删分支 |
| `w1-shift4` | `c7d203b` | 旧 main 线的后代（PR #1） | `-s ours` 合并 `df4ba3c` → 删分支 |
| `mcast-msfilter-calib` | `f45cde8` | 无关历史（385 个 main 没有的提交） | `-s ours` 合并 `67861d0` → 删分支 |
| `very-not-stable-dev` | `61fc789` | 无关历史（359 个） | 合并时已是 HEAD 的祖先（`mcast` 线的祖先）→ 删分支 |
| `w1-shift4-resident` | `c0b15a7` | 无关历史（396 个） | `-s ours` 合并 `e18a0d1` → 删分支 |
| `w1c-self-root` | `4212e73` | 无关历史（425 个） | `-s ours` 合并 `c4f9efe` → 删分支 |

**为什么用 `-s ours`**：这些分支是 9 月的旧实验线（mcast msfilter 标定、w1 shift 系列、w1c 系列），
它们的树比当前线旧得多；直接合并会把 app / 链回退到它们的状态。`-s ours` 只把它们的历史并进来
（提交仍可取回、可 `git push origin <sha>:refs/heads/<名字>` 复活），`main` 的内容保持当前线不变 ——
合并前后 `git diff --stat` 为空，逐字节相同。

**PR**：只有 `w1-shift4` 能在 fork 里开成 PR（#1）；其余四条 GitHub 拒绝开 PR
（`No commits between main and <branch>`：GitHub 的 compare 把它们看成 `behind / ahead=0`），
所以用同样的本地 `-s ours` 合并代替。

**上游**：全部操作只在 fork `inforcqb/ghostlock-app` 内，没有向 `YuKongA/ghostlock-app` 提交任何东西。
