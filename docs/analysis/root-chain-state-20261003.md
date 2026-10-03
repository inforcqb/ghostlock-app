# GhostLock 链条:任务目标 / 当前状态 / 下一步

> 记录时间:2026-10-03(第二轮更新:同日,`57d4b6c1b` / `2e148a076`)· 仓库 `inforcqb/ghostlock-app`(main)· 相关仓库 `inforcqb/kp_rmap_guard_lkm`(kread_min)、`inforcqb/oneplus-susfs4ksu-lkm`、`inforcqb/Magica`

## 0. 任务目标

**总目标**:在一台只有 `adb shell`(uid 2000)、没有其它漏洞的机器上,用 CVE-2026-43499 把链条跑到
**持久 root**(KernelSU `late-load`),并且:

- 全程不被 OPPO 安全模块(harden / guard → `oplus_kevent` → 反 root 重启)打断;
- 用完能把 `selinux_state` 恢复成正确值(不靠重启);
- 不留 wedged 的 parked 进程(退出前把伪造 PI 状态擦干净)。

**本阶段子目标(app 侧)**:

1. uid-0 命令面回到**交互模型**(类似 adb 模块:一个进程持有链接,其它进程/客户端提交命令),
   **不是** AF_UNIX socket server;
2. 命令执行必须 `fork + setgroups/setresgid/setresuid(0,0,0) + exec`(JVM spawn 会掉到 app uid);
3. 监听失败时用 **runcon** 回退(换到 `u:r:system_server:s0` 再监听);
4. chain **入口早期判 part**;若 PART2 则第一件事拉起 Magica;
5. **APK 安装移到 part1、W1 之前**;
6. **part2 不依赖 adb 通道**;大提示显示 **「Part 2 已就绪」**。

## 1. 已完成并验证

| 项 | 状态 | 证据 |
|---|---|---|
| W1(SELinux 转宽容) | ✅ 硬件验证 | `w1.log`:`Write 1 complete` / `W1-only diagnostic complete` / `parking after W1 (pid=…)`,`getenforce` → Permissive |
| `am hang --allow-restart` → Seccomp 0 | ✅ 设备验证 | 软重启后 14 个进程全 `Seccomp 0` |
| OPPO 模块逆向 | ✅ | 两个模块只 `do_exit`/kevent 上报,**不能重启**;`uid==0` 是它们的早退条件 ⇒ 天生 root 的进程不可见 |
| `selinux_state` 字段与修复 | ✅ 设备验证 | `+0 enforcing`、`+1 checkreqprot=0`、`+2 initialized=1`、`+3..+10 policycap[]={0,1,2,5}`(策略只声明 4 个 cap);用 `kread/kwrite` 现场恢复过 |
| `new_boot.img` 字段 diff | ✅ | 新旧镜像同尺寸;`selinux_state`/`init_task`/`root_task_group`/`task_struct.*`/`mm_struct_sz=0x3e8`/`rb_erase` 全部**同址同字节** ⇒ profile 无需重推;`kernel_phys_load` 需真机日志确认;`.ko` vermagic 因内核版本号变了要重编 |
| parked 清理脚本 | ✅ 就绪 | `cleanup-parked.sh`(kallsyms/pid 定位 + 读回验证 + kill),自带 `insmod` 兜底与工作目录回退 |
| `startChannel()` 时序 bug | ✅ 已修 | `IsolatedRootShell.kt`:3 次 × 3s 重试,失败才抛 |
| uid-0 command server(native) | ✅ 编译验证 | `app/src/main/jni/gl_server.cpp` + `gl_server_start()`;`bin.yml` run `37084659961` success |
| JNI 入口 | ✅ 已推 | `magica.cpp` 表项 `start_command_server(ILjava/lang/String;Ljava/lang/String;)I` |
| service 调用点 | ✅ 已推 | `RootShellService.startChannel()` 在 `uid=0` 自检通过后启动 server |
| client 门面 | ✅ 已推 | `root/RootCommand.kt`(协议 + `exec(domain=…)`) |
| 引擎兼任 server | ✅ | `ghostlock --glserver --port N --token T`(`src/core/main.cpp`),供 runcon 回退 |
| 大提示文案 | ✅ 已推 | `strings.xml` `root_chain_part2` = **"Part 2 已就绪"** |
| part2 去 adb(一半) | ✅ 已推 | `PRIV_ENV` 的 `chanOpenAdbGate()`/`chanRestartAdbd()` 改 `try/catch`,失败只记日志 |
| ④b adb 通道降级为「可选」 | ✅ 已推 | `RootChain.kt`:`RootExec` 接口 + `privileged()`(adb 优先、uid-0 命令面兜底、adb 抛异常即永久切换);`adb.connect()`/identity/CapEff 全部只记日志;`ksud late-load` 也走 `privileged()` |
| ③ 入口早期判 part | ✅ 已推 | `run()` 入口一次 `readBootFacts()` + 一行「阶段判定:**PART 1 / PART 2**」;`readFact()` 让 enforce/Seccomp/hang 标记在 uid-2000 通道没了时改读 uid-0 命令面(Seccomp 用 `/proc/1/status`);repo 侧 `resumedPart2()`(读 `ChainStateStore`,纯文件 I/O)在 part 2 续跑时**不再要求无线通道**;UI `rememberedPart2Phase()` 让 part-2 面板与「Part 2 已就绪」在 framework 重启后仍显示 |
| ① APK 安装前移 | ✅ 已推 | 新 `ChainStep.MANAGER_INSTALL`(PART1,在 `W1` 之前),`PRIV_ENV` 里的安装删除;part 2 续跑时该步自跳过 |
| 命令面 token 落地 | ✅ 已推 | `AndroidGhostlockRepository.prepareCommandPlane()`:随机 48 hex token → `<filesDir>/token` + `<filesDir>/port`(供 `RootCommand`),同字节 `DeviceSync.pushText()` → `/data/local/tmp/gl-w1/token`(供隔离进程内的 server);失败只记日志(空 token = 无鉴权,server 端 `if (token && *token …)` 会跳过校验) |
| `magica2jni` target 补回 | ✅ 已推 | APK 构建自 gl_server 那批提交起一直是**红的**(`make: *** No rule to make target 'magica2jni'`,run `37085075891`);`Makefile` 现在按 `app/src/main/jni/Android.mk` 手抄 `magica2`/`lsplt`/`system_properties` 三模块源码,`-static-libstdc++`(APK 不带 `libc++_shared.so`)、保留 `-fvisibility=hidden` + `-Wl,-exclude-libs,ALL`,去掉 LTO |

### 关键 commit(main)

```
2e148a076  build: add the missing `magica2jni` target (libmagica2.so)
57d4b6c1b  chain: part 2 runs on the uid-0 command plane, install moves to part 1   ← ④b + ① + ③ + token
bbb27f5c7  docs: state / objective / next for the root-chain work (2026-10-03)
232ea2495  root service: start the uid-0 command server as part of startChannel()
092a9bebd  jni: start_command_server(port, token, engine) -- the uid-0 command server entry
989241bbf  gl_server: gl_server_start() -- 非阻塞 bind + detached accept + runcon 回退
2dbb328fc  chain: part 2 no longer fails when the adb gate is refused
18bab019d  root: RootCommand -- client facade
50e1085c7  ui: part-2 prompt reads "Part 2 已就绪"
76c3a59d8  engine: --glserver mode
48c8d9670 / 4d0b8f4b7 / 51da942ff  build: gl_server.cpp 链进引擎与 libmagica2.so
d42f2e39b  app/jni: gl_server.cpp（server 本体 + 协议）
```

## 2. 当前形态(数据流)

```
入口     PREFLIGHT(su 探针) ──► 阶段判定 readBootFacts()：enforce==0 && Seccomp==0 ⇒ PART 2
part1    管理端安装(pm install, uid-2000 通道) ──► W1 ──► am hang
part2    MAGICA_ROOT(3×3s 重试) ──► startChannel(): identity=uid=0
          └─► start_command_server(5038, token, engine)
                ├ bind 成功 → 本进程(隔离 uid 0)内 listener(accept 线程)
                └ bind 失败 → fork + setgroups/setresgid/setresuid(0,0,0)
                              + execve(runcon u:r:system_server:s0 <engine> --glserver …)
         PRIV_ENV: 开 adb 门(可选) → 重启 adbd(可选) → adb connect(可选)
                   └─► privileged(): adb 在就用 adb，否则 uid-0 命令面
                        rmmod guard → selinux 修复 → 属性恢复
         KSU_LATE_LOAD: privileged() ⇒ adb 没了也能 late-load
```

**两条特权通道**

| | 传输 | 何时可用 | 谁管理 |
|---|---|---|---|
| adb | `adb connect 127.0.0.1:5555`(root adbd) | 只有 adb 门开成功 | `RootAdbd` |
| 命令面 | `gl_server` 127.0.0.1:5038,行协议 | 只要隔离 root 服务活着 | `RootCommand` |

`RootAdbRunner.exec()` **只在命令没跑成时抛异常**,所以「adb 抛了 → 换命令面」不会重复执行;命令面「没跑成」同样抛异常(`__GHOSTLOCK_EXEC_FAILED__`),退出码非 0 是真实结论、原样返回。

**协议**(行协议,`nc` 与 Java 通用):

```
S->C GHOSTLOCK/1 ; C->S <token> ; S->C OK
C->S <一条命令>\n ; S->C <输出原样> ; S->C __GL_EXIT__ <rc>\n
指令 @t <ms> / @domain <selinux> ; 内置 @id / @quit ; 失败 __GHOSTLOCK_EXEC_FAILED__: <reason>
```

只 bind `127.0.0.1`,默认端口 **5038**;`RootCommand` 从 `<filesDir>/port`、`<filesDir>/token` 读(缺省回落 5038 + 空 token)。

shell 侧用法:`printf '<token>\nid\n' | nc 127.0.0.1 5038`

## 3. 下一步(TODO)

**代码侧本轮的 ④b / ① / ③ 与 token 落地已经推完**(`57d4b6c1b` + `2e148a076`),剩下的是**验证**:

| # | 任务 | 位置 / 做法 |
|---|---|---|
| V1 | CI 转绿:run `37085729678`(`Build`,main,含 `Makefile` 修复)必须 `Build APK` 全绿 —— 之前 `magica2jni` 缺失让 APK 构建一直是红的,这轮是第一次真正编译 `libmagica2.so` + 新增 Kotlin | `gh run watch 37085729678` 或 `gh run view --log-failed` |
| V2 | 装机跑一遍 part 1,看新增日志:阶段判定 PART 1、`pm install` 在 W1 之前、`uid-0 命令面暂存：port=5038 token=…` | `logcat -s GhostlockRoot` |
| V3 | `am hang` 之后(part 2 续跑)必须看到:阶段判定 **PART 2**、面板标题 **「Part 2 已就绪」**、`[+] 提权通道：root adbd …` 或 `[!] root adbd 不可用 … ⇒ 本阶段剩余命令全部走 uid-0 命令面`;**不再**出现「无线调试通道不可用 ⇒ return false」 | 同上 |
| V4 | 命令面自测(设备侧):`printf '<filesDir>/token\nid\n' \| nc 127.0.0.1 5038` ⇒ uid=0;或直接看 `startChannel: command server port=5038 rc=0` | adb shell |
| V5 | runcon 回退(监听失败)在真机上还没验证过:需要制造 bind 失败(例如先占住 5038)看是否出现 `u:r:system_server:s0` 的 listener | 可选 |
| V6 | 可选:`cleanup-parked.sh` 里加 `GL_FIX_SELINUX=1` 开关(默认关),让清理顺手修 selinux | `tools/device/cleanup-parked.sh` |
| V7 | 可选:设备没有 `/data/local/tmp` 时,命令面 token / engine 路径仍是硬编码 —— server 端读不到 token 就是空 token(无鉴权,仍能用),但 runcon 回退的 engine 路径会找不到 | `ChainSpec.DEVICE_DIR` / `RootShellService.COMMAND_SERVER_*` |

## 4. 设备侧检查清单(跑完一条链后看)

```sh
adb shell 'grep -aE "command server port|LOAD_KO|W1c: wrote|RESULT|handed to parked|killed parked" /data/local/tmp/gl-w1/w1c.log'
adb shell 'grep -a "startChannel" <logcat -s GhostlockRoot>'      # 0=listening, -1=bind failed
printf '<token>\nid\n' | nc 127.0.0.1 5038                        # 期望 uid=0 + 该进程的 context
adb shell 'cat /sys/fs/selinux/enforce /sys/fs/selinux/checkreqprot'
adb shell 'for c in /sys/fs/selinux/policy_capabilities/*; do echo $c=$(cat $c); done'
```

## 5. 已知约束 / 坑

- 监听回退用的 `runcon` 换域**保持 uid 0**(所以必须由隔离进程 fork 出来,不能由 JVM spawn);
- 命令执行**不要**用 `ProcessBuilder`(子进程会掉到 app uid);
- `magica2jni` 的构建必须同时包含 `gl_server.cpp`(引擎的 `CXX_SRCS`、`Android.mk` 的 `LOCAL_SRC_FILES`,以及根 `Makefile` 的 `MAGICA2_SRCS` 三处);
- parked 进程在清理验证通过前**不能退**(exit 会走伪造 PI 树 → wedge);
- `selinux_state` 每次 W1 都会踩 `+0..+7`,需要 kread 恢复(脚本 `fix-selinux.sh`,永不自动开 enforcing);
- 命令面 server 的 token 为空时**任何** token 都通过(`if (token && *token …)`),所以「推送失败」不会把链条卡死,只是没鉴权;
- `readBootFacts()` 现在会在 uid-2000 通道不通时改读命令面,Seccomp 用 `/proc/1/status`(init 的),因为命令面里的 `/proc/self` 是**它自己**那个进程。
