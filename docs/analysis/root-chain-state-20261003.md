# GhostLock 链条:任务目标 / 当前状态 / 下一步

> 记录时间:2026-10-03 · 仓库 `inforcqb/ghostlock-app`(main)· 相关仓库 `inforcqb/kp_rmap_guard_lkm`(kread_min)、`inforcqb/oneplus-susfs4ksu-lkm`、`inforcqb/Magica`

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

### 关键 commit(main)

```
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
part1  W1 ──► am hang
part2  MAGICA_ROOT(3×3s 重试) ──► startChannel(): identity=uid=0
        └─► start_command_server(5038, token, engine)
              ├ bind 成功 → 本进程(隔离 uid 0)内 listener(accept 线程)
              └ bind 失败 → fork + setgroups/setresgid/setresuid(0,0,0)
                            + execve(runcon u:r:system_server:s0 <engine> --glserver …)
        PRIV_ENV: adb 门(可选,失败不停) → 5555 → rmmod → 管理端 → selinux 修复 → 属性恢复
        KSU_LATE_LOAD
```

**协议**(行协议,`nc` 与 Java 通用):

```
S->C GHOSTLOCK/1 ; C->S <token> ; S->C OK
C->S <一条命令>\n ; S->C <输出原样> ; S->C __GL_EXIT__ <rc>\n
指令 @t <ms> / @domain <selinux> ; 内置 @id / @quit ; 失败 __GHOSTLOCK_EXEC_FAILED__: <reason>
```

只 bind `127.0.0.1`,默认端口 **5038**;`RootCommand` 从 `<filesDir>/port`、`<filesDir>/token` 读(缺省回落 5038 + 空 token)。

shell 侧用法:`printf '<token>\nid\n' | nc 127.0.0.1 5038`

## 3. 下一步(TODO,带锚点)

| # | 任务 | 位置 |
|---|---|---|
| ④b | `adb.connect()` + `adb.exec(READ_IDENTITY/READ_CAPS)` 改 tolerant(**不能简单置空**,要先读 `:1013-1075` 看这两个值喂给谁) | `chain/RootChain.kt:1010-1013` |
| ① | APK 安装从 `PRIV_ENV` 拆出 → 新增 `MANAGER_INSTALL(…, PART1)` 放在 `W1` 之前(完成串现在 `:1108`) | `chain/RootChain.kt:346`(枚举)、`:954`(PRIV_ENV) |
| ③ | 入口早期判 part:marker / `belongsToThisBoot` / `enforce==0` 处判定 phase,PART2 时第一件事跑 `MAGICA_ROOT` | `chain/RootChain.kt` 入口段(约 `:660-760`) |
| — | app 侧把实际 `port`/`token` 写进 `<filesDir>`(现在靠默认值工作;为空 token 时无鉴权,建议写 token) | `RootShellService.kt` 常量 `COMMAND_SERVER_*` 附近 |
| — | 验证:每次改动后 `bin.yml`(引擎)+ `build.yml`(APK/JNI),`.md` 改动不会触发(`build.yml` 有 `paths-ignore: **.md`) | CI |

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
- `magica2jni` 的构建必须包含 `gl_server.cpp`(已在根 `Makefile` 的 `JNI_SRCS` 与 `Android.mk` 加好);
- parked 进程在清理验证通过前**不能退**(exit 会走伪造 PI 树 → wedge);
- `selinux_state` 每次 W1 都会踩 `+0..+7`,需要 kread 恢复(脚本 `fix-selinux.sh`,永不自动开 enforcing)。
