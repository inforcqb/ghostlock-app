package com.ghostlock.app.chain

import com.ghostlock.app.adb.LibAdbClient
import com.ghostlock.app.root.RootChannel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

/**
 * The frozen root chain, as it was verified end to end on 2026-09-26.
 *
 * Design and rationale: `docs/analysis/root-chain-integration.md`.
 * Device-side runbook (command whitelist, per-step verification, pitfalls):
 * `docs/analysis/current-chain-20260926.md`.
 *
 * ## Every command below is verbatim
 *
 * These are the exact commands of the verified chain. They must NOT be replaced by
 * "simplified" equivalents -- the device-side runbook §3 blacklists:
 *  * `ksud resetprop service.adb.tcp.port 5555` and friends (skipping the adbd domain),
 *  * `resetprop` for `service.*` properties,
 *  * legacy-domain tricks (`surfaceflinger`, `crash_dump`, ...) to reach `ctl.*`,
 *  * any step reordering or merging (for example dropping `am hang`).
 *
 * The domain borrows in steps 5/6 work only while SELinux is permissive (W1 landed
 * and `ksud late-load` has not run yet), which is why the order is what it is.
 */
object ChainSpec {
    const val DEVICE_DIR = "/data/local/tmp/gl-w1"

    /** The uid-0 shell channel Magica leaves behind (`sh <DEVICE_DIR>/rshell` uses these). */
    const val CHANNEL_SOCK = "$DEVICE_DIR/rshell.sock"
    const val CHANNEL_TOKEN = "$DEVICE_DIR/rshell.token"

    /** step 2: make system_server hang, so Magica's zygote can come up */
    const val AM_HANG = "am hang --allow-restart"

    /**
     * Written to the device right BEFORE `am hang --allow-restart` runs.
     *
     * That command restarts the framework and kills this app, so the restarted app
     * cannot tell from memory that the step already happened. The marker plus
     * `enforce == 0` (this boot already had W1) is what lets a second tap resume
     * instead of redoing the dangerous parts.
     */
    const val MARKER_HANG = "$DEVICE_DIR/.step-am-hang"

    /**
     * step 3: the uid-0 channel.
     *
     * This used to be `am start -n io.github.vvb2060.puellamagi/.MainActivity`, i.e. an
     * *external* app that is not installed on this handset, so the step could only ever
     * fail ("Activity class ... does not exist"). The port lives in this app now, so the
     * chain starts it in-process -- see [RootShellLauncher]. No privileged command
     * changes: they are still the verbatim ones below.
     */
    const val CHANNEL_LAUNCH_NOTE = "内置 root 服务：AppZygote 预载 libmagica2.so，绑成隔离进程"

    /**
     * `am hang --allow-restart` does not return until the watchdog kills system_server.
     * Measured on this handset: system_server and both zygotes are unchanged for the
     * first ~80s, the `am` command comes back at ~93s ("Hanging the system..." plus
     * "Failure calling service activity: Broken pipe (32)"), and only then are the pids
     * new. A 45s window -- and, worse, accepting an *unreadable* pid as "the pid
     * changed" -- is what made the chain walk on with a framework that had never
     * restarted.
     */
    const val HANG_WINDOW_MS = 180_000L

    /** Poll period of the restart verdict. */
    const val HANG_POLL_MS = 5_000L

    /**
     * Exit code that means "the command never ran" (a Shizuku transport failure), as
     * opposed to a command that ran and failed. A shell command cannot exit with it.
     */
    const val TRANSPORT_FAILURE = -1

    /**
     * Commands that must NOT be repeated when the transport failed: for these we cannot
     * be sure the command really did not run (the connection can drop *after* the call
     * was delivered), and running a privileged step twice is worse than stopping.
     * Everything else is repeatable -- `rm -f`, `echo`, `test`, the reads -- because the
     * sentinel means the command never ran.
     */
    val NON_IDEMPOTENT = listOf(
        AM_HANG,
        RMMOD_GUARD,
        KSUD_LATE_LOAD,
        ADBD_SET_TCP_PORT,
        USBD_RESTART_ADBD,
    )

    /** step 4: open the channel and check who we are */
    const val CHANNEL_PROBE = "id"

    /**
     * step 1, the frozen device-side driver: the runbook's `sh /data/local/tmp/gl-w1/w1.sh`.
     *
     * The chain used to reach W1 through the Shizuku user service; the wireless-debugging
     * channel is the same identity (uid 2000, `Seccomp: 0`) and the script is the frozen
     * command, so nothing about step 1 is re-invented -- the app just runs it.
     */
    const val SCRIPT_W1 = "$DEVICE_DIR/w1.sh"

    /** W1 parks a forged waiter and waits for the engine's marker; give it real headroom. */
    const val W1_TIMEOUT_MS = 240_000L

    /** step 5: `service.adb.tcp.port` is `adbd_config_prop` -- only the adbd domain may set it */
    const val ADBD_SET_TCP_PORT = "runcon u:r:adbd:s0 setprop service.adb.tcp.port 5555"

    /** step 6: `ctl_adbd_prop` is granted to `usbd` alone (`plat_sepolicy.cil`) */
    const val USBD_RESTART_ADBD = "runcon u:r:usbd:s0 setprop ctl.restart adbd"

    /** step 8: the first of the two things this chain actually exists for */
    const val RMMOD_GUARD = "rmmod oplus_security_guard"

    /** step 9: the second one -- KernelSU late-load gives the persistent root */
    const val KSUD_LATE_LOAD = "/data/adb/ksud late-load"

    /** verification only (never a substitute for the commands above) */
    const val READ_ENFORCE = "cat /sys/fs/selinux/enforce"
    /** Same file as [READ_CAPS]; the `Seccomp:` line is what the boot-fact check reads. */
    const val READ_STATUS = "cat /proc/self/status"

    /**
     * How often the boot facts are read before the chain refuses to guess. The Shizuku
     * hop fails intermittently (null-message exception), so a single failed read must
     * not decide anything.
     */
    const val BOOT_FACTS_ATTEMPTS = 4
    const val READ_LISTEN = "ss -lnt"
    const val READ_MODULES = "cat /proc/modules"
    const val READ_IDENTITY = "id"
    const val READ_CAPS = "cat /proc/self/status"

    const val ADB_PORT = 5555
}

enum class ChainStep(val label: String) {
    PREFLIGHT("预检：通道与文件"),
    W1("W1：SELinux 转宽容"),
    MAGICA_ROOT("Magica：uid-0 通道"),
    OPEN_ADB_GATE("打开 adbd 门（借 adbd/usbd 域）"),
    ADB_CONNECT("adb 客户端连 127.0.0.1:5555"),
    REMOVE_GUARD("rmmod oplus_security_guard"),
    KSU_LATE_LOAD("ksud late-load"),
    VERIFY("校验 KernelSU"),
}

enum class StepState { RUNNING, OK, FAILED }

data class ChainProgress(
    val step: ChainStep,
    val index: Int,
    val total: Int,
    val state: StepState,
    val detail: String = "",
)

/** Result of one shell command executed as the shell user (uid 2000). */
data class ShellResult(val exitCode: Int, val output: String) {
    val ok: Boolean get() = exitCode == 0
}

/** Runs a command in the shell-uid context (uid 2000: the wireless-debugging channel). */
fun interface ShellExec {
    suspend fun exec(command: String, timeoutMs: Long): ShellResult
}

/** Runs the W1 stage through the exploit binary (uid 2000: the wireless-debugging channel). */
fun interface W1Runner {
    suspend fun runW1Only(onLog: (String) -> Unit): Boolean
}

/**
 * Starts this app's own uid-0 root service (isolated AppZygote process) and makes sure
 * it really is uid 0 with a listening channel. Implemented by
 * `com.ghostlock.app.root.IsolatedRootShell` in the app process -- an isolated service
 * may only be bound by the app that declares it, so this cannot run in the Shizuku user
 * service (uid 2000).
 */
fun interface RootShellLauncher {
    /** Returns a line for the log; throws when the channel did not come up. */
    suspend fun launch(): String
}

/**
 * The chain state machine. It only coordinates; every privileged step is executed by
 * whatever context the corresponding step requires (shell uid, the Magica channel,
 * or the adb client attached to the root adbd).
 *
 * Nothing here does "cleanup": the verified chain deliberately leaves the adb gate
 * open and the W1 park alive (a reboot restores both), and the blacklist forbids
 * inventing extra steps.
 */
class RootChain(
    private val shell: ShellExec,
    private val w1: W1Runner,
    private val rootShell: RootShellLauncher,
    private val channel: RootChannel,
    private val adb: LibAdbClient,
    private val onLog: (String) -> Unit,
    private val onProgress: (ChainProgress) -> Unit,
) {
    private val total = ChainStep.entries.size

    /**
     * Shell-uid command with the chain's default budget (the interface itself has none).
     *
     * A transport failure (the channel call itself failed -- the wireless-debugging
     * connection can drop, and a hung read reports the same sentinel) is NOT an empty
     * result: the command never ran, so no caller may interpret its missing output as a
     * fact. It used to look exactly like that with the removed Shizuku hop, and the
     * `am hang` verdict then read "unreadable pid" as "the framework restarted" and
     * walked on. Fail the step instead.
     */
    private suspend fun sh(
        command: String,
        timeoutMs: Long = 60_000L,
        transportRetries: Int = 1,
    ): ShellResult {
        var attempt = 0
        while (true) {
            attempt++
            val result = shell.exec(command, timeoutMs)
            if (result.exitCode != ChainSpec.TRANSPORT_FAILURE) return result
            /* The Shizuku hop drops connections on its own schedule (measured: several
             * "UserService 断开连接" per chain). Since the sentinel means the command did
             * NOT run, repeating it is safe -- except for the privileged steps, where a
             * lost answer could hide that the command *did* run. */
            val repeatable = ChainSpec.NON_IDEMPOTENT.none { command.contains(it) }
            if (attempt > transportRetries || !repeatable) {
                val why = if (repeatable) {
                    "已重试 $transportRetries 次仍失败"
                } else {
                    "该步骤不允许重复执行"
                }
                throw IllegalStateException("无线调试通道执行失败（命令没有真正运行，不是退出码，$why）：$command")
            }
            onLog("[*] 通道传输失败（命令没运行），重试 $attempt/$transportRetries：$command")
        }
    }

    /**
     * Last non-empty line of a command's captured output.
     *
     * The Shizuku user service prints the command it is about to run through the same
     * callback as the real output, so anything that parses the text must look at the
     * value, not at the beginning of the buffer: comparing the raw output with "0"
     * meant the W1 step never noticed that SELinux had turned permissive. [execShell]
     * now filters the echo, and this keeps the checks robust to any future prefix.
     */
    private fun lastLineOf(output: String): String =
        output.trim().lines().lastOrNull { it.isNotBlank() }?.trim().orEmpty()

    /**
     * Run one command in the uid-0 channel, from step 3 on.
     *
     * Transport is the app's own AF_UNIX client ([RootChannel]), NOT the device-side
     * `rshell` wrapper and NOT Shizuku: uid 2000 exists only to start W1. Restarting adbd
     * (`runcon u:r:usbd:s0 setprop ctl.restart adbd`, step 6) kills every shell-uid
     * process -- including Shizuku's server and user services -- so every command after
     * that point must come from this app, over the channel that the isolated uid-0 process
     * serves. [RootChannel] talks to it with the wrapper's own timing.
     */
    private suspend fun chan(command: String): String = withContext(Dispatchers.IO) {
        channel.exec(command, timeoutMs = 60_000)
    }

    private suspend fun step(
        step: ChainStep,
        detail: String = "",
        body: suspend () -> String,
    ): String? {
        onProgress(ChainProgress(step, step.ordinal + 1, total, StepState.RUNNING, detail))
        return try {
            val outcome = body()
            onProgress(ChainProgress(step, step.ordinal + 1, total, StepState.OK, outcome))
            outcome
        } catch (t: Throwable) {
            val message = t.message ?: t.javaClass.simpleName
            onLog("[!] ${step.label} failed: $message")
            onProgress(ChainProgress(step, step.ordinal + 1, total, StepState.FAILED, message))
            null
        }
    }

    /** Poll [read] until it satisfies [check], or let [withTimeout] abort the step. */
    private suspend fun await(
        what: String,
        timeoutMs: Long,
        intervalMs: Long = 1_000L,
        read: suspend () -> String,
        check: (String) -> Boolean,
    ): String = withTimeout(timeoutMs) {
        var warned = false
        var current = ""
        val started = System.currentTimeMillis()
        var lastReport = 0L
        while (!check(current)) {
            if (!warned) {
                onLog("[*] waiting for $what ...")
                warned = true
            }
            current = runCatching { read() }.getOrDefault("")
            if (!check(current)) {
                /* Long waits (the root channel, the adb gate) used to print one line and
                 * then go silent for minutes, which reads as "the app hung". */
                val elapsed = System.currentTimeMillis() - started
                if (elapsed - lastReport >= 10_000L) {
                    lastReport = elapsed
                    onLog(
                        "[*] 仍在等待 $what（${elapsed / 1000}s）——最近读到：" +
                            current.replace("\n", " ").take(160),
                    )
                }
                delay(intervalMs)
            }
        }
        current
    }

    /**
     * Live facts that decide whether this boot already went through W1.
     *
     * `enforce` comes from `/sys/fs/selinux/enforce`, `seccomp` from `Seccomp:` in
     * `/proc/self/status` (the Shizuku user service, uid 2000). W1 counts as landed only
     * when BOTH say so: SELinux permissive alone could in principle be the vendor's own
     * doing, while the shell context having no seccomp filter is the state the exploit
     * needs to still be able to run at all.
     */
    private data class BootFacts(val enforce: String, val seccomp: String, val w1Landed: Boolean)

    /**
     * Read both facts, with retries.
     *
     * This replaces a marker-file check and a single `enforce` read. Two failure modes
     * came out of that: `am hang --allow-restart` kills this app in the middle of the
     * step, so the marker it writes can be missing in the next launch (the chain then
     * re-ran W1 on top of an existing park), and the Shizuku hop fails intermittently
     * with a null-message exception, which used to be printed as `error: null` and read
     * as "unreadable ⇒ fresh boot" -- i.e. also a re-run of W1.
     *
     * If the state cannot be established after [ChainSpec.BOOT_FACTS_ATTEMPTS] attempts
     * this throws instead of guessing: neither re-running W1 (a park may already exist)
     * nor skipping it (the device may be enforcing) is safe on a guess.
     */
    private suspend fun readBootFacts(): BootFacts {
        var enforce: String? = null
        var seccomp: String? = null
        var attempts = 0
        var lastError: String? = null
        while ((enforce == null || seccomp == null) && attempts < ChainSpec.BOOT_FACTS_ATTEMPTS) {
            attempts++
            if (enforce == null) {
                enforce = runCatching {
                    lastLineOf(sh(ChainSpec.READ_ENFORCE).output).takeIf { it.isNotEmpty() }
                }.onFailure { lastError = it.message }.getOrNull()
            }
            if (seccomp == null) {
                seccomp = runCatching {
                    sh(ChainSpec.READ_STATUS).output.lineSequence()
                        .firstOrNull { it.startsWith("Seccomp:") }
                        ?.substringAfter(':')
                        ?.trim()
                        ?.takeIf { it.isNotEmpty() }
                }.onFailure { lastError = it.message }.getOrNull()
            }
        }
        val e = enforce
        val s = seccomp
        if (e == null || s == null) {
            val enforceText = e ?: "读不到"
            val seccompText = s ?: "读不到"
            val tail = lastError?.let { "，最后错误：$it" } ?: ""
            throw IllegalStateException(
                "无法确认现场状态（enforce=$enforceText, Seccomp=$seccompText，" +
                    "已重试 $attempts 次$tail）：" +
                    "不猜 —— 盲目重跑 W1 会在已有 park 上再伪造 waiter，跳过又可能在 Enforcing 下白跑。" +
                    "请再点一次",
            )
        }
        return BootFacts(e, s, w1Landed = e.startsWith("0") && s == "0")
    }

    /**
     * system_server's pid, or null when the read did not work at all.
     *
     * `pidof` exits 1 with EMPTY output when there is no such process, so "empty" and
     * "unreadable" must stay distinguishable: an empty read is meaningful (the server is
     * momentarily gone, i.e. the restart is in progress), an unreadable one is not
     * evidence of anything.
     */
    private suspend fun readSystemServerPid(): String? = try {
        lastLineOf(sh("pidof system_server").output)
    } catch (t: Throwable) {
        onLog("[*] 读 system_server pid 失败（通道抖动：${t.message}）⇒ 不作证据，继续等")
        null
    }

    /**
     * Wait for the framework restart that `am hang --allow-restart` triggers.
     *
     * The only accepted evidence is a *readable* pid that differs from [before]: the
     * watchdog needs ~93s here (see [ChainSpec.HANG_WINDOW_MS]), and an empty pid is
     * logged as "in between" rather than treated as success. In the normal run this
     * function never returns at all -- the framework restart kills this app, and the
     * next launch resumes from the marker file and `enforce == 0`.
     */
    private suspend fun awaitFrameworkRestart(before: String, deadline: Long): Boolean {
        var lastSeen = ""
        while (System.currentTimeMillis() < deadline) {
            delay(ChainSpec.HANG_POLL_MS)
            val now = readSystemServerPid() ?: continue
            if (now.isNotEmpty() && now != before) {
                onLog("[*] hang verdict: system_server pid $before -> $now ⇒ framework 与 zygote 已重启 ✓")
                return true
            }
            if (now != lastSeen) {
                lastSeen = now
                onLog(
                    if (now.isEmpty()) {
                        "[*] system_server 当前无 pid（正在重启中）… 继续等"
                    } else {
                        "[*] system_server 仍是 pid=$now（watchdog 约需 90s）… 继续等"
                    },
                )
            }
        }
        return false
    }

    /**
     * Connectability probe for the root channel.
     *
     * The step used to wait for `ls -l rshell.sock` to show the file, which a *stale*
     * socket from an earlier boot satisfies -- that is exactly how a run walked past a
     * root service that had never started, and died on the first connect with
     * `Connection refused`. Only a successful connect (and a uid-0 identity) counts.
     */
    private suspend fun probeChannel(): String = try {
        val identity = chan(ChainSpec.CHANNEL_PROBE).trim()
        if (identity.contains("uid=0")) "connected" else "connected but identity=$identity"
    } catch (t: Throwable) {
        "not yet: ${t::class.simpleName}: ${t.message}"
    }

    suspend fun run(): Boolean {
        // step 0 ------------------------------------------------------------------
        var ok = step(ChainStep.PREFLIGHT, "channel socket") {
            val listing = sh("ls -l ${ChainSpec.CHANNEL_SOCK} ${ChainSpec.CHANNEL_TOKEN}").output
            onLog("[*] $listing")
            if (!listing.contains("rshell.sock")) {
                onLog("[*] channel not up yet -- Magica has to run once (step 3)")
            }
            "preflight done"
        } != null
        if (!ok) return false

        // step 1: W1 ---------------------------------------------------------------
        /* Live facts decide whether W1 has to run at all -- see [readBootFacts]:
         *  - `enforce == 0` AND `Seccomp: 0` together mean this boot already ran W1 (a
         *    framework restart does NOT restore enforcing; only a reboot does), and the
         *    parked engine that holds the forged PI state is still alive. Running W1
         *    again would forge a second waiter on top of it, so skip it -- and skip the
         *    `am hang` right after it as well, unconditionally, without consulting the
         *    marker file (the hang kills this app, so that file may legitimately be
         *    absent or invisible in the next launch).
         *  - otherwise this is a fresh boot: clear the step markers, they describe the
         *    previous boot.
         * If neither can be established, [readBootFacts] throws rather than guessing. */
        val boot = readBootFacts()
        val w1AlreadyDone = boot.w1Landed
        if (w1AlreadyDone) {
            onLog(
                "[*] 现场事实 enforce=${boot.enforce} + Seccomp=${boot.seccomp} ⇒ 本次开机已做过 W1：" +
                    "无条件跳过 W1 与 am hang（不看标记文件）",
            )
        } else {
            sh("rm -f ${ChainSpec.MARKER_HANG}")
            onLog(
                "[*] 现场事实 enforce=${boot.enforce} + Seccomp=${boot.seccomp} ⇒ 未做过 W1：" +
                    "清掉旧步骤标记，W1 照常执行",
            )
        }
        ok = step(ChainStep.W1, "GHOSTLOCK_W1_ONLY + GHOSTLOCK_PARK_AFTER_W1") {
            if (w1AlreadyDone) {
                return@step "enforce=${boot.enforce} + Seccomp=${boot.seccomp} ⇒ W1 已做过，跳过"
            }
            if (!w1.runW1Only(onLog)) throw IllegalStateException("W1 runner returned failure")
            val enforce = await(
                "SELinux permissive",
                timeoutMs = 90_000L,
                read = { sh(ChainSpec.READ_ENFORCE).output },
                check = { lastLineOf(it).startsWith("0") },
            )
            "enforce=$enforce"
        } != null
        if (!ok) return false

        // step 2 + 3: Magica ------------------------------------------------------
        ok = step(ChainStep.MAGICA_ROOT, "am hang -> 内置 uid-0 服务 -> channel") {
            /* am hang --allow-restart takes system_server down on purpose and lets
             * the watchdog restart it; zygote -- and therefore THIS APP -- goes
             * with it.  That is expected, not a failure, but the user has to be
             * told before it happens, and the app has to be able to say where it
             * got to when it comes back (see ChainStateStore). */
            onLog(
                "[!] am hang --allow-restart: system_server 会被挂起并由 watchdog 重启，" +
                    "zygote 连同本 app 会一起重启 —— 这是**预期**行为，不是失败。",
            )
            onLog(
                "[!] 重启后请重新打开本 app：它会读取已保存的进度 (chain-state.txt) 与现场事实" +
                    "（enforce / lsmod / adb tcp 端口）判断已跑到哪一步，并从该步继续。",
            )
            onLog("[!] W1 的 park 进程与 SELinux permissive 状态在重启 framework 后仍然保持。")
            /* The marker is only a *hint* for the case where the live facts cannot tell
             * (they can: `w1AlreadyDone` already skips the hang unconditionally, without
             * this file). Reading it must therefore never fail the step -- a Shizuku
             * glitch here would otherwise stop a chain whose skip decision is already
             * made. */
            val hangMarkerPresent = runCatching {
                lastLineOf(sh("test -f ${ChainSpec.MARKER_HANG} && echo yes || echo no").output) == "yes"
            }.getOrDefault(false)
            /* Skip the hang for the SAME reason W1 was skipped -- enforce == 0 means this
             * boot already went past it, and the hang is the step right after W1 -- and
             * independently when the marker file is there. Restarting the framework a
             * second time would just kill this app again for nothing. */
            val hangAlreadyDone = w1AlreadyDone || hangMarkerPresent
            if (w1AlreadyDone) {
                onLog("[*] enforce=0（本次开机已做过 W1）⇒ am hang 一并跳过，直接启动 root 服务")
            } else if (hangMarkerPresent) {
                onLog("[*] 标记 ${ChainSpec.MARKER_HANG} 存在 ⇒ 本次开机已做过 am hang，跳过（不再重启一次 framework）")
            } else {
                onLog("[*] 本次开机还没做过 am hang：先读基线 pid，落标记，再执行")
            }
            if (!hangAlreadyDone) {
            /* `am hang --allow-restart` only *asks* the framework to hang; the watchdog
             * does the killing, and on this handset that takes ~93s (measured: pids
             * unchanged until t=80s, `am` returns at t=93s with "Hanging the system..."
             * and "Failure calling service activity: Broken pipe (32)", new pids right
             * after). The old code waited 45s and then accepted an *unreadable* pid as
             * "the pid changed" -- i.e. it declared success on a framework that had
             * never restarted, and the next step had no fresh zygote to work with.
             *
             * The baseline is now mandatory (without a readable pid there is nothing to
             * compare against), the window is [ChainSpec.HANG_WINDOW_MS], and the only
             * accepted evidence is a readable pid that differs from the baseline. */
            var baseline: String? = null
            var baselineTries = 0
            while (baseline.isNullOrEmpty() && baselineTries < 3) {
                baselineTries++
                baseline = readSystemServerPid()
            }
            val ssPidBefore = baseline
            if (ssPidBefore.isNullOrEmpty()) {
                throw IllegalStateException(
                    "读不到 system_server 的 pid（通道连续失败 $baselineTries 次）：" +
                        "没有基线就无法判断 am hang 是否生效，已停止（未落标记，重试即可）",
                )
            }
            onLog("[*] system_server pid before hang: $ssPidBefore")
            sh("echo done > ${ChainSpec.MARKER_HANG}")
            onLog("[*] 已落标记 ${ChainSpec.MARKER_HANG}（在 am hang 之前写：app 随后被杀也能知道这一步做过）")
            var hangEffective = false
            for (hangAttempt in 1..2) {
                val deadline = System.currentTimeMillis() + ChainSpec.HANG_WINDOW_MS
                val hang = sh(ChainSpec.AM_HANG, timeoutMs = ChainSpec.HANG_WINDOW_MS + 60_000L)
                onLog("[*] attempt $hangAttempt/2: ${ChainSpec.AM_HANG} -> exit=${hang.exitCode}")
                hang.output.lineSequence().filter { it.isNotBlank() }
                    .forEach { onLog("    $it") }
                if (hang.output.contains("Broken pipe", ignoreCase = true)) {
                    onLog("[*] am 以 broken pipe 收尾（watchdog 已杀 system_server）⇒ 再用 pid 证据确认")
                }
                if (awaitFrameworkRestart(ssPidBefore, deadline)) {
                    hangEffective = true
                    break
                }
                onLog(
                    "[!] 第 $hangAttempt 次 am hang 在 ${ChainSpec.HANG_WINDOW_MS / 1000}s 内未见效：" +
                        "system_server pid 仍是 $ssPidBefore",
                )
            }
            if (!hangEffective) {
                throw IllegalStateException(
                    "am hang --allow-restart 没有生效：${ChainSpec.HANG_WINDOW_MS / 1000}s 内没有读到" +
                        "「不同于 $ssPidBefore 且非空的」system_server pid。已停止推进，" +
                        "避免拿没有重启的 framework 去启动隔离 root 服务",
                )
            }
            /* A fresh system_server needs a moment before anything may bind to it. */
            await(
                "framework 重启后恢复响应",
                timeoutMs = 90_000L,
                read = { runCatching { sh("pm path android").output }.getOrDefault("") },
                check = { it.contains("package:") },
            )
            }
            onLog("[*] ${ChainSpec.CHANNEL_LAUNCH_NOTE}")
            onLog("[*] ${rootShell.launch()}")
            /* Do NOT block here. The root service already reported that its server is
             * listening (startChannel() == true), and the channel is verifiably up on the
             * device (a shell-side `rshell` gets `uid=0` / `u:r:isolated_app:s0`), so a
             * probe of our own must not hold the chain hostage: it burned minutes waiting
             * for a transport that the chain does not use anyway. Probe once for the log,
             * then move on to opening the adb gate. */
            onLog("[*] 通道自检（一次性）：${probeChannel()}")
            val identity = chan(ChainSpec.CHANNEL_PROBE)
            onLog("[*] channel identity: ${identity.trim()}")
            if (!identity.contains("uid=0")) throw IllegalStateException("channel is not uid 0")
            if (identity.contains("uid=0") && !identity.contains("isolated_app")) {
                onLog("[!] unexpected channel domain (expected u:r:isolated_app:s0)")
            }
            identity.trim()
        } != null
        if (!ok) return false

        // step 5 + 6: open the adb gate (domain borrows, permissive only) --------
        ok = step(ChainStep.OPEN_ADB_GATE, "runcon adbd + usbd") {
            chan(ChainSpec.ADBD_SET_TCP_PORT).let {
                onLog("[*] adbd domain: ${ChainSpec.ADBD_SET_TCP_PORT}")
                if (it.contains("Failed to set property")) {
                    throw IllegalStateException("setprop rejected -- is SELinux still permissive?")
                }
            }
            chan(ChainSpec.USBD_RESTART_ADBD).let {
                onLog("[*] usbd domain: ${ChainSpec.USBD_RESTART_ADBD}")
            }
            val listen = await(
                "adbd listening on ${ChainSpec.ADB_PORT}",
                timeoutMs = 60_000L,
                /* Through the channel, not Shizuku: the setprop above just restarted adbd,
                 * which takes the whole shell uid (and therefore Shizuku) with it. The
                 * uid-0 channel is unaffected. */
                read = { chan(ChainSpec.READ_LISTEN) },
                check = { it.contains(":${ChainSpec.ADB_PORT}") },
            )
            "listening"
        } != null
        if (!ok) return false

        // step 7: the app becomes an adb client ----------------------------------
        ok = step(ChainStep.ADB_CONNECT, "127.0.0.1:${ChainSpec.ADB_PORT}") {
            adb.connect()
            val identity = adb.exec(ChainSpec.READ_IDENTITY)
            val caps = adb.exec(ChainSpec.READ_CAPS)
            onLog("[*] adb identity: ${identity.trim()}")
            val capLine = caps.lineSequence().firstOrNull { it.startsWith("CapEff:") }?.trim() ?: ""
            onLog("[*] adb $capLine")
            if (!identity.contains("uid=0")) throw IllegalStateException("adb shell is not root")
            if (!capLine.contains("000001ffffffffff")) {
                throw IllegalStateException("adb shell has no full capabilities: $capLine")
            }
            "$identity / $capLine"
        } != null
        if (!ok) return false

        // step 8: the goal, part one ---------------------------------------------
        ok = step(ChainStep.REMOVE_GUARD, ChainSpec.RMMOD_GUARD) {
            val out = adb.exec(ChainSpec.RMMOD_GUARD)
            if (out.isNotBlank()) onLog("[*] rmmod: ${out.trim()}")
            val modules = adb.exec(ChainSpec.READ_MODULES)
            if (modules.contains("oplus_security_guard")) {
                throw IllegalStateException("oplus_security_guard is still loaded")
            }
            "guard unloaded"
        } != null
        if (!ok) return false

        // step 9: the goal, part two ---------------------------------------------
        ok = step(ChainStep.KSU_LATE_LOAD, ChainSpec.KSUD_LATE_LOAD) {
            val out = adb.exec(ChainSpec.KSUD_LATE_LOAD, timeoutMs = 120_000)
            if (out.isNotBlank()) onLog("[*] ksud: ${out.trim()}")
            // NOTE: ksud late-load reloads the SELinux policy, so `getenforce` going back
            // to Enforcing here is expected behaviour, not a failure.
            "late-load returned"
        } != null
        if (!ok) return false

        // verify -----------------------------------------------------------------
        ok = step(ChainStep.VERIFY, "kernelsu module") {
            val modules = await(
                "kernelsu in /proc/modules",
                timeoutMs = 30_000L,
                read = { adb.exec(ChainSpec.READ_MODULES) },
                check = { it.contains("kernelsu") },
            )
            if (!modules.contains("kernelsu")) throw IllegalStateException("kernelsu not loaded")
            "kernelsu loaded"
        } != null

        adb.close()
        channel.close()
        onLog(if (ok) "[+] root chain complete" else "[!] root chain stopped early")
        return ok
    }
}
