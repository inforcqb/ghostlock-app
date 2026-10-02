package com.ghostlock.app.chain

import com.ghostlock.app.domain.model.ChainPhase
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
 * One deliberate exception, asked for by the user on 2026-10-01: step 8b **closes** the gate
 * with `resetprop service.adb.tcp.port ""` (see [ChainSpec.hardenCommands]). Opening it still
 * goes through the adbd domain in step 5 -- only the closing direction uses resetprop, and only
 * inside the window where resetprop was verified usable.
 *
 * The domain borrows in steps 5/6 work only while SELinux is permissive (W1 landed
 * and `ksud late-load` has not run yet), which is why the order is what it is.
 */
object ChainSpec {
    const val DEVICE_DIR = "/data/local/tmp/gl-w1"

    /* The uid-0 command plane is a binder to the isolated root service (`IRootShellService`),
     * not a socket: the AF_UNIX path + token it used to be needed a shared, writable directory
     * and behaved differently per device. See `com.ghostlock.app.root.RootChannel`. */

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
     *
     * The two adbd-gate writes are deliberately absent: they are channel *actions* now
     * ([chanSetProp]), and that path has no retry to guard against in the first place.
     */
    val NON_IDEMPOTENT = listOf(
        AM_HANG,
        RMMOD_GUARD,
        KSUD_LATE_LOAD,
        W1_START_MARK,
    )

    /**
     * step 4: open the channel and check who we are.
     *
     * There is no command string for this any more -- the identity is read inside the service
     * process ([RootChannel.identity]), so there is nothing to spawn and nothing to parse.
     */

    /**
     * The fool-proof probe of step 0: does `su` already hand out root?
     *
     * Run through the same uid-2000 channel as every other step, with a short budget --
     * a `su` that has to ask the user for consent (KernelSU's prompt) blocks here, and that
     * must not stall the preflight: no answer within the budget simply means "no root".
     */
    const val SU_PROBE = "su -c id"
    const val SU_PROBE_TIMEOUT_MS = 20_000L

    /**
     * step 1 -- W1, from the app's own engine.
     *
     * The runbook drove the device-side script `$DEVICE_DIR/w1.sh`, which ran whatever
     * `ghostlock` happened to be sitting in `/data/local/tmp` (measured: the 2026-09-28 push,
     * whose early-exit gate still said 50%). The app now ships the engine itself
     * (`libghostlock.so`) and does what the script did -- see [W1Stage]: sync the engine and
     * the profile into [DEVICE_DIR], start it detached with `setsid`, and watch the log for
     * the landing marker. The script is kept only as the historical reference.
     */
    const val SCRIPT_W1 = "$DEVICE_DIR/w1.sh"

    /** Where the app's own engine/profile/log live (never the user's manual runbook files). */
    const val W1_ENGINE = "$DEVICE_DIR/gl-engine"
    const val W1_PROFILE = "$DEVICE_DIR/gl-profile.bin"
    const val W1_LOG = "$DEVICE_DIR/gl-w1.log"

    /** Bundled device tooling, pushed from `assets/device/` (see DeviceSync.BUNDLED). */
    const val KREAD_KO = "$DEVICE_DIR/kread_min.ko"
    const val FIX_SELINUX = "$DEVICE_DIR/fix-selinux.sh"

    /**
     * The SukiSU-Ultra manager APK the app carries and installs.
     *
     * Bundled on purpose: the device must not have to reach GitHub (国内网络到 GitHub 不稳).
     * CI copies the **latest** upstream release into `assets/device/sukisu-manager.apk` on every
     * build, so the copy in the APK is never hardcoded to a version. The chain pushes it here
     * (see DeviceSync) and installs it with root.
     */
    const val KSU_MANAGER_APK = "$DEVICE_DIR/sukisu-manager.apk"

    /** Package id of that manager, used for the log line (and by `prepareKsud`). */
    const val KSU_MANAGER_PACKAGE = "com.sukisu.ultra"

    /** Module name the kernel knows `kread_min.ko` by (`insmod` / `rmmod`). */
    const val KREAD_MODULE = "kread_min"

    /**
     * step 8a: repair `selinux_state`, which W1's collateral store clobbers.
     *
     * The script's own header states the contract: it repairs bytes `+1..+10` (checkreqprot,
     * initialized, `policycap[]`) and **never** touches `+0` (enforcing) -- the chain needs
     * permissive, and turning enforcing back on while the other bytes are still garbage drops
     * the session instantly. `/proc/kwrite` comes from `kread_min.ko`, so the module has to be
     * loaded first and unloaded right after (also the user's requirement: 脚本文后要
     * `rmmod kread_min`).
     *
     * It sits **after** `rmmod oplus_security_guard` on purpose: the OPPO guard fights module
     * loading, and the device-side cleanup tooling loads `kread_min` in exactly that order
     * (unload the OPPO modules first, then insmod).
     */
    fun selinuxRepairCommands(): List<String> = listOf(
        "insmod $KREAD_KO",
        "sh $FIX_SELINUX",
        "rmmod $KREAD_MODULE",
    )

    /** How many commands [selinuxRepairCommands] holds (for the failure summary). */
    const val KREAD_STEPS = 3

    /** The line the engine prints when the forged PI state is in place. */
    const val W1_LANDED_MARKER = "Write 1 complete"

    /** The process name of the parked engine (`comm` of [W1_ENGINE]). */
    const val W1_ENGINE_COMM = "gl-engine"

    /**
     * The start command, verbatim from `w1.sh`'s env/args, with three differences that the
     * script's own warnings demand: the engine and the profile are the app's files, the log
     * goes to [W1_LOG], and `setsid` detaches the process so the adb shell session can end
     * without taking the parked engine with it.
     */
    const val W1_START =
        "cd $DEVICE_DIR; " +
            "export GHOSTLOCK_HOME=$DEVICE_DIR GHOSTLOCK_W1_ONLY=1 " +
            "GHOSTLOCK_PARK_AFTER_W1=1 GHOSTLOCK_MCAST_SOCKET=tcp6; " +
            "rm -f $W1_LOG; " +
            "setsid $W1_ENGINE --profile $W1_PROFILE >$W1_LOG 2>&1 &"

    /** Marker for [NON_IDEMPOTENT]: starting W1 twice forges a second waiter. */
    const val W1_START_MARK = "GHOSTLOCK_PARK_AFTER_W1"

    /** The script waited 90 x 1s for the marker; the landing itself takes ~11-17s. */
    const val W1_DEADLINE_MS = 90_000L
    const val W1_POLL_MS = 1_000L

    /** An engine that dies this early never had a chance to land. */
    const val W1_EARLY_EXIT_MS = 5_000L

    /** How long the engine's log must stand still before a missing pid means "it died". */
    const val W1_STALL_MS = 5_000L

    /** W1 parks a forged waiter and waits for the engine's marker; give it real headroom. */
    const val W1_TIMEOUT_MS = 240_000L

    /**
     * step 5: `service.adb.tcp.port` is `adbd_config_prop` -- only the adbd domain may set it, so
     * the write borrows that domain (`setcon`, i.e. what `runcon u:r:adbd:s0` did).
     */
    const val ADBD_DOMAIN = "u:r:adbd:s0"

    /** step 6: `ctl_adbd_prop` is granted to `usbd` alone (`plat_sepolicy.cil`). */
    const val USBD_DOMAIN = "u:r:usbd:s0"

    /** init's own control property for restarting a service, and the service it names. */
    const val CTL_RESTART_PROP = "ctl.restart"
    const val ADBD_SERVICE = "adbd"

    /** How long the gate is given to start listening before `adb connect` takes over. */
    const val GATE_WAIT_MS = 60_000L

    /** step 8: the first of the two things this chain actually exists for */
    const val RMMOD_GUARD = "rmmod oplus_security_guard"

    /**
     * The bundled `ksud` the chain calls for the property work -- pushed to the device first
     * (`assets`-style push from `jniLibs`, see DeviceSync), and always by **absolute path**:
     * a bare `resetprop` depends on the shell's PATH, which is exactly what broke the first
     * version of step 8b.
     *
     * `ksud` carries `resetprop` the way busybox carries its applets, so the invocation is
     * `ksud resetprop …` (verified on the PJA110 2026-10-01, from a copy in /data/local/tmp:
     * `…/ksud resetprop ro.secure` -> `1`, `su -c '… -Z ro.secure'` ->
     * `u:object_r:userdebug_or_eng_prop:s0`).
     */
    const val KSUD = "$DEVICE_DIR/ksud"

    /** The device's own installation, used when the bundled copy could not be pushed. */
    const val KSUD_FALLBACK = "/data/adb/ksud"

    /** Local name of the bundled ksud inside the APK (`jniLibs/arm64-v8a`). */
    const val KSUD_LIB = "libksud.so"

    /**
     * step 8b: the property area, in the window between `rmmod` and `ksud late-load`.
     *
     * With `oplus_security_guard` gone -- and before `ksud` reloads the policy -- the property
     * tool is usable, so the debug-state properties can be put back to their normal values.
     * Order matters and is the one the tool documents:
     *
     *  1. `resetprop -c <context>` **rebuilds the property area** that owns `ro.secure` /
     *     `ro.debuggable` (`userdebug_or_eng_prop`); without that rebuild the area's state can
     *     reject or silently drop the writes that follow;
     *  2. the two `ro.*` writes;
     *  3. `suid_dumpable` back to 0;
     *  4. `resetprop -c` with no name, i.e. rebuild **every** property area -- the cleanup;
     *  5. `resetprop service.adb.tcp.port ""` -- clears the port this chain opened in step 5/6.
     *     It goes **last** so the area rebuild above cannot be the thing that rewrites it, and
     *     the running 5555 listener is unaffected until adbd is restarted (`ksud late-load` does
     *     that a moment later), which is exactly when the gate is supposed to close.
     *
     * Note on the runbook: `docs/analysis/current-chain-20260926.md` §3 blacklists `resetprop`
     * for `service.*` while *opening* the gate (that has to happen in the `adbd` domain). This
     * is the closing direction, in the same window where `resetprop` was verified usable, and
     * the user asked for it explicitly (2026-10-01). If the property is still there after a run,
     * the alternative is the sanctioned one: `runcon u:r:adbd:s0 setprop service.adb.tcp.port ""`
     * -- which needs SELinux permissive, i.e. this same window.
     *
     * Non-fatal on purpose: this is hardening/cleanup, and it must not stop the step that gives
     * the device persistent root. Every command is logged with its exit code either way.
     */
    fun hardenCommands(ksud: String): List<String> = listOf(
        "$ksud resetprop -c $HARDEN_CONTEXT",
        "$ksud resetprop ro.secure 1",
        "$ksud resetprop ro.debuggable 0",
        "echo 0 > /proc/sys/fs/suid_dumpable",
        "$ksud resetprop -c",
        "$ksud resetprop $ADB_TCP_PORT_PROP \"\"",
    )

    /** The property step 5/6 sets to open the root adbd gate -- step 8b clears it again. */
    const val ADB_TCP_PORT_PROP = "service.adb.tcp.port"

    /** The property area those `ro.*` values live in. */
    const val HARDEN_CONTEXT = "u:object_r:userdebug_or_eng_prop:s0"

    /**
     * step 9: the second one -- KernelSU late-load gives the persistent root
     *
     * Deliberately the **device's** ksud and not the bundled one: `late-load` has to find the
     * module payload of the KernelSU installation that is actually there, while `resetprop`
     * (step 8b) is version-independent and is what the bundled copy is for.
     */
    const val KSUD_LATE_LOAD = "$KSUD_FALLBACK late-load"

    /** verification only (never a substitute for the commands above) */
    const val READ_ENFORCE = "cat /sys/fs/selinux/enforce"

    /**
     * Both phase facts in ONE command: SELinux and the shell's `Seccomp`.
     *
     * `/sys/fs/selinux/enforce` has no trailing newline (measured: `1` arrives glued to the
     * next output), hence the explicit `echo` between the two reads.
     */
    const val READ_PHASE = "cat /sys/fs/selinux/enforce; echo; grep -m1 '^Seccomp:' /proc/self/status"
    /** Same file as [READ_CAPS]; the `Seccomp:` line is what the boot-fact check reads. */
    const val READ_STATUS = "cat /proc/self/status"

    /**
     * How often the boot facts are read before the chain refuses to guess. The wireless
     * channel drops connections on its own schedule, so a single failed read must not
     * decide anything.
     */
    const val BOOT_FACTS_ATTEMPTS = 6
    const val READ_MODULES = "cat /proc/modules"
    const val READ_IDENTITY = "id"
    const val READ_CAPS = "cat /proc/self/status"

    const val ADB_PORT = 5555

    /** The root adbd the chain talks to once the gate is open (steps 7-9). */
    const val ADB_ENDPOINT = "127.0.0.1:$ADB_PORT"

    /** How often a dropped wireless channel is retried for one repeatable command. */
    const val TRANSPORT_RETRIES = 3

    /** `adb connect 127.0.0.1:5555` rounds: the adbd restart takes a moment to listen. */
    const val ROOT_CONNECT_ROUNDS = 6

    /** How often `am hang --allow-restart` may be issued (the watchdog needs ~93s). */
    const val HANG_ATTEMPTS = 3
}

/**
 * One step of the chain. [phase] is null for the step that is not part of the split
 * ([PREFLIGHT]): it runs in both halves and is always shown.
 *
 * Everything between the uid-0 channel and `ksud late-load` is a single step, [PRIV_ENV]
 * 「提权环境恢复」: opening the adb gate, connecting to the root adbd, removing the security
 * module, installing the manager, repairing `selinux_state` and putting the debug properties
 * back are one phase, and six rows of the same phase told the user nothing extra.
 */
enum class ChainStep(val label: String, val phase: ChainPhase?) {
    PREFLIGHT("预检：通道与文件", null),
    W1("W1：SELinux 转宽容", ChainPhase.PART1),
    AM_HANG("重启 framework（am hang）", ChainPhase.PART1),
    MAGICA_ROOT("Magica：uid-0 通道", ChainPhase.PART2),
    PRIV_ENV("提权环境恢复", ChainPhase.PART2),
    KSU_LATE_LOAD("ksud late-load", ChainPhase.PART2),
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
 * One command on the root adbd: the exit code matters as much as the text.
 *
 * `ksud late-load` is judged by its return code alone -- it restarts adbd on the way out, so
 * nothing may be read over that transport afterwards.
 */
data class RootAdbResult(val exitCode: Int, val output: String)

/**
 * The root adbd the chain drives in steps 7-9.
 *
 * There is no adb implementation inside this app: the bundled `adb` CLI (see `AdbCli`) is
 * the client for the wireless-debugging channel (uid 2000) *and*, once the gate is open, for
 * the root adbd on [ChainSpec.ADB_ENDPOINT]. The adb public-key machinery
 * (`AdbKey`/`pushAdbKey`/libadb) went away with it -- the wireless pairing already
 * registered our key with adbd, so nothing has to be appended to `/data/misc/adb/adb_keys`.
 */
interface RootAdbRunner {
    /** Connect to [ChainSpec.ADB_ENDPOINT]; throws when the transport does not come up. */
    suspend fun connect()

    /** Run one command on that transport; throws only when the command never ran. */
    suspend fun exec(command: String, timeoutMs: Long = 30_000L): RootAdbResult
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
    private val adb: RootAdbRunner,
    /**
     * Absolute path of the `ksud` the property step (8b) must use: the app's own copy in
     * [ChainSpec.KSUD] when it was pushed, else the device's [ChainSpec.KSUD_FALLBACK].
     */
    private val ksud: String,
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
        transportRetries: Int = ChainSpec.TRANSPORT_RETRIES,
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
     * meant the W1 step never noticed that SELinux had turned permissive. The user service's
     * exec filters the echo now, and this keeps the checks robust to any future prefix.
     */
    private fun lastLineOf(output: String): String =
        output.trim().lines().lastOrNull { it.isNotBlank() }?.trim().orEmpty()

    /*
     * The uid-0 channel, from step 3 on: three typed actions, not shell commands.
     *
     * Transport is this app's binder to its own isolated root service ([RootChannel]), NOT the
     * device-side `rshell` wrapper and NOT Shizuku: uid 2000 exists only to start W1.
     * Restarting adbd (step 6) kills every shell-uid process -- including Shizuku's server and
     * user services -- so everything after that point comes from this app, over the channel the
     * isolated uid-0 process serves.
     *
     * Why actions and not command strings: the far side is a capless uid 0 that cannot spawn a
     * shell with its own identity (the platform drops a spawned child to the app uid -- measured
     * on this handset) and can be frozen by the cached-app freezer. A string that has to be
     * parsed and executed is exactly the part that behaves differently per device; each action
     * below is a syscall, or one property write, inside the isolated process itself.
     */

    /** uid 0 + SELinux context of the service process (step 4's identity check). */
    private suspend fun chanIdentity(): String = withContext(Dispatchers.IO) {
        channel.identity()
    }

    /** `runcon <domain> setprop <name> <value>`, executed in the service process. */
    private suspend fun chanSetProp(domain: String, name: String, value: String): String =
        withContext(Dispatchers.IO) { channel.setPropInDomain(domain, name, value) }

    /** Does the kernel report a LISTEN on `port`?  See [RootChannel.PortProbe]. */
    private suspend fun chanWaitPort(port: Int, timeoutMs: Long): RootChannel.PortProbe =
        withContext(Dispatchers.IO) { channel.waitForPort(port, timeoutMs.toInt()) }

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
        onLog("[*] 读 system_server pid 失败，通道抖动：${t.message}，不作证据，继续等")
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
     * Liveness probe for the root channel.
     *
     * The step used to wait for `ls -l rshell.sock` to show the file, which a *stale*
     * socket from an earlier boot satisfies -- that is exactly how a run walked past a
     * root service that had never started, and died on the first connect with
     * `Connection refused`. The probe is the identity read instead: only a live service
     * running as uid 0 can answer it, and there is no file to be stale.
     */
    private suspend fun probeChannel(): String = try {
        val identity = chanIdentity().trim()
        if (identity.contains("uid=0")) "connected" else "connected but identity=$identity"
    } catch (t: Throwable) {
        "not yet: ${t::class.simpleName}: ${t.message}"
    }

    /**
     * Does `su` already hand out root? See [ChainSpec.SU_PROBE].
     *
     * Only a clean `uid=0` in the answer counts. A command that never ran (transport failure),
     * a timeout, or a `su` that returned non-zero is **not** evidence of root -- so the probe
     * errs towards running the chain, which is the safe direction: skipping a needed W1 leaves
     * the user with nothing, while running an unneeded one only costs time.
     */
    private suspend fun suGrantsRoot(): Boolean {
        val probe = runCatching {
            sh(ChainSpec.SU_PROBE, timeoutMs = ChainSpec.SU_PROBE_TIMEOUT_MS, transportRetries = 1)
        }.getOrNull() ?: run {
            onLog("[*] 预检：`${ChainSpec.SU_PROBE}` 没能执行（通道问题）⇒ 按“没有 root”处理")
            return false
        }
        val text = probe.output.trim()
        val firstLine = text.lineSequence().firstOrNull { it.isNotBlank() }
        if (firstLine != null) onLog("[*] 预检 su 输出：${firstLine.take(160)}")
        return probe.exitCode == 0 && UID_ZERO.containsMatchIn(text)
    }

    suspend fun run(): Boolean {
        // step 0 ------------------------------------------------------------------
        /* The fool-proof check comes first: if the device already hands out root through
         * `su`, this chain must not run at all. Every step of it forges kernel state, hangs
         * system_server and reboots adbd -- all of it pointless, and not harmless, when the
         * goal (root) is already there. */
        var alreadyRooted = false
        var ok = step(ChainStep.PREFLIGHT, "channel + su") {
            /* The command plane is a binder to the isolated root service, so there is nothing to
             * list from the shell side -- the client object answers for itself. */
            onLog("[*] uid-0 通道：${channel.describe()}")
            alreadyRooted = suGrantsRoot()
            if (alreadyRooted) {
                onLog("[+] 预检：`${ChainSpec.SU_PROBE}` 拿到了 uid=0 ⇒ 本机已有 root，不必执行利用链")
            } else {
                onLog("[*] 预检：su 不可用（或没有 uid=0）⇒ 继续走利用链")
            }
            "preflight done"
        } != null
        if (!ok) return false
        if (alreadyRooted) {
            /* Reported as a *success*: the thing the user asked for (root) is already there,
             * and the chain stopping here is the correct outcome, not a failure. */
            onProgress(
                ChainProgress(
                    ChainStep.PREFLIGHT,
                    1,
                    total,
                    StepState.OK,
                    "su 可用（uid=0）：本机已有 root，跳过利用链",
                ),
            )
            onLog("[+] root 可用（su -c id 返回 uid=0）—— 利用链已跳过，没有伪造任何内核状态。")
            return true
        }

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
            if (!w1.runW1Only(onLog)) {
                /* W1 occasionally panics the kernel, and a panic reboots the device -- so the
                 * one useful thing to say here is "try again once" (see [W1Stage.panicHint]). */
                throw IllegalStateException(
                    "W1 没有落地。当前 W1 有小概率把内核打 panic（设备会当场重启，属已知风险）：" +
                        "若设备重启过，请再点一次「一键 root」重试一次；重启已把现场清干净，无需别的收尾。",
                )
            }
            val enforce = await(
                "SELinux permissive",
                timeoutMs = 90_000L,
                read = { sh(ChainSpec.READ_ENFORCE).output },
                check = { lastLineOf(it).startsWith("0") },
            )
            "enforce=$enforce"
        } != null
        if (!ok) return false

        // step 2: the end of part 1 -- hang the framework on purpose ---------------
        /* This is the boundary between the two halves of the path, and it is a step of its
         * own for exactly that reason: everything above it runs while SELinux is Enforcing,
         * everything below it runs in the app instance the watchdog's restart produces. */
        ok = step(ChainStep.AM_HANG, ChainSpec.AM_HANG) {
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
                    "读不到 system_server 的 pid，通道连续失败 $baselineTries 次：" +
                        "没有基线就无法判断 am hang 是否生效，已停止（未落标记，重试即可）",
                )
            }
            onLog("[*] system_server pid before hang: $ssPidBefore")
            sh("echo done > ${ChainSpec.MARKER_HANG}")
            onLog("[*] 已落标记 ${ChainSpec.MARKER_HANG}（在 am hang 之前写：app 随后被杀也能知道这一步做过）")
            var hangEffective = false
            for (hangAttempt in 1..ChainSpec.HANG_ATTEMPTS) {
                val deadline = System.currentTimeMillis() + ChainSpec.HANG_WINDOW_MS
                val hang = sh(ChainSpec.AM_HANG, timeoutMs = ChainSpec.HANG_WINDOW_MS + 60_000L)
                onLog("[*] attempt $hangAttempt/${ChainSpec.HANG_ATTEMPTS}: ${ChainSpec.AM_HANG} -> exit=${hang.exitCode}")
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
            "am hang 已生效（system_server 已重启）"
        } != null
        if (!ok) return false

        // step 3: the start of part 2 -- the uid-0 channel -------------------------
        ok = step(ChainStep.MAGICA_ROOT, "内置 uid-0 服务 -> channel") {
            onLog("[*] ${ChainSpec.CHANNEL_LAUNCH_NOTE}")
            onLog("[*] ${rootShell.launch()}")
            /* Do NOT block here. [IsolatedRootShell.launch] already required a successful
             * self-test (startChannel() == true, i.e. the service answered with a uid-0
             * identity), so a probe of our own must not hold the chain hostage -- an earlier
             * version of this step burned minutes waiting for a transport the chain does not
             * use. Read the identity once for the log, check it, and move on to the adb
             * gate. */
            onLog("[*] 通道自检（一次性）：${probeChannel()}")
            val identity = chanIdentity()
            onLog("[*] channel identity: ${identity.trim()}")
            if (!identity.contains("uid=0")) throw IllegalStateException("channel is not uid 0")
            if (identity.contains("uid=0") && !identity.contains("isolated_app")) {
                onLog("[!] unexpected channel domain (expected u:r:isolated_app:s0)")
            }
            identity.trim()
        } != null
        if (!ok) return false

        // step 4 +: turn the device into a usable root environment -------------------
        /* ONE step on purpose (the user's call, 2026-10-01): opening the adb gate, becoming an
         * adb client, removing the security module, installing the manager, repairing
         * selinux_state and putting the debug properties back are one *phase* --
         * 「提权环境恢复」. The order inside it is the verified one, with two changes:
         *
         *  * the manager install moved **after** `rmmod oplus_security_guard`: the guard fights
         *    both module loading and property writes, so everything privileged happens after it
         *    is gone;
         *  * the manager install no longer precedes the guard (it used to sit right after the
         *    adb connect).
         *
         * A throw inside aborts the whole step (and with it the chain) -- the sub-phases that may
         * legitimately fail (manager install, selinux repair, property restore) only log loudly.
         */
        ok = step(ChainStep.PRIV_ENV, "adb 门 → 5555 → rmmod → 管理端 → selinux 修复 → 属性恢复") {
            // (1) open the adb gate (domain borrows; permissive only) -------------
            /* These two lines are the whole of
             *     runcon u:r:adbd:s0 setprop service.adb.tcp.port 5555
             *     runcon u:r:usbd:s0 setprop ctl.restart adbd
             * done inside the uid-0 service process: `setcon` to the borrowed domain, one
             * property write through property_service (the only client init listens to, and
             * the reason a `ctl.*` write takes effect at all), and back.  A failure here
             * throws: without the gate there is no root adbd, and the step would otherwise
             * spend its time in the connect rounds below. */
            chanSetProp(ChainSpec.ADBD_DOMAIN, ChainSpec.ADB_TCP_PORT_PROP, "${ChainSpec.ADB_PORT}")
                .let { onLog("[*] ${ChainSpec.ADBD_DOMAIN} → ${ChainSpec.ADB_TCP_PORT_PROP}=${ChainSpec.ADB_PORT}：${it.trim()}") }
            chanSetProp(ChainSpec.USBD_DOMAIN, ChainSpec.CTL_RESTART_PROP, ChainSpec.ADBD_SERVICE)
                .let { onLog("[*] ${ChainSpec.USBD_DOMAIN} → ${ChainSpec.CTL_RESTART_PROP}=${ChainSpec.ADBD_SERVICE}：${it.trim()}") }
            /* Is adbd listening by now?  The answer comes from inside the isolated process,
             * which cannot open an IP socket and reads its own /proc/net table -- so a
             * negative or unreadable answer is *logged*, never fatal.  The authority is
             * `adb connect` below: it runs in the app process, and it retries
             * ROOT_CONNECT_ROUNDS times.  A positive answer is real evidence and ends the
             * wait immediately. */
            val gate = chanWaitPort(ChainSpec.ADB_PORT, ChainSpec.GATE_WAIT_MS)
            when (gate.listening) {
                true -> onLog("[+] adbd 已在 ${ChainSpec.ADB_PORT} 上监听（${gate.detail}）")
                false -> onLog("[!] 内核监听表里没有 ${ChainSpec.ADB_PORT}（${gate.detail}）⇒ 由 adb connect 判定")
                null -> onLog("[!] 隔离进程读不到内核监听表（${gate.detail}）⇒ 由 adb connect 判定")
            }

            // (2) the app becomes an adb client ----------------------------------
            adb.connect()
            val identity = adb.exec(ChainSpec.READ_IDENTITY).output
            val caps = adb.exec(ChainSpec.READ_CAPS).output
            onLog("[*] adb identity: ${identity.trim()}")
            val capLine = caps.lineSequence().firstOrNull { it.startsWith("CapEff:") }?.trim() ?: ""
            onLog("[*] adb $capLine")
            if (!identity.contains("uid=0")) throw IllegalStateException("adb shell is not root")
            if (!capLine.contains("000001ffffffffff")) {
                throw IllegalStateException("adb shell has no full capabilities: $capLine")
            }

            // (3) the goal, part one: drop the security module -------------------
            val rmmod = adb.exec(ChainSpec.RMMOD_GUARD).output
            if (rmmod.isNotBlank()) onLog("[*] rmmod: ${rmmod.trim()}")
            val modules = adb.exec(ChainSpec.READ_MODULES).output
            if (modules.contains("oplus_security_guard")) {
                throw IllegalStateException("oplus_security_guard is still loaded")
            }
            onLog("[+] oplus_security_guard 已卸载")

            // (4) the manager, now that the guard is gone ------------------------
            /* The APK is the app's own copy of the latest SukiSU-Ultra release (pushed next to
             * the engine by DeviceSync), so a device that never saw GitHub still ends up with a
             * manager for `su` prompts and modules. Non-fatal: `pm install -r` on an installed
             * manager is a no-op and nothing later depends on it. */
            run {
                val result = adb.exec("pm install -r ${ChainSpec.KSU_MANAGER_APK}", timeoutMs = 180_000)
                val output = result.output.trim()
                if (output.isNotEmpty()) {
                    output.lineSequence().filter { it.isNotBlank() }.take(8).forEach { onLog("    $it") }
                }
                if (result.exitCode == 0) {
                    onLog("[+] 管理端已安装：${ChainSpec.KSU_MANAGER_PACKAGE}（$output）")
                } else {
                    onLog(
                        "[!] pm install 退出码 ${result.exitCode} —— 管理端可能已经装过或没装成功，" +
                            "不阻断后面的步骤",
                    )
                }
            }

            // (5) repair selinux_state (kread_min + fix-selinux.sh + rmmod) ------
            /* Order inside is the script's: load the module that provides /proc/kwrite, run the
             * repair (it only writes bytes +1..+10, enforcing is untouched), then unload the
             * module again -- nothing stays behind. */
            run {
                val commands = ChainSpec.selinuxRepairCommands()
                val failures = mutableListOf<String>()
                for (command in commands) {
                    val result = adb.exec(command)
                    val output = result.output.trim()
                    onLog("[*] $command -> exit=${result.exitCode}")
                    if (output.isNotEmpty()) {
                        output.lineSequence().filter { it.isNotBlank() }.take(12)
                            .forEach { onLog("    $it") }
                    }
                    if (result.exitCode != 0) failures += "$command (exit=${result.exitCode})"
                }
                if (failures.isEmpty()) {
                    onLog("[+] selinux_state 已修复（+1..+10 回填，enforcing 未动），kread_min 已卸载")
                } else {
                    onLog(
                        "[!] ${failures.size}/${ChainSpec.KREAD_STEPS} 条 selinux 修复命令没有成功：" +
                            failures.joinToString(),
                    )
                }
            }

            // (6) restore the debug properties -----------------------------------
            /* `resetprop` is usable here and not before: the guard is gone and `ksud late-load`
             * has not reloaded the policy yet. See [ChainSpec.hardenCommands] for the order. */
            run {
                val commands = ChainSpec.hardenCommands(ksud)
                val failures = mutableListOf<String>()
                onLog("[*] 属性恢复用 $ksud（内置 ksud，busybox 式调用 ksud resetprop）")
                for (command in commands) {
                    val result = adb.exec(command)
                    val output = result.output.trim()
                    if (output.isNotEmpty()) {
                        output.lineSequence().filter { it.isNotBlank() }.take(4)
                            .forEach { onLog("    $it") }
                    }
                    onLog("[*] $command -> exit=${result.exitCode}")
                    if (result.exitCode != 0) failures += "$command (exit=${result.exitCode})"
                }
                if (failures.isEmpty()) {
                    onLog(
                        "[+] 属性已恢复：ro.secure=1 / ro.debuggable=0 / suid_dumpable=0，" +
                            "并清掉 ${ChainSpec.ADB_TCP_PORT_PROP}（重建属性区后执行）",
                    )
                } else {
                    onLog(
                        "[!] ${failures.size}/${commands.size} 条属性恢复命令没有成功：" +
                            failures.joinToString() + " —— 不阻断后面的 ksud（它才是持久 root 的来源）",
                    )
                }
            }

            "提权环境就绪（adbd 开门 / uid=0 满 cap / guard 已卸 / 管理端已装 / selinux 已修 / 属性已恢复）"
        } != null
        if (!ok) return false


        // step 9: the goal, part two ---------------------------------------------
        /* load ok == exit 0 is the whole verdict. `ksud late-load` reloads the SELinux policy
         * and **restarts adbd** on the way out, so anything that would read the module list
         * afterwards reads through a transport that no longer exists -- which is exactly the
         * check that used to turn a successful late-load into a failed step. */
        ok = step(ChainStep.KSU_LATE_LOAD, ChainSpec.KSUD_LATE_LOAD) {
            val out = adb.exec(ChainSpec.KSUD_LATE_LOAD, timeoutMs = 120_000)
            if (out.output.isNotBlank()) onLog("[*] ksud: ${out.output.trim()}")
            if (out.exitCode != 0) {
                throw IllegalStateException("ksud late-load 退出码 ${out.exitCode}（只看返回码判断成败）")
            }
            /* NOTE: ksud late-load reloads the SELinux policy and restarts adbd, so
             * `getenforce` going back to Enforcing -- and the adb transport going away -- are
             * expected behaviour, not failures. */
            "late-load 返回 0 ⇒ 完成"
        } != null
        if (!ok) return false

        /* No verification step: it read /proc/modules over the adb transport, which ksud's
         * adbd restart takes down, so it could only ever report a failure after a success. */

        /* Nothing to close on the adb side: the CLI's server owns both transports and
         * [AdbService] keeps them alive across chain runs (the root serial stays marked, so
         * a second tap reuses it). The uid-0 channel is ours to drop. */
        channel.close()
        onLog(if (ok) "[+] root chain complete" else "[!] root chain stopped early")
        return ok
    }

    private companion object {
        /** `uid=0` exactly -- `uid=0` must not match a `uid=01…` style line. */
        val UID_ZERO = Regex("""uid=0(?!\d)""")
    }
}
