package com.ghostlock.app.wireless

import android.content.Context
import com.ghostlock.app.chain.ChainSpec
import io.github.muntashirakon.adb.AdbConnection
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * `adb_command` -- the single entry point for talking to adbd.
 *
 * **One command, one channel.** Every call opens its own connection and releases it
 * completely before returning, so no session is ever carried between commands. Holding a
 * session kept failing on the device: adbd kicks a transport when a second connection
 * appears under the same client identity, and a kicked transport still looks *connected* to
 * libadb (`isConnected`/`isConnectionEstablished` stay true) while its reader never
 * delivers again, so the next command either hung or died with `Stream closed.` on the
 * freshly opened stream.
 *
 * **It blocks and verifies instead of handing failures back.** A command is only started on
 * a channel that has just answered a round trip, and if that channel dies mid-command the
 * facade waits, opens another one and tries again -- up to [retries] rounds (default
 * [DEFAULT_RETRIES]) and up to [CHANNEL_READY_BUDGET_MS] per round just to get a usable
 * channel. Callers therefore never see a transient channel hiccup; a returned
 * [ChainSpec.TRANSPORT_FAILURE] means the facade really ran out of options.
 *
 * **Safety is enforced here, not left to callers.** A command whose text appears in
 * [ChainSpec.NON_IDEMPOTENT] (`am hang --allow-restart`, `rmmod oplus_security_guard`,
 * `/data/adb/ksud late-load`, the two `setprop`s) is never repeated: a failed read may mean
 * the command DID run, and running those twice is worse than stopping. It is verified once
 * and executed exactly once.
 *
 * Usage: [attach] once from the application, then `AdbCommand.exec(command)` or
 * `AdbCommand.exec(command, retries)`.
 */
object AdbCommand {
    /** Channel-failure retries, used when a caller does not pass its own count. */
    const val DEFAULT_RETRIES = 3

    const val DEFAULT_TIMEOUT_MS = 30_000L

    /**
     * How long one round may spend getting a *usable* channel (connect + round-trip probe,
     * repeated). This is the "block internally" part: a flaky wireless-debugging endpoint
     * gets time to come back instead of failing the caller on the first try.
     */
    private const val CHANNEL_READY_BUDGET_MS = 20_000L

    /** Pause between two channel attempts (and after a failed command, before retrying). */
    private const val CHANNEL_GAP_MS = 800L

    private const val DISCOVERY_TIMEOUT_MS = 20_000L

    /** The round trip that proves a fresh connection is actually usable. */
    private const val PROBE_COMMAND = "true"
    private const val PROBE_TIMEOUT_MS = 5_000L

    /** The self-check: `id` for the identity, `/proc/self/status` for `Seccomp`. */
    const val SELF_CHECK_COMMAND = "id; cat /proc/self/status"
    const val SELF_CHECK_TIMEOUT_MS = 15_000L

    /** Log lines are capped so one `cat /proc/self/status` cannot drown the log panel. */
    private const val MAX_LOGGED_OUTPUT_LINES = 24

    /** What the caller gets back: an exit code plus combined output. */
    data class Result(val exitCode: Int, val output: String) {
        val ok: Boolean get() = exitCode == 0
        val transportFailure: Boolean get() = exitCode == ChainSpec.TRANSPORT_FAILURE
    }

    /** Serialises commands: two of them must never race into duplicate-identity connects. */
    private val gate = Mutex()

    @Volatile
    private var appContext: Context? = null

    @Volatile
    private var logger: (String) -> Unit = {}

    /** Bind the application context once (`GhostlockApplication.onCreate`). */
    fun attach(context: Context) {
        appContext = context.applicationContext
    }

    /** Where log lines go when a caller does not pass its own sink. */
    fun setLogger(sink: (String) -> Unit) {
        logger = sink
    }

    /**
     * Run one command on its own fresh, verified channel.
     *
     * @param retries how many rounds (channel failure -> wait -> new channel -> try again)
     *   are allowed. A non-repeatable command (see [ChainSpec.NON_IDEMPOTENT]) uses exactly
     *   one round regardless of this value.
     * @param timeoutMs how long the command itself may take.
     * @param onLog where the command, its output and the channel diagnostics go; defaults to
     *   the sink registered with [setLogger].
     */
    suspend fun exec(
        command: String,
        retries: Int = DEFAULT_RETRIES,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS,
        onLog: ((String) -> Unit)? = null,
    ): Result {
        val log = onLog ?: logger
        val context = appContext
        if (context == null) {
            log("[!] adb_command 尚未初始化，命令没有运行：$command")
            return Result(ChainSpec.TRANSPORT_FAILURE, "")
        }
        val repeatable = ChainSpec.NON_IDEMPOTENT.none { command.contains(it) }
        val rounds = if (repeatable) retries.coerceAtLeast(1) else 1
        return gate.withLock {
            var round = 0
            var last = "原因不明"
            while (round < rounds) {
                round++
                log("$ $command")
                /* Verified before the command runs: this is what keeps a non-repeatable
                 * command from being fired into a channel that is already dying. */
                val connection = try {
                    openVerified(context, log)
                } catch (error: Throwable) {
                    last = WirelessAdb.describe(error)
                    log("[!] 通道不可用 第$round/$rounds 轮：$last")
                    if (round < rounds) delay(CHANNEL_GAP_MS)
                    continue
                }
                try {
                    val outcome = WirelessAdb.shellWithExitCode(connection, command, timeoutMs)
                    logOutput(outcome.output, log)
                    if (outcome.exitCode != ChainSpec.TRANSPORT_FAILURE) {
                        return@withLock Result(outcome.exitCode, outcome.output)
                    }
                    last = "没有返回退出码，通道在命令执行中断开"
                } catch (error: Throwable) {
                    last = WirelessAdb.describe(error)
                } finally {
                    /* Complete release: nothing of this round survives into the next one. */
                    WirelessAdb.closeQuietly(connection)
                }
                log("[!] 第$round/$rounds 轮失败：$last")
                if (!repeatable) {
                    log("[!] 该命令不允许重复执行，停止")
                    break
                }
                if (round < rounds) delay(CHANNEL_GAP_MS)
            }
            log("[!] 命令未能执行：$last")
            Result(ChainSpec.TRANSPORT_FAILURE, "")
        }
    }

    /**
     * Make sure a channel can be opened and prove it with the self-check.
     *
     * Used before the chain starts: pairing is the standing authorization, so "paired but not
     * connected yet" is normal. The self-check is idempotent, so the whole cycle is repeated
     * on the same round budget.
     */
    suspend fun ensure(retries: Int = DEFAULT_RETRIES, onLog: ((String) -> Unit)? = null): Boolean {
        val log = onLog ?: logger
        val context = appContext
        if (context == null) {
            log("[!] adb_command 尚未初始化")
            return false
        }
        val rounds = retries.coerceAtLeast(1)
        return gate.withLock {
            var round = 0
            while (round < rounds) {
                round++
                /* No separate probe here: the self-check IS the verification. */
                val connection = try {
                    open(context, round, rounds, log)
                } catch (error: Throwable) {
                    log("[!] 连接失败 第$round/$rounds 轮：${WirelessAdb.describe(error)}")
                    if (round < rounds) delay(CHANNEL_GAP_MS)
                    continue
                }
                try {
                    val probe = WirelessAdb.shellWithExitCode(
                        connection,
                        SELF_CHECK_COMMAND,
                        SELF_CHECK_TIMEOUT_MS,
                    )
                    if (probe.exitCode != ChainSpec.TRANSPORT_FAILURE) {
                        val identity = probe.output.lineSequence()
                            .firstOrNull { it.trimStart().startsWith("uid=") }
                            ?.trim()
                            .orEmpty()
                        val seccomp = Regex("Seccomp:\\s*(\\d+)")
                            .find(probe.output)?.groupValues?.get(1)
                        log("[*] 通道就绪：$identity Seccomp=${seccomp ?: "?"}")
                        return@withLock true
                    }
                    log("[!] 自检没有返回 第$round/$rounds 轮")
                } catch (error: Throwable) {
                    log("[!] 自检失败 第$round/$rounds 轮：${WirelessAdb.describe(error)}")
                } finally {
                    WirelessAdb.closeQuietly(connection)
                }
                if (round < rounds) delay(CHANNEL_GAP_MS)
            }
            log("[!] 无线调试通道不可用")
            false
        }
    }

    // ---------------------------------------------------------------- internals

    /**
     * A fresh connection that has answered a round trip. Callers hold [gate].
     *
     * Keeps trying until [CHANNEL_READY_BUDGET_MS] runs out: a connect that fails, or a probe
     * that does not come back, means "this channel is not usable yet" -- not "the caller's
     * command failed" -- so it is retried here rather than returned upward.
     */
    private suspend fun openVerified(context: Context, onLog: (String) -> Unit): AdbConnection {
        val deadline = System.currentTimeMillis() + CHANNEL_READY_BUDGET_MS
        var attempt = 0
        var last: Throwable? = null
        while (true) {
            attempt++
            try {
                val connection = open(context, attempt, 0, onLog)
                if (probe(connection)) {
                    onLog("[*] 通道验证通过")
                    return connection
                }
                WirelessAdb.closeQuietly(connection)
                last = IllegalStateException("通道探针没有返回")
                onLog("[*] 通道探针没有返回，换一条通道")
            } catch (error: Throwable) {
                last = error
                onLog("[*] 连接失败：${WirelessAdb.describe(error)}")
            }
            if (System.currentTimeMillis() >= deadline) break
            delay(CHANNEL_GAP_MS)
        }
        throw IllegalStateException(
            "在 ${CHANNEL_READY_BUDGET_MS / 1000}s 内没有拿到可用通道：${WirelessAdb.describe(last)}",
            last,
        )
    }

    /** One connect, no retry. [rounds] of 0 means "part of openVerified's own loop". */
    private suspend fun open(
        context: Context,
        attempt: Int,
        rounds: Int,
        onLog: (String) -> Unit,
    ): AdbConnection {
        val endpoint = WirelessAdb.discover(
            context,
            WirelessAdb.SERVICE_CONNECT,
            DISCOVERY_TIMEOUT_MS,
        ) ?: throw IllegalStateException(
            "没有发现 ${WirelessAdb.SERVICE_CONNECT}，无线调试打开了吗",
        )
        val suffix = if (rounds > 0) " 第$attempt/$rounds 轮" else " 第$attempt 次"
        onLog("[*] 连接 $endpoint$suffix")
        val connection = WirelessAdb.connect(context, endpoint)
        onLog("[*] adb 已连接")
        return connection
    }

    /** A trivial round trip: the only way to know a fresh channel really works. */
    private fun probe(connection: AdbConnection): Boolean = runCatching {
        WirelessAdb.shellWithExitCode(connection, PROBE_COMMAND, PROBE_TIMEOUT_MS).exitCode == 0
    }.getOrDefault(false)

    private fun logOutput(output: String, onLog: (String) -> Unit) {
        val lines = output.lineSequence().filter { it.isNotBlank() }.toList()
        lines.take(MAX_LOGGED_OUTPUT_LINES).forEach(onLog)
        if (lines.size > MAX_LOGGED_OUTPUT_LINES) {
            onLog("[*] 其余 ${lines.size - MAX_LOGGED_OUTPUT_LINES} 行未展开")
        }
    }
}
