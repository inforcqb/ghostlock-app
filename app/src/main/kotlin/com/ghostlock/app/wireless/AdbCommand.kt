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
 * completely before returning, so no session is ever carried between commands. That is a
 * deliberate change of model, because holding a session kept failing on the device:
 *
 *  * adbd kicks a transport when a second connection appears under the same client
 *    identity (`I/adbd: kicking transport ... host-25`, `SSL read failed`,
 *    `ADB wifi device disconnected`). Reusing a session therefore meant "hold a session
 *    that adbd may kick at any moment", and a kicked transport looks *connected* to libadb
 *    (`isConnected`/`isConnectionEstablished` stay true) while its reader never delivers
 *    again -- so the next command either hung until its watchdog or died with
 *    `Stream closed.` on the freshly opened stream;
 *  * the device log showed exactly that cascade: `复用已有连接` -> probe says the session is
 *    dead -> fresh connection -> `Stream closed.` again, command after command.
 *
 * Opening a connection per command is what `adb shell cmd` itself does, and it makes the
 * lifecycle trivial: connect, run, close. A short settle between the release and the next
 * connect ([RELEASE_SETTLE_MS]) keeps adbd from seeing the new connection as a duplicate of
 * one it has not finished tearing down.
 *
 * ## Retries
 *
 * [exec]'s second parameter is the retry count for **channel** failures -- a connect that
 * did not happen, or a stream that died without ever reporting an exit code. It defaults to
 * [DEFAULT_RETRIES]. Safety is enforced here, not left to the caller: a command that
 * appears in [ChainSpec.NON_IDEMPOTENT] (`am hang --allow-restart`,
 * `rmmod oplus_security_guard`, `/data/adb/ksud late-load`, the two `setprop`s) is **never**
 * repeated, because a failed read may mean the command did run and running those twice is
 * worse than stopping. Those return [ChainSpec.TRANSPORT_FAILURE] on the first failure.
 *
 * Usage: [attach] once from the application, then `AdbCommand.exec(command)` or
 * `AdbCommand.exec(command, retries)`.
 */
object AdbCommand {
    /** Channel-failure retries, used when a caller does not pass its own count. */
    const val DEFAULT_RETRIES = 3

    const val DEFAULT_TIMEOUT_MS = 30_000L

    /** Pause between a full release and the next connect, so adbd sees no duplicate. */
    private const val RELEASE_SETTLE_MS = 500L

    /** Pause between two attempts that failed before running anything. */
    private const val CONNECT_GAP_MS = 1_500L

    private const val DISCOVERY_TIMEOUT_MS = 20_000L

    /**
     * The self-check, as ONE shell call: `id` for the identity and `/proc/self/status` for
     * `Seccomp`.
     */
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
     * Run one command on its own fresh channel.
     *
     * @param retries how often a *channel* failure may be retried; a non-repeatable command
     *   (see [ChainSpec.NON_IDEMPOTENT]) is never retried regardless of this value.
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
        val attempts = retries.coerceAtLeast(1)
        /* A command that must not run twice is never retried -- a failed read may mean it ran. */
        val repeatable = ChainSpec.NON_IDEMPOTENT.none { command.contains(it) }
        return gate.withLock {
            var attempt = 0
            var last = "原因不明"
            while (attempt < attempts) {
                attempt++
                log("$ $command")
                val connection = try {
                    open(context, attempt, attempts, log)
                } catch (error: Throwable) {
                    last = WirelessAdb.describe(error)
                    log("[!] 通道不可用 第$attempt/$attempts 次：$last")
                    if (!repeatable || attempt >= attempts) break
                    delay(CONNECT_GAP_MS)
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
                    /* Complete release: nothing of this attempt survives into the next one. */
                    WirelessAdb.closeQuietly(connection)
                }
                log("[!] 第$attempt/$attempts 次失败：$last")
                if (!repeatable) {
                    log("[!] 该命令不允许重复执行，停止")
                    break
                }
                if (attempt < attempts) delay(RELEASE_SETTLE_MS)
            }
            log("[!] 命令未能执行：$last")
            Result(ChainSpec.TRANSPORT_FAILURE, "")
        }
    }

    /**
     * Make sure a channel can be opened and prove it with the self-check.
     *
     * Used before the chain starts: pairing is the standing authorization, so "paired but not
     * connected yet" is normal. The self-check is idempotent, so this retries the whole
     * connect + self-check cycle up to [retries] times.
     */
    suspend fun ensure(retries: Int = DEFAULT_RETRIES, onLog: ((String) -> Unit)? = null): Boolean {
        val log = onLog ?: logger
        val context = appContext
        if (context == null) {
            log("[!] adb_command 尚未初始化")
            return false
        }
        val attempts = retries.coerceAtLeast(1)
        return gate.withLock {
            var attempt = 0
            while (attempt < attempts) {
                attempt++
                val connection = try {
                    open(context, attempt, attempts, log)
                } catch (error: Throwable) {
                    log("[!] 通道不可用 第$attempt/$attempts 次：${WirelessAdb.describe(error)}")
                    if (attempt < attempts) delay(CONNECT_GAP_MS)
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
                    log("[!] 自检没有返回 第$attempt/$attempts 次")
                } catch (error: Throwable) {
                    log("[!] 自检失败 第$attempt/$attempts 次：${WirelessAdb.describe(error)}")
                } finally {
                    WirelessAdb.closeQuietly(connection)
                }
                if (attempt < attempts) delay(RELEASE_SETTLE_MS)
            }
            log("[!] 无线调试通道不可用")
            false
        }
    }

    // ---------------------------------------------------------------- internals

    /** Open one connection, on its own. Callers hold [gate] and must close what they get. */
    private suspend fun open(
        context: Context,
        attempt: Int,
        attempts: Int,
        onLog: (String) -> Unit,
    ): AdbConnection {
        val endpoint = WirelessAdb.discover(
            context,
            WirelessAdb.SERVICE_CONNECT,
            DISCOVERY_TIMEOUT_MS,
        ) ?: throw IllegalStateException(
            "没有发现 ${WirelessAdb.SERVICE_CONNECT}，无线调试打开了吗",
        )
        onLog("[*] 连接 $endpoint 第$attempt/$attempts 次")
        val connection = WirelessAdb.connect(context, endpoint)
        onLog("[*] adb 已连接")
        return connection
    }

    private fun logOutput(output: String, onLog: (String) -> Unit) {
        val lines = output.lineSequence().filter { it.isNotBlank() }.toList()
        lines.take(MAX_LOGGED_OUTPUT_LINES).forEach(onLog)
        if (lines.size > MAX_LOGGED_OUTPUT_LINES) {
            onLog("[*] 其余 ${lines.size - MAX_LOGGED_OUTPUT_LINES} 行未展开")
        }
    }
}
