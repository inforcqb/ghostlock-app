package com.ghostlock.app.wireless

import android.content.Context
import com.ghostlock.app.chain.ChainSpec
import io.github.muntashirakon.adb.AdbConnection
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull

/**
 * `adb_command` -- the single entry point for talking to adbd.
 *
 * Nothing else in the app owns a connection: the channel self-check, the one-click chain
 * and the screen's buttons all run commands through here, and this object decides when to
 * connect, when to reuse and when to drop the session. That is what makes the channel
 * manageable, because every failure mode here is about *who holds the socket*:
 *
 *  * **one session at a time.** adbd kicks a transport when a second connection appears
 *    under the same client identity (measured on the PJA110: `I/adbd: kicking transport
 *    ... host-25`, then `SSL read failed`, then `ADB wifi device disconnected`). Two live
 *    connections are therefore not "two channels", they are a race that kills both -- which
 *    is exactly what happened when a completed self-check held a connection and the next
 *    tap tried to build another one;
 *  * **commands are serialised** on a mutex, so a chain step and a UI tap cannot interleave
 *    into that race;
 *  * **dead sessions are closed here**, so the next command reconnects instead of reading
 *    from a corpse;
 *  * **the retry count covers CHANNEL failures only.** A connect that fails proves nothing
 *    ran, so it may be repeated ([retries], default [DEFAULT_RETRIES]); a command that fails
 *    may already have run -- repeating `am hang --allow-restart`,
 *    `rmmod oplus_security_guard` or `/data/adb/ksud late-load` is worse than stopping -- so
 *    a command is never retried here. It is reported as [ChainSpec.TRANSPORT_FAILURE] and
 *    the chain's `NON_IDEMPOTENT` policy decides what may be repeated.
 *
 * Usage: [attach] once from the application, then
 * `AdbCommand.exec(command)` or `AdbCommand.exec(command, retries)`.
 */
object AdbCommand {
    /** Channel-failure retries: how often a *connect* may be attempted. */
    const val DEFAULT_RETRIES = 3

    private const val CONNECT_GAP_MS = 1_500L
    private const val DISCOVERY_TIMEOUT_MS = 20_000L
    const val DEFAULT_TIMEOUT_MS = 30_000L

    /**
     * Budget of the reuse probe.
     *
     * A kicked transport leaves libadb's flags saying "connected" while its reader thread
     * never delivers again, so flags cannot tell a live session from a zombie -- the device
     * showed exactly that: `复用已有连接` followed by a 15s timeout on the self-check. One
     * trivial round trip before trusting a reused session is cheap next to that.
     */
    private const val PROBE_COMMAND = "true"
    private const val PROBE_TIMEOUT_MS = 5_000L

    /**
     * The self-check, as ONE shell call: `id` for the identity and `/proc/self/status` for
     * `Seccomp`. One call means one stream (a kicked transport used to turn a second stream
     * into a 30s hang).
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

    private val mutex = Mutex()

    @Volatile
    private var appContext: Context? = null

    @Volatile
    private var logger: (String) -> Unit = {}

    @Volatile
    private var connection: AdbConnection? = null

    /** Bind the application context once (`GhostlockApplication.onCreate`). */
    fun attach(context: Context) {
        appContext = context.applicationContext
    }

    /** Where log lines go when a caller does not pass its own sink. */
    fun setLogger(sink: (String) -> Unit) {
        logger = sink
    }

    /**
     * Run one command, connecting first if there is no live session.
     *
     * @param retries how often a *channel* failure may be retried; it never retries the
     *   command itself. [DEFAULT_RETRIES] by default.
     * @param timeoutMs how long one command may take.
     * @param onLog where the command, its output and the channel diagnostics go; defaults
     *   to the sink registered with [setLogger].
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
        return mutex.withLock {
            log("$ $command")
            val active = try {
                connect(context, retries, log)
            } catch (error: Throwable) {
                log("[!] 通道不可用，命令没有运行：${WirelessAdb.describe(error)}")
                return@withLock Result(ChainSpec.TRANSPORT_FAILURE, "")
            }
            try {
                val outcome = WirelessAdb.shellWithExitCode(active, command, timeoutMs)
                logOutput(outcome.output, log)
                if (outcome.exitCode == ChainSpec.TRANSPORT_FAILURE) {
                    log("[!] 命令没有返回退出码，会话已失效并丢弃")
                    closeLocked()
                }
                Result(outcome.exitCode, outcome.output)
            } catch (error: Throwable) {
                log("[!] 命令执行失败，可能已经运行：${WirelessAdb.describe(error)}")
                closeLocked()
                Result(ChainSpec.TRANSPORT_FAILURE, "")
            }
        }
    }

    /**
     * Make sure a session exists and prove it with the self-check.
     *
     * Used before the chain starts: pairing is the standing authorization, so "paired but
     * not connected yet" is normal and is resolved here instead of failing inside step 1.
     */
    suspend fun ensure(retries: Int = DEFAULT_RETRIES, onLog: ((String) -> Unit)? = null): Boolean {
        val log = onLog ?: logger
        val context = appContext
        if (context == null) {
            log("[!] adb_command 尚未初始化")
            return false
        }
        val attempts = retries.coerceAtLeast(1)
        return mutex.withLock {
            var attempt = 0
            while (attempt < attempts) {
                attempt++
                try {
                    val active = connect(context, retries = 1, onLog = log)
                    val probe = WirelessAdb.shellWithExitCode(
                        active,
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
                    log("[!] 通道不可用 第$attempt/$attempts 次：${WirelessAdb.describe(error)}")
                }
                closeLocked()
                if (attempt < attempts) delay(CONNECT_GAP_MS)
            }
            log("[!] 无线调试通道不可用")
            false
        }
    }

    /** Drop the session. Best effort: a command in flight simply reconnects next time. */
    fun close() {
        val active = connection
        connection = null
        WirelessAdb.closeQuietly(active)
    }

    // ---------------------------------------------------------------- internals

    /**
     * A live connection, or a fresh one. Callers hold [mutex].
     *
     * [retries] counts *connect* attempts only, and the endpoint is re-discovered each time
     * because the wireless-debugging port changes whenever the user toggles it.
     */
    private suspend fun connect(
        context: Context,
        retries: Int,
        onLog: (String) -> Unit,
    ): AdbConnection {
        liveLocked()?.let { active ->
            onLog("[*] 复用已有连接")
            if (alive(active)) return active
            /* Flags said connected but a round trip says otherwise: the transport was
             * kicked while we were idle. Drop it and build a fresh one. */
            onLog("[*] 复用的连接已失效，重连")
            closeLocked()
        }
        val attempts = retries.coerceAtLeast(1)
        var last: Throwable? = null
        for (attempt in 1..attempts) {
            val endpoint = WirelessAdb.discover(
                context,
                WirelessAdb.SERVICE_CONNECT,
                DISCOVERY_TIMEOUT_MS,
            )
            if (endpoint == null) {
                last = IllegalStateException(
                    "没有发现 ${WirelessAdb.SERVICE_CONNECT}，无线调试打开了吗",
                )
            } else {
                onLog("[*] 连接端点 $endpoint 第$attempt/$attempts 次")
                try {
                    val fresh = WirelessAdb.connect(context, endpoint)
                    connection = fresh
                    onLog("[*] adb 已连接")
                    return fresh
                } catch (error: Throwable) {
                    last = error
                    closeLocked()
                }
            }
            if (attempt < attempts) {
                onLog("[*] 连接失败 第$attempt/$attempts 次：${WirelessAdb.describe(last)}")
                delay(CONNECT_GAP_MS)
            }
        }
        throw IllegalStateException(
            "adb 连接失败 $attempts 次：${WirelessAdb.describe(last)}",
            last,
        )
    }

    private fun logOutput(output: String, onLog: (String) -> Unit) {
        val lines = output.lineSequence().filter { it.isNotBlank() }.toList()
        lines.take(MAX_LOGGED_OUTPUT_LINES).forEach(onLog)
        if (lines.size > MAX_LOGGED_OUTPUT_LINES) {
            onLog("[*] 其余 ${lines.size - MAX_LOGGED_OUTPUT_LINES} 行未展开")
        }
    }

    /** A trivial round trip: the only way to tell a live session from a kicked one. */
    private suspend fun alive(active: AdbConnection): Boolean = runCatching {
        withTimeoutOrNull(PROBE_TIMEOUT_MS + 2_000L) {
            WirelessAdb.shellWithExitCode(active, PROBE_COMMAND, PROBE_TIMEOUT_MS).exitCode == 0
        } ?: false
    }.getOrDefault(false)

    /** The current session if it is still usable, otherwise null (and dropped). */
    private fun liveLocked(): AdbConnection? {
        val active = connection ?: return null
        val alive = runCatching { active.isConnected && active.isConnectionEstablished }
            .getOrDefault(false)
        if (!alive) {
            closeLocked()
            return null
        }
        return active
    }

    private fun closeLocked() {
        WirelessAdb.closeQuietly(connection)
        connection = null
    }
}
