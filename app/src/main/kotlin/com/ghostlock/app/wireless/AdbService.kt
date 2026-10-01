package com.ghostlock.app.wireless

import android.content.Context
import com.ghostlock.app.chain.ChainSpec
import io.github.muntashirakon.adb.AdbConnection
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Holds the wireless-debugging channel and keeps it alive.
 *
 * This is the session owner: it opens ONE connection, keeps it, and checks it on a timer so
 * a channel that adbd kicked is noticed while it is idle instead of when the next command
 * runs into it. Everything that wants to run something goes through [AdbCommand], which
 * submits to this service; nothing else touches a connection.
 *
 * Why a held session, given that "one channel per command" also failed? Because the failures
 * came from two different places and each model only fixed one of them:
 *
 *  * per-command channels re-connect constantly, and every connect of the same client
 *    identity risks the duplicate-kick race (adbd kicks a transport when a second connection
 *    shows up), so half the fresh streams died with `Stream closed.`;
 *  * a held session never faces that race, but it can silently become a zombie: a kicked
 *    transport still reports `isConnected`/`isConnectionEstablished` while its reader never
 *    delivers again.
 *
 * Holding the session **and** probing it on a timer addresses both: one connection for as
 * long as it works, and a liveness check that drops it as soon as it stops answering, so
 * [exec] never runs a command on a dead channel.
 *
 * Safety is unchanged and enforced here: a command whose text appears in
 * [ChainSpec.NON_IDEMPOTENT] is executed exactly once -- a failed read may mean it DID run,
 * and repeating `am hang --allow-restart`, `rmmod oplus_security_guard` or
 * `/data/adb/ksud late-load` is worse than stopping.
 */
object AdbService {
    /** How often an idle session is probed. */
    private const val KEEP_ALIVE_INTERVAL_MS = 5_000L

    /** Budget of one liveness probe / one command channel. */
    private const val PROBE_COMMAND = "true"
    private const val PROBE_TIMEOUT_MS = 5_000L

    /** How long one attempt at (re)establishing the session may take. */
    private const val CONNECT_BUDGET_MS = 20_000L

    /** Pause between two attempts, and between two command rounds. */
    private const val GAP_MS = 800L

    private const val DISCOVERY_TIMEOUT_MS = 20_000L

    /** What a command produced. */
    data class Result(val exitCode: Int, val output: String) {
        val ok: Boolean get() = exitCode == 0
        val transportFailure: Boolean get() = exitCode == ChainSpec.TRANSPORT_FAILURE
    }

    private val gate = Mutex()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var keepAlive: Job? = null

    @Volatile
    private var appContext: Context? = null

    @Volatile
    private var logger: (String) -> Unit = {}

    @Volatile
    private var liveness: ((Boolean) -> Unit)? = null

    @Volatile
    private var connection: AdbConnection? = null

    /** True once this process managed to establish a session (used to avoid reconnect spam). */
    @Volatile
    private var everConnected = false

    /** Bind the application context once (`GhostlockApplication.onCreate`) and start keeping alive. */
    fun attach(context: Context) {
        appContext = context.applicationContext
        startKeepAlive()
    }

    fun setLogger(sink: (String) -> Unit) {
        logger = sink
    }

    /** The sink registered with [setLogger]; used when a caller does not pass its own. */
    fun defaultLogger(): (String) -> Unit = logger

    /** Called whenever the held session becomes usable or stops being usable. */
    fun setLivenessListener(sink: ((Boolean) -> Unit)?) {
        liveness = sink
    }

    /**
     * Run one command on the held session, (re)establishing it if necessary.
     *
     * `rounds` counts how often a *channel* failure may be retried; a non-repeatable command
     * gets exactly one round no matter what the caller asks for.
     */
    suspend fun exec(
        command: String,
        timeoutMs: Long,
        rounds: Int,
        onLog: (String) -> Unit,
    ): Result {
        val repeatable = ChainSpec.NON_IDEMPOTENT.none { command.contains(it) }
        val attempts = if (repeatable) rounds.coerceAtLeast(1) else 1
        return gate.withLock {
            var round = 0
            var last = "原因不明"
            while (round < attempts) {
                round++
                onLog("$ $command")
                val active = try {
                    session(onLog)
                } catch (error: Throwable) {
                    last = WirelessAdb.describe(error)
                    onLog("[!] 通道不可用 第$round/$attempts 轮：$last")
                    if (round < attempts) delay(GAP_MS)
                    continue
                }
                try {
                    val outcome = WirelessAdb.shellWithExitCode(active, command, timeoutMs)
                    logOutput(outcome.output, onLog)
                    if (outcome.exitCode != ChainSpec.TRANSPORT_FAILURE) {
                        return@withLock Result(outcome.exitCode, outcome.output)
                    }
                    last = "没有返回退出码，通道在命令执行中断开"
                } catch (error: Throwable) {
                    last = WirelessAdb.describe(error)
                }
                /* The session is suspect now: drop it, so the next command (or the keep-alive
                 * tick) builds a fresh one instead of reusing a half-dead transport. */
                dropSession("命令期间通道断开", onLog)
                onLog("[!] 第$round/$attempts 轮失败：$last")
                if (!repeatable) {
                    onLog("[!] 该命令不允许重复执行，停止")
                    break
                }
                if (round < attempts) delay(GAP_MS)
            }
            onLog("[!] 命令未能执行：$last")
            Result(ChainSpec.TRANSPORT_FAILURE, "")
        }
    }

    /**
     * Make sure the held session exists and a round trip comes back.
     *
     * Used before the chain starts and by the screen's connect button.
     */
    suspend fun ensure(rounds: Int, onLog: (String) -> Unit): Boolean = gate.withLock {
        try {
            session(onLog)
            true
        } catch (error: Throwable) {
            onLog("[!] 无线调试通道不可用：${WirelessAdb.describe(error)}")
            false
        }
    }

    /** Drop the session and stop keeping it alive (there is nothing to release otherwise). */
    fun close() {
        keepAlive?.cancel()
        keepAlive = null
        val active = connection
        connection = null
        WirelessAdb.closeQuietly(active)
    }

    // ---------------------------------------------------------------- session

    /**
     * The held session, verified. Callers hold [gate].
     *
     * A verified session is never rebuilt -- that is the point of holding one: adbd punishes
     * a second connection under the same client identity. Only when it is missing or dead is
     * a new one opened, and then the old one is closed first.
     */
    private suspend fun session(onLog: (String) -> Unit): AdbConnection {
        connection?.let { active ->
            if (probe(active)) return active
            onLog("[*] 持有连接已失效，重连")
            dropSession(null)
        }
        val deadline = System.currentTimeMillis() + CONNECT_BUDGET_MS
        var attempt = 0
        var last: Throwable? = null
        while (true) {
            attempt++
            try {
                val fresh = open(onLog, attempt)
                if (probe(fresh)) {
                    connection = fresh
                    everConnected = true
                    onLog("[*] 通道就绪且验证通过")
                    liveness?.invoke(true)
                    return fresh
                }
                last = IllegalStateException("探针没有返回")
                WirelessAdb.closeQuietly(fresh)
                onLog("[*] 新通道探针没有返回，换一条")
            } catch (error: Throwable) {
                last = error
                onLog("[*] 连接失败：${WirelessAdb.describe(error)}")
            }
            if (System.currentTimeMillis() >= deadline) break
            delay(GAP_MS)
        }
        liveness?.invoke(false)
        throw IllegalStateException(
            "在 ${CONNECT_BUDGET_MS / 1000}s 内没有建立可用通道：${WirelessAdb.describe(last)}",
            last,
        )
    }

    private suspend fun open(onLog: (String) -> Unit, attempt: Int): AdbConnection {
        val context = appContext ?: throw IllegalStateException("AdbService 尚未初始化")
        val endpoint = WirelessAdb.discover(
            context,
            WirelessAdb.SERVICE_CONNECT,
            DISCOVERY_TIMEOUT_MS,
        ) ?: throw IllegalStateException(
            "没有发现 ${WirelessAdb.SERVICE_CONNECT}，无线调试打开了吗",
        )
        onLog("[*] 连接 $endpoint 第$attempt 次")
        val fresh = WirelessAdb.connect(context, endpoint)
        onLog("[*] adb 已连接")
        return fresh
    }

    /** A trivial round trip: the only way to tell a live session from a kicked one. */
    private fun probe(active: AdbConnection): Boolean = runCatching {
        WirelessAdb.shellWithExitCode(active, PROBE_COMMAND, PROBE_TIMEOUT_MS).exitCode == 0
    }.getOrDefault(false)

    private fun dropSession(reason: String?, onLog: (String) -> Unit = logger) {
        val active = connection
        connection = null
        WirelessAdb.closeQuietly(active)
        if (active != null) {
            reason?.let { onLog("[*] 会话已丢弃：$it") }
            liveness?.invoke(false)
        }
    }

    /** Log a command's output, capped so `cat /proc/self/status` cannot drown the log panel. */
    private fun logOutput(output: String, onLog: (String) -> Unit) {
        val lines = output.lineSequence().filter { it.isNotBlank() }.toList()
        lines.take(MAX_LOGGED_OUTPUT_LINES).forEach(onLog)
        if (lines.size > MAX_LOGGED_OUTPUT_LINES) {
            onLog("[*] 其余 ${lines.size - MAX_LOGGED_OUTPUT_LINES} 行未展开")
        }
    }

    // ---------------------------------------------------------------- keep-alive

    private fun startKeepAlive() {
        if (keepAlive?.isActive == true) return
        keepAlive = scope.launch {
            while (isActive) {
                delay(KEEP_ALIVE_INTERVAL_MS)
                runCatching { keepAliveTick() }
            }
        }
    }

    /**
     * One liveness tick.
     *
     * Probes the held session and drops it when it stops answering, so a zombie is discovered
     * while idle. It also restores a session that *was* established in this process and then
     * died, but it never starts connecting for an app that has not connected yet (that would
     * just log failures while the user has not paired).
     */
    private suspend fun keepAliveTick() = gate.withLock {
        val active = connection
        if (active != null) {
            if (probe(active)) return@withLock
            logger("[*] 保活：通道不再应答，丢弃并重连")
            dropSession(null)
        } else if (!everConnected) {
            return@withLock
        }
        try {
            val fresh = open(logger, 1)
            if (probe(fresh)) {
                connection = fresh
                logger("[*] 保活：通道已恢复")
                liveness?.invoke(true)
            } else {
                WirelessAdb.closeQuietly(fresh)
            }
        } catch (error: Throwable) {
            logger("[*] 保活：重连失败（${WirelessAdb.describe(error)}），稍后再试")
        }
    }

    private const val MAX_LOGGED_OUTPUT_LINES = 24
}
