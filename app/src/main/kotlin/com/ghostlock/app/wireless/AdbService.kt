package com.ghostlock.app.wireless

import android.content.Context
import com.ghostlock.app.chain.ChainSpec
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
 * Owns the wireless-debugging channel and keeps it alive.
 *
 * The channel is now the bundled `adb` (see [AdbCli]): this service starts the adb **server**
 * once and keeps the **transport** to the device in the `device` state, so every command the
 * app runs goes over one session that the real adb server maintains. That is the model that
 * fits adbd, which accepts a single wireless-debugging session at a time -- measured on the
 * device: while the app held that session, a second client (even the same adb binary) could
 * not connect at all.
 *
 * Liveness has two layers:
 *
 *  * the adb server reconnects the transport on its own (it is the same code a PC runs);
 *  * this service checks it every [KEEP_ALIVE_INTERVAL_MS] with `adb devices` and reconnects
 *    when the transport disappears, logging each transition, so the UI can show it.
 *
 * Safety is enforced here: a command listed in [ChainSpec.NON_IDEMPOTENT] is executed exactly
 * once -- a failed read may mean it DID run, and repeating `am hang --allow-restart`,
 * `rmmod oplus_security_guard` or `/data/adb/ksud late-load` is worse than stopping.
 */
object AdbService {
    private const val KEEP_ALIVE_INTERVAL_MS = 5_000L
    private const val GAP_MS = 800L
    private const val SERVICE_CONNECT = "_adb-tls-connect"
    private const val SERVICE_PAIRING = "_adb-tls-pairing"

    /** What a command produced; [transportFailure] means it never ran. */
    data class Result(val exitCode: Int, val output: String) {
        val ok: Boolean get() = exitCode == 0
        val transportFailure: Boolean get() = exitCode == ChainSpec.TRANSPORT_FAILURE
    }

    private val gate = Mutex()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var keepAlive: Job? = null

    @Volatile
    private var cli: AdbCli? = null

    @Volatile
    private var logger: (String) -> Unit = {}

    @Volatile
    private var liveness: ((Boolean) -> Unit)? = null

    /** The connected endpoint (`ip:port`), i.e. the transport we send commands to. */
    @Volatile
    private var serial: String? = null

    /** True once a transport worked in this process; keeps the keep-alive quiet before that. */
    @Volatile
    private var everConnected = false

    fun attach(context: Context) {
        if (cli == null) {
            val created = AdbCli(context.applicationContext)
            cli = created
            logger("[*] 内置 adb：${created.available}")
        }
        startKeepAlive()
    }

    fun setLogger(sink: (String) -> Unit) {
        logger = sink
    }

    /** The sink registered with [setLogger]; used when a caller does not pass its own. */
    fun defaultLogger(): (String) -> Unit = logger

    fun setLivenessListener(sink: ((Boolean) -> Unit)?) {
        liveness = sink
    }

    // ---------------------------------------------------------------- commands

    /**
     * Run one command over the held transport.
     *
     * `rounds` counts how often a *channel* failure may be retried; a non-repeatable command
     * gets exactly one round.
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
                val target = try {
                    transport(onLog)
                } catch (error: Throwable) {
                    last = error.message ?: error::class.java.simpleName
                    onLog("[!] 通道不可用 第$round/$attempts 轮：$last")
                    if (round < attempts) delay(GAP_MS)
                    continue
                }
                val result = cli()?.shell(target, command, timeoutMs)
                    ?: return@withLock Result(ChainSpec.TRANSPORT_FAILURE, "")
                if (result.exitCode >= 0 && !result.transportFailure) {
                    logOutput(result.output, onLog)
                    return@withLock Result(result.exitCode, result.output)
                }
                last = if (result.transportFailure) {
                    "adb 报告传输失败：${result.output.trim().take(160)}"
                } else {
                    "命令没有返回（超时或被中断）"
                }
                logOutput(result.output, onLog)
                /* The transport is suspect: drop it so the next round (or the keep-alive
                 * tick) connects again instead of reusing a dead session. */
                dropTransport("命令期间传输失败", onLog)
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

    /** Make sure a usable transport exists; the self-check itself is run by the caller. */
    suspend fun ensure(rounds: Int, onLog: (String) -> Unit): Boolean = gate.withLock {
        try {
            transport(onLog)
            true
        } catch (error: Throwable) {
            onLog("[!] 无线调试通道不可用：${error.message ?: error::class.java.simpleName}")
            false
        }
    }

    /** Identity of the connected device, or null when nothing is connected. */
    suspend fun identity(onLog: (String) -> Unit): String? = gate.withLock {
        val target = runCatching { transport(onLog) }.getOrNull() ?: return@withLock null
        val result = cli()?.shell(target, "id", 15_000) ?: return@withLock null
        if (result.transportFailure) null else result.output.trim()
    }

    // ---------------------------------------------------------------- pairing

    /** The `_adb-tls-pairing` endpoint mDNS currently advertises, or null. */
    fun pairingEndpoints(): List<String> = cli()?.mdnsServices()
        ?.filter { it.serviceType == SERVICE_PAIRING }
        ?.map { it.endpoint }
        ?: emptyList()

    /** The CLI's mDNS listing verbatim -- diagnostics for "it found nothing". */
    fun rawMdnsServices(): String =
        cli()?.run(listOf("mdns", "services"), 20_000)?.output?.trim().orEmpty()

    /** Pair with the code from the system dialog. Returns the CLI's message. */
    fun pair(endpoint: String, code: String): String {
        val result = cli()?.pair(endpoint, code)
            ?: return "内置 adb 不可用"
        return result.output.ifBlank { "exit=${result.exitCode}" }
    }

    /** Connect to the advertised `_adb-tls-connect` endpoint; false when none worked. */
    fun connectAdvertised(onLog: (String) -> Unit): Boolean {
        val candidates = cli()?.mdnsServices()
            ?.filter { it.serviceType == SERVICE_CONNECT }
            ?.map { it.endpoint }
            .distinct()
            .orEmpty()
        if (candidates.isEmpty()) {
            onLog("[!] 还没有发现无线调试端点：请确认「无线调试」已打开，并先在「打开无线调试」里完成配对")
            return false
        }
        for (endpoint in candidates) {
            val result = cli()?.connect(endpoint) ?: return false
            val message = result.output.trim().ifBlank { "exit=${result.exitCode}" }
            if (cli()?.stateOf(endpoint) == "device") {
                serial = endpoint
                everConnected = true
                onLog("[*] 已连上 $endpoint")
                liveness?.invoke(true)
                return true
            }
            onLog("[!] 连接 $endpoint 失败：$message")
        }
        onLog("[!] 所有候选端点都没连上：请确认本机已完成配对（配对码是否输过），并保持无线调试开启")
        return false
    }

    fun close() {
        keepAlive?.cancel()
        keepAlive = null
        serial = null
    }

    // ---------------------------------------------------------------- internals

    private fun cli(): AdbCli? = cli

    /**
     * The transport to run commands on: the held one when it is still `device`, otherwise a
     * freshly connected advertised endpoint. Callers hold [gate].
     */
    private fun transport(onLog: (String) -> Unit): String {
        val active = serial
        val cli = cli ?: throw IllegalStateException("AdbService 尚未初始化")
        if (!cli.available) throw IllegalStateException("内置 adb 缺失")
        if (active != null) {
            if (cli.stateOf(active) == "device") return active
            onLog("[*] 传输 $active 已掉线")
            dropTransport(null, onLog)
        }
        if (!connectAdvertised(onLog)) {
            throw IllegalStateException("还没有可用的无线调试通道：请先完成配对并保持无线调试开启")
        }
        return serial ?: throw IllegalStateException("连接成功但没有拿到序列号")
    }

    private fun dropTransport(reason: String?, onLog: (String) -> Unit = logger) {
        val previous = serial
        serial = null
        if (previous != null) {
            reason?.let { onLog("[*] 传输已丢弃：$it（$previous）") }
            liveness?.invoke(false)
        }
    }

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
            runCatching { cli()?.startServer() }
                ?.onFailure { logger("[*] adb server 启动失败：${it.message}") }
            while (isActive) {
                delay(KEEP_ALIVE_INTERVAL_MS)
                runCatching { keepAliveTick() }
            }
        }
    }

    /**
     * Keep the transport in the `device` state.
     *
     * The adb server reconnects on its own, so this only has to notice and log the
     * transitions -- and, once a transport has worked in this process, reconnect when the
     * server gave up. Before the first successful connection it does nothing, so an app whose
     * user has not paired yet does not fill the log.
     */
    private suspend fun keepAliveTick() = gate.withLock {
        val cli = cli ?: return@withLock
        val active = serial
        if (active == null) {
            if (!everConnected) return@withLock
            if (connectAdvertised(logger)) logger("[*] 保活：通道已恢复") else logger("[*] 保活：暂时没有可连的端点")
            return@withLock
        }
        if (cli.stateOf(active) == "device") return@withLock
        logger("[*] 保活：传输掉线，重新连接")
        dropTransport(null)
        if (connectAdvertised(logger)) logger("[*] 保活：通道已恢复")
    }

    private const val MAX_LOGGED_OUTPUT_LINES = 24
}
