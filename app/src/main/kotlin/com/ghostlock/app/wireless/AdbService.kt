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
import kotlinx.coroutines.withContext

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
    /* `adb mdns services` prints the type as `_adb-tls-connect._tcp.` and AdbCli normalises
     * it to `adb-tls-connect` (the leading underscore is trimmed), so these constants must
     * match THAT form; comparing against the underscored form filtered every candidate away
     * and left the pairing flow with nothing but the NsdManager fallback. */
    private const val SERVICE_CONNECT = "adb-tls-connect"
    private const val SERVICE_PAIRING = "adb-tls-pairing"
    private const val CONNECT_ROUNDS = 5
    private const val CONNECT_ROUND_GAP_MS = 1_500L
    private const val NSD_CONNECT_TIMEOUT_MS = 6_000L
    private const val PUSH_TIMEOUT_MS = 180_000L

    @Volatile
    private var appContext: Context? = null

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

    /**
     * The local root adbd (`127.0.0.1:5555`) once the chain has opened the gate.
     *
     * From that moment on, the wireless-debugging transport is the wrong one -- restarting
     * adbd (chain step 6) killed it, and reconnecting it would kick the root transport the
     * remaining steps run on. Setting this makes both [transport] and the keep-alive look
     * after the root serial instead.
     */
    @Volatile
    private var rootSerial: String? = null

    /** True once a transport worked in this process; keeps the keep-alive quiet before that. */
    @Volatile
    private var everConnected = false

    fun attach(context: Context) {
        appContext = context.applicationContext
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
    ): Result = runCommand(command, timeoutMs, rounds, onLog, root = false)

    /**
     * Run one command on an explicit serial.
     *
     * Used for the root adbd (`127.0.0.1:5555`): the CLI is the same binary and the same
     * server, `-s` just picks the transport.
     */
    suspend fun execOn(
        serial: String,
        command: String,
        timeoutMs: Long,
        rounds: Int,
        onLog: (String) -> Unit,
    ): Result = withContext(Dispatchers.IO) {
        runCommand(command, timeoutMs, rounds, onLog, root = false, forcedSerial = serial)
    }

    /**
     * Send a local file to the device with `adb push`.
     *
     * Needed because a device-side `cp` cannot read the app's files: `/data/app/<pkg>/lib`
     * is not readable by uid 2000 (checked on the PJA110). Returns false when the push
     * failed, so the caller never assumes a file arrived.
     */
    suspend fun push(
        localPath: String,
        remotePath: String,
        onLog: (String) -> Unit,
    ): Boolean = withContext(Dispatchers.IO) {
        gate.withLock {
            val target = runCatching { transport(onLog) }.getOrElse {
                onLog("[!] 推送前没有可用通道：${it.message}")
                return@withLock false
            }
            onLog("$ adb -s $target push $localPath $remotePath")
            val result = cli()?.run(listOf("-s", target, "push", localPath, remotePath), PUSH_TIMEOUT_MS) {
                onLog(it)
            } ?: return@withLock false
            if (result.exitCode != 0) {
                onLog("[!] adb push 退出码 ${result.exitCode}：${result.output.take(200)}")
            }
            result.exitCode == 0
        }
    }

    /**
     * `adb connect <endpoint>` and remember it as the root transport.
     *
     * adbd has just been restarted (chain step 6), so the first rounds legitimately fail
     * while it is still coming up: the retry budget is the point of this function.
     */
    suspend fun connectRoot(endpoint: String, rounds: Int, onLog: (String) -> Unit): Boolean =
        withContext(Dispatchers.IO) {
            gate.withLock { connectEndpoint(endpoint, rounds, onLog) }
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
        val context = appContext ?: return false
        for (round in 1..CONNECT_ROUNDS) {
            /* The platform resolver first: the CLI's mDNS listing is a cache and still shows
             * ports adbd has already moved away from (measured: three stale ones after a
             * pairing, while the live port was a fresh one that was not in the list yet). */
            val fresh = NsdPairingFinder.find(context, NSD_CONNECT_TIMEOUT_MS, NsdPairingFinder.CONNECT)
            val fromCli = cli()?.mdnsServices()
                ?.filter { it.serviceType == SERVICE_CONNECT }
                ?.map { it.endpoint }
                .orEmpty()
            val candidates = (listOfNotNull(fresh) + fromCli).distinct()
            if (candidates.isEmpty()) {
                onLog("[!] 第$round/$CONNECT_ROUNDS 次：还没发现无线调试端点（无线调试是否已打开？）")
            }
            for (endpoint in candidates) {
                val result = cli()?.connect(endpoint) ?: return false
                if (cli()?.stateOf(endpoint) == "device") {
                    serial = endpoint
                    everConnected = true
                    onLog("[*] 已连上 $endpoint")
                    liveness?.invoke(true)
                    return true
                }
                onLog("[!] 连接 $endpoint 失败：${result.output.trim().ifBlank { "exit=${result.exitCode}" }}")
            }
            if (round < CONNECT_ROUNDS) Thread.sleep(CONNECT_ROUND_GAP_MS)
        }
        onLog("[!] 没有连上的端点：请确认本机已配对（输过 6 位配对码）并保持无线调试开启")
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
     * One command with the channel's retry policy.
     *
     * `rounds` counts how often a *channel* failure may be retried; a non-repeatable command
     * gets exactly one round. [root] / [forcedSerial] select the transport: the held wireless
     * one by default, an explicit serial for the root adbd.
     */
    private suspend fun runCommand(
        command: String,
        timeoutMs: Long,
        rounds: Int,
        onLog: (String) -> Unit,
        root: Boolean,
        forcedSerial: String? = null,
    ): Result = withContext(Dispatchers.IO) {
        val repeatable = ChainSpec.NON_IDEMPOTENT.none { command.contains(it) }
        val attempts = if (repeatable) rounds.coerceAtLeast(1) else 1
        gate.withLock {
            var round = 0
            var last = "原因不明"
            while (round < attempts) {
                round++
                onLog("$ $command")
                val target = try {
                    forcedSerial ?: if (root) requireRootTransport(onLog) else transport(onLog)
                } catch (error: Throwable) {
                    last = error.message ?: error::class.java.simpleName
                    onLog("[!] 通道不可用 第$round/$attempts 轮：$last")
                    if (round < attempts) delay(GAP_MS)
                    continue
                }
                val result = cli()?.shell(target, command, timeoutMs) { line -> onLog(line) }
                    ?: return@withLock Result(ChainSpec.TRANSPORT_FAILURE, "")
                if (result.exitCode >= 0 && !result.transportFailure) {
                    return@withLock Result(result.exitCode, result.output)
                }
                last = if (result.transportFailure) {
                    "adb 报告传输失败：${result.output.trim().take(160)}"
                } else {
                    "命令没有返回（超时或被中断）"
                }
                /* The transport is suspect: drop it so the next round (or the keep-alive
                 * tick) connects again instead of reusing a dead session. */
                if (forcedSerial != null || root) {
                    rootSerial = null
                    onLog("[*] 根传输已丢弃：$last")
                } else {
                    dropTransport("命令期间传输失败", onLog)
                }
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

    /** The root adbd transport, or an exception when it is not there. */
    private fun requireRootTransport(onLog: (String) -> Unit): String {
        val root = rootSerial ?: throw IllegalStateException("根 adbd 还没连上（先连 127.0.0.1:5555）")
        val cli = cli ?: throw IllegalStateException("AdbService 尚未初始化")
        if (cli.stateOf(root) != "device") {
            rootSerial = null
            throw IllegalStateException("根传输 $root 已掉线")
        }
        return root
    }

    /**
     * `adb connect <endpoint>` until the server reports `device`. Callers hold [gate].
     *
     * adbd has just been restarted when this is used (chain step 6), so the first rounds
     * legitimately fail while it is still coming up.
     */
    private fun connectEndpoint(endpoint: String, rounds: Int, onLog: (String) -> Unit): Boolean {
        val cli = cli() ?: return false
        repeat(rounds.coerceAtLeast(1)) { index ->
            val round = index + 1
            val result = cli.connect(endpoint)
            if (cli.stateOf(endpoint) == "device") {
                rootSerial = endpoint
                onLog("[*] 根 adbd 已连上 $endpoint（第 $round/$rounds 次）")
                return true
            }
            onLog(
                "[!] connect $endpoint 第 $round/$rounds 次未就绪：" +
                    result.output.trim().ifBlank { "exit=${result.exitCode}" },
            )
            if (round < rounds) Thread.sleep(CONNECT_ROUND_GAP_MS)
        }
        onLog("[!] 无法连接 $endpoint：adbd 是否已监听（ss -lnt）？")
        return false
    }

    /**
     * The transport to run commands on: the root adbd once the chain opened the gate, else
     * the held wireless one, else a freshly connected advertised endpoint. Callers hold [gate].
     */
    private fun transport(onLog: (String) -> Unit): String {
        val cli = cli ?: throw IllegalStateException("AdbService 尚未初始化")
        if (!cli.available) throw IllegalStateException("内置 adb 缺失")
        /* Restarting adbd (chain step 5/6) killed the wireless transport, and reconnecting it
         * would kick the root session the remaining steps run on -- so the root serial wins
         * from the moment it exists. */
        val root = rootSerial
        if (root != null) {
            if (cli.stateOf(root) == "device") return root
            onLog("[*] 根传输 $root 已掉线")
            rootSerial = null
        }
        val active = serial
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
     * The adb server reconnects on its own, so this mostly has to notice and log the
     * transitions -- and, once a transport has worked in this process, reconnect when the
     * server gave up. Before the first successful connection it does nothing, so an app whose
     * user has not paired yet does not fill the log.
     *
     * Once the chain has the root adbd ([rootSerial]), that transport is the one kept alive:
     * the wireless one died with the adbd restart, and reconnecting it would kick the root
     * session the remaining chain steps run on.
     */
    private suspend fun keepAliveTick() = gate.withLock {
        val cli = cli ?: return@withLock
        val root = rootSerial
        if (root != null) {
            if (cli.stateOf(root) == "device") return@withLock
            logger("[*] 保活：根传输 $root 掉线，重连")
            rootSerial = null
            if (connectEndpoint(root, 3, logger)) {
                logger("[*] 保活：根传输已恢复")
            } else {
                logger("[!] 保活：根传输仍不可用（adbd 是否还在监听 ${ChainSpec.ADB_PORT}？）")
            }
            return@withLock
        }
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

}
