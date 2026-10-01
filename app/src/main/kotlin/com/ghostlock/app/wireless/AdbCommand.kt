package com.ghostlock.app.wireless

import android.content.Context
import com.ghostlock.app.chain.ChainSpec
import io.github.muntashirakon.adb.AdbConnection
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The single entry point for talking to adbd.
 *
 * Nothing else in the app owns a connection: the channel self-check, the one-click chain
 * and the screen's buttons all call [exec] and let this object decide when to connect,
 * when to reuse and when to drop the session. That is what makes the channel manageable,
 * because the failure modes here are all about *who holds the socket*:
 *
 *  * **one session at a time.** adbd kicks a transport when a second connection appears
 *    under the same client identity (measured on the PJA110: `I/adbd: kicking transport
 *    ... host-25`, then `SSL_read failed`, then `ADB wifi device disconnected`). Two live
 *    connections are therefore not "two channels", they are a race that kills both -- which
 *    is exactly what happened when a completed self-check held a connection and the next
 *    tap tried to build another one;
 *  * **commands are serialised** on a mutex, so a chain step and a UI tap cannot interleave
 *    into that race;
 *  * **dead sessions are closed here.** A kicked transport leaves libadb's connection
 *    "connected" as far as its flags go while its reader never delivers again; detecting
 *    that (hung read, `Stream closed.`, missing exit probe) and closing it means the next
 *    command reconnects instead of reading from a corpse;
 *  * **connecting may be retried, a command may not.** A failed connect proves nothing ran,
 *    so [CONNECT_TRIES] attempts are safe. A failed read may well mean the command DID run
 *    -- repeating `am hang --allow-restart`, `rmmod oplus_security_guard` or
 *    `/data/adb/ksud late-load` is worse than stopping -- so a command is never retried
 *    here. The failure is reported as [ChainSpec.TRANSPORT_FAILURE] and the chain's
 *    `NON_IDEMPOTENT` policy decides what may be repeated.
 */
object AdbCommand {
    /** Total connect attempts before a command reports "the channel is not usable". */
    private const val CONNECT_TRIES = 3
    private const val CONNECT_GAP_MS = 1_500L
    private const val DISCOVERY_TIMEOUT_MS = 20_000L

    /**
     * The channel self-check, as ONE shell call: `id` for the identity and
     * `/proc/self/status` for `Seccomp`. One call means one stream (a kicked transport used
     * to turn a second stream into a 30s hang).
     */
    const val SELF_CHECK_COMMAND = "id; cat /proc/self/status"
    const val SELF_CHECK_TIMEOUT_MS = 15_000L

    /** What the caller gets back: an exit code plus combined output. */
    data class Result(val exitCode: Int, val output: String) {
        val ok: Boolean get() = exitCode == 0
        val transportFailure: Boolean get() = exitCode == ChainSpec.TRANSPORT_FAILURE
    }

    private val mutex = Mutex()

    @Volatile
    private var connection: AdbConnection? = null

    /**
     * Run one command, connecting first if there is no live session.
     *
     * Never throws: an unusable channel is reported as [ChainSpec.TRANSPORT_FAILURE] with
     * the reason pushed to [onLog], because "the command did not run" is a verdict callers
     * must be able to distinguish from "it ran and failed".
     */
    suspend fun exec(
        context: Context,
        command: String,
        timeoutMs: Long = 30_000L,
        onLog: (String) -> Unit = {},
    ): Result = mutex.withLock {
        onLog("$ $command")
        val active = try {
            connect(context, onLog)
        } catch (error: Throwable) {
            onLog("[!] 通道不可用，命令没有运行：${WirelessAdb.describe(error)}")
            return@withLock Result(ChainSpec.TRANSPORT_FAILURE, "")
        }
        try {
            val outcome = WirelessAdb.shellWithExitCode(active, command, timeoutMs)
            outcome.output.lineSequence().filter { it.isNotBlank() }.forEach(onLog)
            if (outcome.exitCode == ChainSpec.TRANSPORT_FAILURE) {
                onLog("[!] 命令没有返回退出码，会话已失效并丢弃")
                closeLocked()
            }
            Result(outcome.exitCode, outcome.output)
        } catch (error: Throwable) {
            onLog("[!] 命令执行失败，可能已经运行：${WirelessAdb.describe(error)}")
            closeLocked()
            Result(ChainSpec.TRANSPORT_FAILURE, "")
        }
    }

    /**
     * Make sure a session exists and prove it with the self-check.
     *
     * Used before the chain starts: pairing is the standing authorization, so "paired but
     * not connected yet" is normal and resolved here rather than failing inside step 1.
     */
    suspend fun ensure(context: Context, onLog: (String) -> Unit = {}): Boolean = mutex.withLock {
        try {
            val active = connect(context, onLog)
            val probe = WirelessAdb.shellWithExitCode(active, SELF_CHECK_COMMAND, SELF_CHECK_TIMEOUT_MS)
            if (probe.exitCode == ChainSpec.TRANSPORT_FAILURE) {
                closeLocked()
                onLog("[!] 通道自检没有返回，会话已丢弃")
                return@withLock false
            }
            val identity = probe.output.lineSequence()
                .firstOrNull { it.trimStart().startsWith("uid=") }
                ?.trim()
                .orEmpty()
            val seccomp = Regex("Seccomp:\\s*(\\d+)").find(probe.output)?.groupValues?.get(1)
            onLog("[*] 通道就绪：$identity Seccomp=${seccomp ?: "?"}")
            true
        } catch (error: Throwable) {
            onLog("[!] 无线调试通道不可用：${WirelessAdb.describe(error)}")
            closeLocked()
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
     * Connecting is the only step that may be retried, and the endpoint is re-discovered on
     * every attempt because the wireless-debugging port changes whenever the user toggles
     * it.
     */
    private suspend fun connect(context: Context, onLog: (String) -> Unit): AdbConnection {
        liveLocked()?.let { active ->
            onLog("[*] 复用已有连接")
            return active
        }
        var last: Throwable? = null
        for (attempt in 1..CONNECT_TRIES) {
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
                onLog("[*] 连接端点 $endpoint 第$attempt/$CONNECT_TRIES 次")
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
            if (attempt < CONNECT_TRIES) {
                onLog("[*] 连接失败 第$attempt/$CONNECT_TRIES 次：${WirelessAdb.describe(last)}")
                delay(CONNECT_GAP_MS)
            }
        }
        throw IllegalStateException(
            "adb 连接失败 $CONNECT_TRIES 次：${WirelessAdb.describe(last)}",
            last,
        )
    }

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
