package com.ghostlock.app.wireless

import android.content.Context
import android.os.Build
import android.util.Log
import com.ghostlock.app.adb.AdbKey
import io.github.muntashirakon.adb.AdbConnection
import io.github.muntashirakon.adb.PairingConnectionCtx
import io.github.muntashirakon.adb.android.AdbMdns
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/** A host and port found through mDNS. */
data class AdbEndpoint(val host: String, val port: Int) {
    override fun toString(): String = "$host:$port"
}

/**
 * The raw ADB pieces of the wireless-debugging path, on top of libadb-android.
 *
 * This is the replacement for the uid-0 channel doing `adb pair` by hand: the pairing
 * handshake below registers our public key with adbd the official way, so nothing has to
 * `fork()` into a short-lived uid-1000 process and append a line to
 * `/data/misc/adb/adb_keys` (that route is only used by the old Magica chain).
 *
 * Three steps, each independently observable:
 *   1. [discover] `_adb-tls-pairing._tcp` -> host/port to pair with;
 *   2. [pair]     the SPAKE2 + TLS pairing handshake with the six-digit code;
 *   3. [discover] `_adb-tls-connect._tcp` -> host/port of the normal (TLS) adbd port,
 *      then [connect] with the now-authorized key and [shell] to run a command as uid 2000.
 */
object WirelessAdb {
    const val TAG = "GhostlockWireless"

    /** `_adb-tls-pairing._tcp`: only advertised while the pairing dialog is open. */
    val SERVICE_PAIRING: String = AdbMdns.SERVICE_TYPE_TLS_PAIRING

    /** `_adb-tls-connect._tcp`: advertised while wireless debugging is on. */
    val SERVICE_CONNECT: String = AdbMdns.SERVICE_TYPE_TLS_CONNECT

    /**
     * mDNS discovery of one service type.
     *
     * `AdbMdns` resolves a service and only reports it when the port is in use on one of
     * our own interface addresses -- on the same device that is exactly what we want.
     *
     * @return the endpoint, or null when nothing was found within [timeoutMs].
     */
    fun discover(context: Context, serviceType: String, timeoutMs: Long): AdbEndpoint? {
        val latch = CountDownLatch(1)
        val host = AtomicReference<InetAddress?>(null)
        val port = AtomicInteger(-1)
        val mdns = AdbMdns(context, serviceType) { address, found ->
            if (address != null && found > 0) {
                host.set(address)
                port.set(found)
                latch.countDown()
            }
        }
        mdns.start()
        try {
            if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                Log.w(TAG, "no $serviceType endpoint within ${timeoutMs}ms")
                return null
            }
        } finally {
            runCatching { mdns.stop() }
        }
        val address = host.get() ?: return null
        val resolved = port.get()
        if (resolved <= 0) return null
        val text = address.hostAddress ?: return null
        return AdbEndpoint(text, resolved)
    }

    /**
     * Pair with adbd using the six-digit code from the system's pairing dialog.
     *
     * Success means adbd stored our public key: from here on the private key in [AdbKey]
     * authenticates us, with no `setuid(1000)` write to `/data/misc/adb/adb_keys`.
     *
     * Throws on failure; a wrong code fails inside the handshake ("Exchanging message
     * wasn't successful."), which is why the caller must treat this as user-visible.
     */
    fun pair(context: Context, endpoint: AdbEndpoint, pairingCode: String, timeoutMs: Long = 60_000L) {
        val key = AdbKey.load(context.filesDir)
        val code = pairingCode.trim()
        require(code.isNotEmpty()) { "empty pairing code" }
        withWatchdog(timeoutMs, "pairing $endpoint") {
            PairingConnectionCtx(
                endpoint.host,
                endpoint.port,
                code.toByteArray(Charsets.UTF_8),
                key.privateKey,
                key.certificate,
                AdbKey.NAME,
            ).use { it.start() }
        }
    }

    /**
     * Connect to adbd and finish the AUTH handshake.
     *
     * adbd needs a moment after it starts listening (and after a pairing), so the
     * connection is retried; a failed [AdbConnection] cannot be reused, hence the fresh
     * object per attempt. `setApi(SDK_INT)` says client and daemon are on the same device.
     */
    fun connect(
        context: Context,
        endpoint: AdbEndpoint,
        timeoutMs: Long = 30_000L,
        attempts: Int = 4,
        gapMs: Long = 2_000L,
    ): AdbConnection {
        val key = AdbKey.load(context.filesDir)
        var last: Throwable? = null
        for (attempt in 1..attempts) {
            try {
                val connection = AdbConnection.Builder(endpoint.host, endpoint.port)
                    .setDeviceName("ghostlock")
                    .setApi(Build.VERSION.SDK_INT)
                    .setPrivateKey(key.privateKey)
                    .setCertificate(key.certificate)
                    .connect(timeoutMs, TimeUnit.MILLISECONDS, false)
                if (connection.isConnected) return connection
                runCatching { connection.close() }
                last = IllegalStateException("连接建立后握手未完成（第 $attempt/$attempts 次）")
            } catch (error: Throwable) {
                last = error
            }
            if (attempt < attempts) Thread.sleep(gapMs)
        }
        throw IllegalStateException("adb connect $endpoint 连续 $attempts 次失败：${last?.message}", last)
    }

    /**
     * Run one command through the `shell:` service and return its output.
     *
     * The read runs on a worker thread so a daemon that never closes the stream cannot
     * hang the caller forever; on timeout the stream is closed and an error is thrown.
     */
    fun shell(connection: AdbConnection, command: String, timeoutMs: Long = 30_000L): String =
        withWatchdog(timeoutMs, "adb shell '$command'") {
            connection.open("shell:$command").use { stream ->
                stream.openInputStream().bufferedReader(Charsets.UTF_8).readText()
            }
        }

    fun closeQuietly(connection: AdbConnection?) {
        if (connection == null) return
        runCatching { connection.close() }
    }

    /**
     * Run [block] on a daemon thread and fail after [timeoutMs].
     *
     * libadb's pairing and stream reads have no timeout of their own; without this a dead
     * endpoint would park the chain forever instead of reporting a failure.
     */
    private fun <T> withWatchdog(timeoutMs: Long, what: String, block: () -> T): T {
        val result = AtomicReference<T>()
        val failure = AtomicReference<Throwable>()
        val done = CountDownLatch(1)
        val worker = Thread {
            try {
                result.set(block())
            } catch (error: Throwable) {
                failure.set(error)
            } finally {
                done.countDown()
            }
        }
        worker.isDaemon = true
        worker.name = "ghostlock-wireless"
        worker.start()
        if (!done.await(timeoutMs, TimeUnit.MILLISECONDS)) {
            throw IllegalStateException("$what 超过 ${timeoutMs}ms 未返回")
        }
        failure.get()?.let { throw it }
        @Suppress("UNCHECKED_CAST")
        return result.get() as T
    }
}
