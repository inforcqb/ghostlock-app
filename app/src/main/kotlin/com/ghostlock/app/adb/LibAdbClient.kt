package com.ghostlock.app.adb

import android.content.Context
import io.github.muntashirakon.adb.AdbConnection
import java.util.concurrent.TimeUnit

/**
 * The app's ADB client for the chain, on top of libadb-android.
 *
 * This replaces the hand-written [AdbClient], which spoke enough of the protocol to
 * `connect` but stopped at `adbd asked for AUTH (type=1)` -- it had no answer for the
 * challenge. libadb does the whole thing: `AUTH` token -> `SHA1withRSA` signature with
 * our private key, public-key fallback, and (for pairing, which we do not use) TLS.
 *
 * The key pair comes from [AdbKey] and must already exist; it is generated during
 * preflight, because its public half is what gets pushed to `/data/misc/adb/adb_keys`
 * over the uid-0 channel -- that push is our equivalent of `adb pair`.
 *
 * Same shape as the old client on purpose (`connect` / `exec` / `close`), so the chain
 * keeps its verbatim commands and only changes who runs them.
 */
class LibAdbClient(
    private val context: Context,
    private val host: String = "127.0.0.1",
    private val port: Int = 5555,
) {
    private var connection: AdbConnection? = null

    /**
     * Connect to adbd, retrying a few times.
     *
     * adbd has just been restarted by `runcon u:r:usbd:s0 setprop ctl.restart adbd`, and
     * "ss shows 5555 listening" happens before the daemon actually accepts connections --
     * a single attempt failed here with libadb's "Unable to establish a new connection"
     * even though a PC adb could connect to the same port moments later. Each attempt
     * builds a fresh connection object, because a failed one cannot be reused.
     *
     * setApi(SDK_INT) tells the library that client and adbd live on the same device.
     */
    fun connect(connectTimeoutMs: Int = 30_000, attempts: Int = 6, gapMs: Long = 2_000L) {
        val key = AdbKey.load(context.filesDir)
        var last: Throwable? = null
        for (attempt in 1..attempts) {
            try {
                val conn = AdbConnection.Builder(host, port)
                    .setDeviceName("ghostlock")
                    .setApi(android.os.Build.VERSION.SDK_INT)
                    .setPrivateKey(key.privateKey)
                    .setCertificate(key.certificate)
                    .connect(connectTimeoutMs.toLong(), TimeUnit.MILLISECONDS, false)
                if (conn.isConnected) {
                    connection = conn
                    return
                }
                runCatching { conn.close() }
                last = IllegalStateException("连接建立后未完成握手（第 $attempt/$attempts 次）")
            } catch (error: Throwable) {
                last = error
            }
            if (attempt < attempts) {
                Thread.sleep(gapMs)
            }
        }
        throw IllegalStateException(
            "adb connect $host:$port 连续 $attempts 次失败：${last?.message}",
            last,
        )
    }

    /** Run one command through the `shell:` service and return its combined output. */
    fun exec(command: String, timeoutMs: Int = 60_000): String {
        val conn = connection ?: throw IllegalStateException("adb client is not connected")
        val stream = conn.open("shell:$command")
        stream.use { open ->
            return open.openInputStream().bufferedReader(Charsets.UTF_8).readText()
        }
    }

    fun close() {
        runCatching { connection?.close() }
        connection = null
    }
}