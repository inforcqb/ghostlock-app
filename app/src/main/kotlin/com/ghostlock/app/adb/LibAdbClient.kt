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

    fun connect(connectTimeoutMs: Int = 30_000) {
        val key = AdbKey.load(context.filesDir)
        val conn = AdbConnection.Builder(host, port)
            .setDeviceName("ghostlock")
            .setPrivateKey(key.privateKey)
            .setCertificate(key.certificate)
            .connect(connectTimeoutMs.toLong(), TimeUnit.MILLISECONDS, true)
        connection = conn
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