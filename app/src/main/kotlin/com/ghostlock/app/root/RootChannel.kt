package com.ghostlock.app.root

import android.net.LocalSocket
import android.net.LocalSocketAddress
import java.io.File
import java.net.SocketTimeoutException

/**
 * Client for the uid-0 shell channel that the root service leaves behind.
 *
 * ## Wire protocol (from the ported `magica.cpp` `rsh_*` / `start_shell_server()`)
 *
 * * socket `$deviceDir/rshell.sock`, `AF_UNIX`/`SOCK_STREAM`, mode 0666
 * * token `$deviceDir/rshell.token`, 32 hex chars + `\n`, mode 0644
 * * handshake: the client writes the token followed by `\n`; a mismatch answers `bad token\n`
 * * after a successful handshake the server forks a **pty-backed `sh -i`** and pumps raw bytes
 *   between the socket and the pty master, so the session is an interactive shell, not a
 *   length-framed request/response protocol.
 *
 * ## How one-shot commands work
 *
 * There is no "execute and exit" request: the host-side wrapper (`rshell '<cmd>'`) simply feeds
 * the command and then closes its stdout, which makes the pty child exit. This client does the
 * same -- write the command, `shutdownOutput()`, then read until EOF. That is why [exec] must
 * only be used for short commands (all channel steps of the root chain are `setprop`/`runcon`
 * calls); a long-running command would be cut off when the pty gets EOF.
 *
 * The directory is shared on purpose: the server runs in an isolated process (a different uid
 * with no access to the app's private data dir) while the adb shell (uid 2000) must be able to
 * read the token -- `/data/local/tmp` plus 0644/0666 is what makes the design work.
 */
class RootChannel(private val deviceDir: String = DEFAULT_DEVICE_DIR) {

    val socketPath: String get() = File(deviceDir, "rshell.sock").absolutePath
    val tokenPath: String get() = File(deviceDir, "rshell.token").absolutePath

    /** True when both the socket and the token are visible from this process. */
    fun available(): Boolean = File(socketPath).exists() && File(tokenPath).exists()

    /** Read the token; it is world-readable by design (see the class note). */
    private fun token(): String {
        val file = File(tokenPath)
        if (!file.isFile) throw IllegalStateException("channel token missing: $tokenPath")
        return file.readText().trim()
    }

    /**
     * Verification step: connect, hand over the token, run `id` and require `uid=0`.
     * Called by the chain right after the root service reports that its channel is up.
     */
    fun open() {
        val identity = exec("id")
        if (!identity.contains("uid=0")) {
            throw IllegalStateException("channel is not uid 0: ${identity.trim()}")
        }
    }

    /**
     * Run one short command in the channel as uid 0 and return its (combined) output,
     * with the pty's echo of the command itself removed.
     */
    fun exec(command: String, timeoutMs: Int = 30_000): String {
        val raw = StringBuilder()
        val socket = LocalSocket()
        try {
            socket.connect(LocalSocketAddress(socketPath, LocalSocketAddress.Namespace.FILESYSTEM))
            socket.soTimeout = timeoutMs
            val out = socket.outputStream
            out.write((token() + "\n").toByteArray(Charsets.UTF_8))
            out.write((command + "\n").toByteArray(Charsets.UTF_8))
            out.flush()
            // Half-close so the pty child sees EOF and exits (the one-shot contract).
            runCatching { socket.shutdownOutput() }
            try {
                socket.inputStream.bufferedReader(Charsets.UTF_8).forEachLine { line ->
                    raw.appendLine(line)
                }
            } catch (_: SocketTimeoutException) {
                // Partial output is still useful; the caller decides from its content.
            } catch (_: Exception) {
                // EOF / reset after the child exited: same treatment.
            }
        } finally {
            runCatching { socket.close() }
        }
        return stripEcho(command, raw.toString())
    }

    fun close() = Unit // each exec owns its own connection

    private fun stripEcho(command: String, raw: String): String {
        val commandLine = command.trim()
        return raw.lineSequence()
            .filterNot { it.trim() == commandLine || it == "bad token" }
            .joinToString("\n")
            .trim()
    }

    companion object {
        /** The shared directory used by the device-side tooling (`w1.sh`, `rshell`, cleaners). */
        const val DEFAULT_DEVICE_DIR = "/data/local/tmp/gl-w1"
    }
}
