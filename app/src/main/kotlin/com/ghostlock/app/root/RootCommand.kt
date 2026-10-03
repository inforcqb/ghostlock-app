package com.ghostlock.app.root

import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets

/**
 * Client for the uid-0 command server in `app/src/main/jni/gl_server.cpp`.
 *
 * The server is the single owner of the privileged link (it lives inside the
 * Magica isolated uid-0 process, or -- when it could not bind there -- in a child
 * re-exec'd as `runcon u:r:system_server:s0`).  Everything else, including this
 * file, only submits commands:
 *
 *     RootCommand.attach(context.filesDir)
 *     RootCommand.exec("rmmod oplus_security_guard").ok
 *     RootCommand.exec("setprop service.adb.tcp.port 5555", domain = "u:r:adbd:s0")
 *
 * Wire format (see gl_server.cpp): banner `GHOSTLOCK/1`, the token line, `OK`,
 * then one command line per request; output is streamed verbatim and terminated
 * by `__GL_EXIT__ <rc>`; a spawn failure comes back as
 * `__GHOSTLOCK_EXEC_FAILED__: <reason>` instead of the terminator.
 *
 * `port` is read from `<filesDir>/port` (the run writes the real one there, in
 * case 5038 was taken), `token` from `<filesDir>/token`.  There is no default token:
 * an empty one means the server refuses to serve at all (loopback is reachable by
 * every app on the device), so an empty read is treated as "not staged yet" and
 * retried -- see [exec].
 */
object RootCommand {

    const val DEFAULT_PORT = 5038
    private const val BANNER = "GHOSTLOCK/1"
    private const val TAG_EXIT = "__GL_EXIT__ "
    private const val TAG_FAIL = "__GHOSTLOCK_EXEC_FAILED__: "

    /**
     * How often [exec] retries a failure that provably happened **before** the command could run,
     * and how long it waits in between.
     *
     * Only unambiguous cases are retried here (connect refused, handshake refused, or the server
     * saying the command never started): after a mid-command I/O error the command may well have
     * executed, and repeating it is the caller's decision, not this client's.
     */
    private const val ATTEMPTS = 3
    private const val RETRY_MS = 1_000L

    data class Result(val exitCode: Int, val output: String, val failed: String?) {
        val ok: Boolean get() = failed == null && exitCode == 0
    }

    @Volatile private var dir: File? = null

    /** Point the facade at the app's private directory that holds port/token. */
    fun attach(filesDir: File) {
        dir = filesDir
    }

    fun port(): Int =
        runCatching { File(dir, "port").readText().trim().toInt() }.getOrDefault(DEFAULT_PORT)

    private fun token(): String =
        runCatching { File(dir, "token").readText().trim() }.getOrDefault("")

    /**
     * Run one command and wait for its terminator.  [domain] runs it through
     * `/system/bin/runcon <domain> sh -c <command>`, which is what commands that
     * need a domain of their own (property writes) require.
     *
     * Failures that cannot have executed anything are retried [ATTEMPTS] times: a plane that is
     * still coming up, a token file that has not landed yet, or a server that reports the
     * command never started.  A mid-command I/O error is returned as-is (the command may have
     * run), and the chain decides whether to repeat it.
     */
    fun exec(
        command: String,
        timeoutMs: Int = 30_000,
        domain: String? = null,
        connectMs: Int = 3_000,
    ): Result {
        var last: Result? = null
        for (attempt in 1..ATTEMPTS) {
            val result = runOnce(command, timeoutMs, domain, connectMs)
            if (!retryable(result.failed) || attempt == ATTEMPTS) return result
            last = result
            Thread.sleep(RETRY_MS)
        }
        return last ?: Result(-1, "", "no attempt was made")
    }

    /**
     * Which failures are known to have happened before the command could run.
     *
     * Deliberately narrow: `IOException`/`SocketException` are NOT here, because a dropped
     * connection may mean the command executed and its output was lost.
     */
    private fun retryable(failed: String?): Boolean = when {
        failed == null -> false
        failed.startsWith(TAG_FAIL) -> true                       // the server says it never started
        failed.startsWith("handshake:") -> true                    // refused before any command
        failed.startsWith("ConnectException") -> true
        failed.startsWith("NoRouteToHostException") -> true
        failed == "no banner" -> true
        else -> false
    }

    private fun runOnce(
        command: String,
        timeoutMs: Int,
        domain: String?,
        connectMs: Int,
    ): Result {
        val socket = Socket()
        return try {
            socket.connect(InetSocketAddress("127.0.0.1", port()), connectMs)
            socket.soTimeout = timeoutMs + 5_000
            val out = socket.getOutputStream()
            val input = socket.getInputStream()

            readLine(input) ?: return Result(-1, "", "no banner")
            send(out, token())
            val ack = readLine(input)
            if (ack != "OK") return Result(-1, "", "handshake: ${ack ?: "closed"}")

            if (!domain.isNullOrBlank()) {
                send(out, "@domain $domain")
                readLine(input)
            }
            send(out, "@t $timeoutMs")
            readLine(input)

            send(out, command)
            val (body, tag) = readUntilTerminator(input)
            val rest = tag.removePrefix(TAG_EXIT)
            val rc = rest.trim().toIntOrNull() ?: -1
            return Result(rc, body, null)
        } catch (error: Exception) {
            Result(-1, "", "${error::class.simpleName}: ${error.message}")
        } finally {
            runCatching { socket.close() }
        }
    }

    private fun send(out: java.io.OutputStream, line: String) {
        out.write((line + "\n").toByteArray(StandardCharsets.UTF_8))
        out.flush()
    }

    /** Read one CRLF/LF terminated line; null on EOF. */
    private fun readLine(input: java.io.InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val c = input.read()
            if (c < 0) return if (sb.isEmpty()) null else sb.toString()
            if (c == '\n'.code) return sb.toString().trimEnd('\r')
            if (c == '\r'.code) continue
            sb.append(c.toChar())
        }
    }

    /**
     * Read until either terminator appears anywhere in the stream.  The server
     * writes the terminator straight after the command's output, which need not
     * end in a newline, so this cannot be line based.
     */
    private fun readUntilTerminator(input: java.io.InputStream): Pair<String, String> {
        val buf = ByteArray(4096)
        val sb = StringBuilder()
        while (true) {
            val n = input.read(buf)
            if (n < 0) return sb.toString() to ""
            sb.append(String(buf, 0, n, StandardCharsets.UTF_8))
            val text = sb.toString()
            val exit = text.indexOf(TAG_EXIT)
            val fail = text.indexOf(TAG_FAIL)
            if (fail >= 0 && (exit < 0 || fail < exit)) {
                return text.substring(0, fail) to (TAG_FAIL + text.substring(fail + TAG_FAIL.length).trim())
            }
            if (exit >= 0) {
                val end = text.indexOf('\n', exit)
                val tag = if (end < 0) text.substring(exit) else text.substring(exit, end)
                return text.substring(0, exit) to tag
            }
        }
    }

    /** Cheap liveness check: the banner alone proves something is listening. */
    fun ping(): Boolean = runCatching {
        Socket().use { s ->
            s.connect(InetSocketAddress("127.0.0.1", port()), 1_000)
            s.soTimeout = 1_000
            readLine(s.getInputStream())?.startsWith(BANNER) == true
        }
    }.getOrDefault(false)
}
