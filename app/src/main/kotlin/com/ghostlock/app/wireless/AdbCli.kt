package com.ghostlock.app.wireless

import android.content.Context
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The bundled `adb` command line, as a process.
 *
 * `libadbcli.so` in the app's `nativeLibraryDir` is the real platform-tools `adb` (see
 * `app/src/main/jniLibs/README.md`), which is the whole point of this layer: adbd's
 * wireless-debugging port accepts **one** session at a time, so the app needs the same thing
 * a PC uses -- a single long-lived adb *server* that owns that session and multiplexes
 * commands over it. Doing that by hand (libadb) meant re-implementing the server, and it kept
 * losing the race against adbd.
 *
 * What the CLI gives us for free:
 *
 *  * `adb pair <ip:port> <code>` -- the official pairing, which also records the device's TLS
 *    certificate in `$HOME/.android/adb_known_hosts` (without that record a later
 *    `adb connect` to the TLS port is refused);
 *  * `adb connect <ip:port>` -- maintains the transport, reconnecting on its own;
 *  * `adb shell <cmd>` -- **returns the command's exit code**, so no marker/echo hack and no
 *    guessing whether a command ran;
 *  * `adb mdns services` -- discovery of `_adb-tls-connect` / `_adb-tls-pairing`.
 *
 * Every process shares one `HOME` (app files dir), so the key pair and the known-hosts record
 * persist across runs and app updates -- the pairing only has to happen once.
 */
class AdbCli(context: Context) {
    /** One finished CLI invocation. */
    data class Result(val exitCode: Int, val stdout: String, val stderr: String) {
        /** stdout and stderr, as the chain's log wants them. */
        val output: String
            get() = listOf(stdout.trim(), stderr.trim()).filter { it.isNotEmpty() }.joinToString("\n")

        /**
         * True when the CLI itself could not reach the device, i.e. the command never ran.
         * That must never be read as "the command ran and failed".
         */
        val transportFailure: Boolean
            get() = exitCode != 0 && TRANSPORT_ERRORS.any { output.contains(it) }
    }

    /** One discovered mDNS service. */
    data class MdnsService(val serviceType: String, val endpoint: String)

    private val appContext = context.applicationContext
    private val binary = File(appContext.applicationInfo.nativeLibraryDir, BINARY_NAME)
    private val home = File(appContext.filesDir, HOME_DIR).apply { mkdirs() }

    val available: Boolean get() = binary.isFile

    /** Run the CLI and collect its output; kills it when [timeoutMs] elapses. */
    fun run(args: List<String>, timeoutMs: Long = DEFAULT_TIMEOUT_MS): Result {
        if (!available) {
            return Result(127, "", "bundled adb is missing at ${binary.absolutePath}")
        }
        val builder = ProcessBuilder(listOf(binary.absolutePath) + args)
            .directory(appContext.filesDir)
        builder.environment().apply {
            /* One HOME for key, known-hosts and the server's own state. */
            put("HOME", home.absolutePath)
            put("TMPDIR", appContext.cacheDir.absolutePath)
            put("PATH", "/system/bin:/system/xbin")
        }
        val process = try {
            builder.start()
        } catch (error: Throwable) {
            return Result(126, "", "cannot run adb: ${error::class.java.simpleName}: ${error.message}")
        }
        val stdout = StringBuilder()
        val stderr = StringBuilder()
        val done = CountDownLatch(2)
        Thread({ copy(process.inputStream, stdout, done) }, "adb-cli-out").apply { isDaemon = true }.start()
        Thread({ copy(process.errorStream, stderr, done) }, "adb-cli-err").apply { isDaemon = true }.start()
        val finished = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
        if (!finished) {
            runCatching { process.destroyForcibly() }
            done.await(1, TimeUnit.SECONDS)
            return Result(-1, stdout.toString(), stderr.toString().ifEmpty { "adb timed out after ${timeoutMs}ms" })
        }
        done.await(2, TimeUnit.SECONDS)
        return Result(process.exitValue(), stdout.toString(), stderr.toString())
    }

    // ---------------------------------------------------------------- operations

    fun startServer(): Result = run(listOf("start-server"), 30_000)

    fun killServer(): Result = run(listOf("kill-server"), 15_000)

    /** The official pairing; also records the device's certificate for later connects. */
    fun pair(endpoint: String, code: String): Result = run(listOf("pair", endpoint, code), 60_000)

    fun connect(endpoint: String): Result = run(listOf("connect", endpoint), 30_000)

    fun disconnect(endpoint: String): Result = run(listOf("disconnect", endpoint), 15_000)

    /** `serial -> state` for every transport the server knows. */
    fun devices(): Map<String, String> = run(listOf("devices"), 15_000).stdout
        .lineSequence()
        .map { it.trim() }
        .filter { it.isNotEmpty() && !it.startsWith("List of devices") && it.contains('\t') }
        .mapNotNull { line ->
            val serial = line.substringBefore('\t').trim()
            val state = line.substringAfter('\t').trim().substringBefore(' ')
            if (serial.isEmpty()) null else serial to state
        }
        .toMap()

    fun stateOf(serial: String): String? = devices()[serial]

    /** Whatever mDNS currently advertises, as `_adb-tls-connect` / `_adb-tls-pairing`. */
    fun mdnsServices(): List<MdnsService> = run(listOf("mdns", "services"), 20_000).stdout
        .lineSequence()
        .map { it.trim() }
        .filter { it.contains("_adb-tls-") }
        .mapNotNull { line ->
            val parts = line.split('\t').map { it.trim() }.filter { it.isNotEmpty() }
            val type = parts.firstOrNull { it.startsWith("_adb-tls-") } ?: return@mapNotNull null
            val endpoint = parts.lastOrNull { it.contains(':') } ?: return@mapNotNull null
            MdnsService(type.substringBefore("._tcp").trim('_', '.'), endpoint)
        }
        .toList()

    /** Run one command on [serial]; the returned exit code is the command's own. */
    fun shell(serial: String, command: String, timeoutMs: Long): Result =
        run(listOf("-s", serial, "shell", command), timeoutMs)

    private fun copy(
        stream: java.io.InputStream,
        sink: StringBuilder,
        done: CountDownLatch,
    ) {
        try {
            stream.bufferedReader().forEachLine { line ->
                synchronized(sink) { sink.append(line).append('\n') }
            }
        } catch (_: Throwable) {
            // The process was killed or the pipe closed: whatever was read is what we have.
        } finally {
            done.countDown()
        }
    }

    companion object {
        const val BINARY_NAME = "libadbcli.so"
        const val HOME_DIR = "adb-home"
        const val DEFAULT_TIMEOUT_MS = 30_000L

        /** Phrases the CLI prints when it could not reach the device at all. */
        private val TRANSPORT_ERRORS = listOf(
            "no devices/emulators found",
            "device offline",
            "device unauthorized",
            "device still authorizing",
            "failed to connect",
            "cannot connect to daemon",
            "error: closed",
            "error: device",
        )
    }
}
