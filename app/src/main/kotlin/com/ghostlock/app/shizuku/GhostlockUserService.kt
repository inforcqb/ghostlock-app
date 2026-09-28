package com.ghostlock.app.shizuku

import android.content.Context
import android.os.Process
import androidx.annotation.Keep
import com.ghostlock.app.BuildConfig
import com.ghostlock.app.chain.ChainSpec
import java.io.File
import java.io.RandomAccessFile
import java.util.concurrent.atomic.AtomicBoolean

@Keep
class GhostlockUserService(private val context: Context) : IGhostlockUserService.Stub() {
    private val running = AtomicBoolean(false)

    override fun runExploit(
        primaryCpu: Int,
        consumerCpu: Int,
        safeMode: Boolean,
        profileBlob: ByteArray,
        debugDir: String?,
        callback: IGhostlockCallback,
    ) {
        if (!running.compareAndSet(false, true)) {
            callback.onLog("error: another GhostLock process is already running")
            callback.onComplete(1)
            return
        }
        Thread({
            val exitCode = runCatching {
                require(Process.myUid() == Process.SHELL_UID) {
                    "Shizuku UserService uid=${Process.myUid()}, expected ${Process.SHELL_UID}"
                }
                val status = File("/proc/self/status").readText()
                require(Regex("(?m)^Seccomp:\\s*0$").containsMatchIn(status)) {
                    "Shizuku UserService is still seccomp-filtered"
                }
                val release = System.getProperty("os.version", "").orEmpty()
                require(profileBlob.size >= 12) { "profile blob is too short" }
                // PROFILE-SUGGEST-01: recommend_shizuku is a suggestion; the
                // blob's header carries it, and the app already chose the
                // Shizuku path, so it is logged, never a gate.
                if (profileBlob[8].toInt() != 1) {
                    callback.onLog("[*] kernel does not require Shizuku; running on user request")
                }

                val binary = File(context.applicationInfo.nativeLibraryDir, "libghostlock.so")
                require(binary.isFile) { "missing GhostLock binary: ${binary.absolutePath}" }

                val workDir = File("/data/local/tmp/ghostlock-app").apply {
                    require(isDirectory || mkdirs()) { "cannot create $absolutePath" }
                }
                callback.onLog("Shizuku ready: uid=${Process.myUid()} Seccomp=0")
                callback.onLog("kernel: $release")
                val nativeLog = File(workDir, ".ghostlock_native.log")
                // U01-S14: per-run KernelSU log so a previous run's markers can
                // never satisfy the handoff probe; the native process receives
                // the resolved path via GHOSTLOCK_KSU_LOG.
                val ksuLog = File(workDir, "ghostlock-ksu-${System.currentTimeMillis()}.log")
                val activeProfile = File(workDir, "active-profile.bin").apply {
                    writeBytes(profileBlob)
                    setReadable(false, false)
                    setWritable(false, false)
                    setReadable(true, true)
                    setWritable(true, true)
                }
                ProcessBuilder(
                    binary.absolutePath, "--profile", activeProfile.absolutePath,
                )
                    .directory(workDir)
                    .redirectErrorStream(true)
                    .redirectOutput(nativeLog)
                    .apply {
                        environment()["GHOSTLOCK_HOME"] = workDir.absolutePath
                        environment()["TMPDIR"] = workDir.absolutePath
                        environment()["HOME"] = workDir.absolutePath
                        environment()["GHOSTLOCK_KSU_LOG"] = ksuLog.absolutePath
                        if (BuildConfig.DEBUG) environment()["GHOSTLOCK_VERBOSE_DEBUG"] = "1"
                        if (!debugDir.isNullOrEmpty()) environment()["GHOSTLOCK_DEBUG_DIR"] = debugDir
                        environment()["GHOSTLOCK_CORE"] = primaryCpu.toString()
                        environment()["GHOSTLOCK_CONSUMER_CORE"] = consumerCpu.toString()
                        if (safeMode) environment()["GHOSTLOCK_DISABLE_MODULES"] = "1"
                    }
                    .start()
                    .let { process ->
                        // The native process writes its log to a file and this
                        // tailer forwards lines asynchronously. Reading a pipe
                        // here applied backpressure inside the PI race window
                        // (every line also costs a binder round trip), which
                        // stalled the route and ended in a kernel panic.
                        val tailer = Thread({
                            relayLog(nativeLog, callback)
                        }, "ghostlock-shizuku-tailer").apply {
                            isDaemon = true
                            start()
                        }
                        val exitCode = process.waitFor()
                        Thread.sleep(200)
                        tailer.interrupt()
                        tailer.join(1000)
                        exitCode
                    }
            }.getOrElse { error ->
                runCatching { callback.onLog("error: ${error.message}") }
                1
            }
            running.set(false)
            runCatching { callback.onComplete(exitCode) }
        }, "ghostlock-shizuku-runner").start()
    }

    /**
     * W1 only -- the SELinux flip, i.e. exactly what `tools/device/w1.sh` does: the same ELF,
     * the same environment knobs (`GHOSTLOCK_W1_ONLY` + `GHOSTLOCK_PARK_AFTER_W1`), started from
     * this shell-uid (uid 2000, `Seccomp: 0`) context.
     *
     * `GHOSTLOCK_PARK_AFTER_W1` is not optional: the process must stay alive afterwards because
     * the kernel's exit-time PI/futex cleanup walks the forged state. The chain therefore leaves
     * the park in place (the verified chain does no cleanup; a reboot removes it).
     */
    override fun runW1Only(
        profileBlob: ByteArray,
        debugDir: String?,
        callback: IGhostlockCallback,
    ) {
        if (!running.compareAndSet(false, true)) {
            callback.onLog("error: another GhostLock process is already running")
            callback.onComplete(1)
            return
        }
        Thread({
            val exitCode = runCatching {
                require(Process.myUid() == Process.SHELL_UID) {
                    "Shizuku UserService uid=${Process.myUid()}, expected ${Process.SHELL_UID}"
                }
                val status = File("/proc/self/status").readText()
                require(Regex("(?m)^Seccomp:\\s*0$").containsMatchIn(status)) {
                    "Shizuku UserService is still seccomp-filtered"
                }
                require(profileBlob.size >= 12) { "profile blob is too short" }

                val binary = File(context.applicationInfo.nativeLibraryDir, "libghostlock.so")
                require(binary.isFile) { "missing GhostLock binary: ${binary.absolutePath}" }
                val workDir = File("/data/local/tmp/ghostlock-app").apply {
                    require(isDirectory || mkdirs()) { "cannot create $absolutePath" }
                }
                callback.onLog("Shizuku ready: uid=${Process.myUid()} Seccomp=0 (W1 only)")

                val nativeLog = File(workDir, ".ghostlock_w1.log")
                val activeProfile = File(workDir, "active-profile.bin").apply {
                    writeBytes(profileBlob)
                    setReadable(false, false)
                    setWritable(false, false)
                    setReadable(true, true)
                    setWritable(true, true)
                }
                ProcessBuilder(binary.absolutePath, "--profile", activeProfile.absolutePath)
                    .directory(workDir)
                    .redirectErrorStream(true)
                    .redirectOutput(nativeLog)
                    .apply {
                        environment()["GHOSTLOCK_HOME"] = workDir.absolutePath
                        environment()["TMPDIR"] = workDir.absolutePath
                        environment()["HOME"] = workDir.absolutePath
                        environment()["GHOSTLOCK_W1_ONLY"] = "1"
                        environment()["GHOSTLOCK_PARK_AFTER_W1"] = "1"
                        if (BuildConfig.DEBUG) environment()["GHOSTLOCK_VERBOSE_DEBUG"] = "1"
                        if (!debugDir.isNullOrEmpty()) environment()["GHOSTLOCK_DEBUG_DIR"] = debugDir
                    }
                    .start()
                    .let { process ->
                        val tailer = Thread({
                            relayLog(nativeLog, callback)
                        }, "ghostlock-shizuku-w1-tailer").apply {
                            isDaemon = true
                            start()
                        }
                        /* W1 does NOT exit when it succeeds: it parks on purpose
                         * ("parking after W1 ... do NOT exit/kill this process"),
                         * because the kernel walks the forged PI state if the
                         * process goes away.  Waiting for exit therefore blocks the
                         * whole chain forever -- watch the log for the park marker
                         * instead, and treat an early exit as the failure case.
                         * Nothing is killed here either way: killing the park wedges
                         * the machine (a reboot is the clean way out). */
                        val deadline = System.currentTimeMillis() + W1_PARK_TIMEOUT_MS
                        var landed = false
                        var scanned = 0L
                        var carry = ""
                        var parkedPid: String? = null
                        while (System.currentTimeMillis() < deadline) {
                            /* Read only what was appended since the previous poll.
                             * This loop runs while W1 races on two pinned cores, and
                             * re-reading plus re-decoding the whole log four times a
                             * second is avoidable work on exactly those cores. */
                            val seen = runCatching {
                                if (!nativeLog.isFile) return@runCatching false
                                RandomAccessFile(nativeLog, "r").use { raf ->
                                    val length = raf.length()
                                    if (length <= scanned) return@use false
                                    raf.seek(scanned)
                                    val want = (length - scanned)
                                        .coerceAtMost(MAX_LOG_CHUNK.toLong()).toInt()
                                    val bytes = ByteArray(want)
                                    val read = raf.read(bytes)
                                    if (read <= 0) return@use false
                                    scanned += read
                                    /* Keep a marker-sized tail so a marker split
                                     * across two reads is still recognised. */
                                    val chunk = carry + String(bytes, 0, read)
                                    carry = chunk.takeLast(PARK_MARKER.length - 1)
                                    /* The engine prints its own pid on the marker
                                     * line; Process.pid() is not usable here. */
                                    Regex("pid=(\\d+)").find(chunk)?.let {
                                        parkedPid = it.groupValues[1]
                                    }
                                    chunk.contains(PARK_MARKER)
                                }
                            }.getOrDefault(false)
                            if (seen) {
                                landed = true
                                break
                            }
                            if (!process.isAlive) break
                            Thread.sleep(500)
                        }
                        if (landed) {
                            callback.onLog(
                                "W1: landed and parked (pid=${parkedPid ?: "unknown"}); " +
                                    "chain continues, do NOT kill that process",
                            )
                            0
                        } else {
                            val detail = if (process.isAlive) {
                                "timed out after ${W1_PARK_TIMEOUT_MS / 1000}s without the park marker; " +
                                    "leaving the process alone (killing it wedges the kernel)"
                            } else {
                                "the engine exited before parking (exit=${runCatching { process.exitValue() }.getOrNull()})"
                            }
                            callback.onLog("W1: $detail")
                            1
                        }
                    }
            }.getOrElse { error ->
                runCatching { callback.onLog("error: ${error.message}") }
                1
            }
            running.set(false)
            runCatching { callback.onComplete(exitCode) }
        }, "ghostlock-shizuku-w1").start()
    }

    /**
     * Run one shell command as the shell user (uid 2000) and relay its output.
     *
     * The root chain needs this for the steps that must not run as the app: `am hang
     * --allow-restart`, launching the root service, and the state checks between steps. Reads
     * the child's combined output line by line; only short commands are expected here (the
     * pipe-backpressure warning in [runExploit] is about the exploit process inside the PI race
     * window, not about these).
     */
    override fun execShell(command: String, callback: IGhostlockCallback) {
        Thread({
            val exitCode = runCatching {
                callback.onLog("\$ $command")
                val process = ProcessBuilder("/system/bin/sh", "-c", command)
                    .redirectErrorStream(true)
                    .start()
                process.inputStream.bufferedReader().forEachLine { line ->
                    runCatching { callback.onLog(line) }
                }
                process.waitFor()
            }.getOrElse { error ->
                runCatching {
                    callback.onLog("error: ${error::class.simpleName}: ${error.message}")
                }
                /* Same sentinel as the client side: "the command never ran", which the
                 * chain must not read as an empty result. */
                ChainSpec.TRANSPORT_FAILURE
            }
            runCatching { callback.onComplete(exitCode) }
        }, "ghostlock-shizuku-shell").start()
    }

    /** Forward complete native log lines without ever blocking the native
     * process; the file is the transport, binder is only the display path. */
    private fun relayLog(logFile: File, callback: IGhostlockCallback) {
        var offset = 0L
        val pending = StringBuilder()
        while (!Thread.currentThread().isInterrupted) {
            try {
                if (logFile.isFile) {
                    RandomAccessFile(logFile, "r").use { handle ->
                        if (offset > handle.length()) {
                            offset = 0
                            pending.clear()
                        }
                        handle.seek(offset)
                        while (true) {
                            val byte = handle.read()
                            if (byte == -1) break
                            if (byte == '\n'.code) {
                                val line = pending.toString()
                                pending.clear()
                                offset = handle.filePointer
                                if (line.isNotEmpty()) {
                                    runCatching { callback.onLog(line) }
                                }
                            } else {
                                pending.append(byte.toChar())
                            }
                        }
                    }
                }
                Thread.sleep(RELAY_POLL_MS)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            } catch (_: Exception) {
                try {
                    Thread.sleep(200)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return
                }
            }
        }
    }

    override fun destroy() {
        if (!running.get()) kotlin.system.exitProcess(0)
    }

    private companion object {
        /**
         * The engine does NOT exit after a successful W1: it parks on purpose
         * ("parking after W1: forged PI state kept alive ... do NOT exit/kill this
         * process"), because the kernel walks the forged PI state when the process
         * goes away. This is the marker line it prints right before parking, i.e.
         * the "the store landed" signal the chain waits for.
         */
        const val PARK_MARKER = "parking after W1"

        /** How long to wait for that marker before declaring the attempt failed. */
        const val W1_PARK_TIMEOUT_MS = 300_000L

        /**
         * Log tail polling period.
         *
         * W1 is a timing race on two pinned cores, and the relay runs while it is in
         * flight: every period it reads the file and then pushes each new line to the
         * app over Binder. Only the KernelSnitch collision search quality decides
         * whether the attempt lands, and that quality collapses when the cores are
         * busy (measured: 25% collision coverage preceded a silent death in the write
         * path). 100 ms was needlessly eager, so the UI updates four times a second
         * instead -- still live, far less interference.
         */
        const val RELAY_POLL_MS = 400L

        /** Largest slice read per poll while watching for the park marker. */
        const val MAX_LOG_CHUNK = 64 * 1024
    }
}
