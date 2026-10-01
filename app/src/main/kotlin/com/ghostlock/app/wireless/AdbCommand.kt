package com.ghostlock.app.wireless

import android.content.Context
import com.ghostlock.app.chain.ChainSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * `adb_command` -- the only API the app uses to talk to adbd.
 *
 * It is deliberately thin: the connection is owned and kept alive by [AdbService], and this
 * object just submits commands to it. Call sites therefore read as one line --
 * `AdbCommand.exec(command)` or `AdbCommand.exec(command, retries)`.
 *
 * The optional second parameter is the retry count for **channel** failures -- a session
 * that could not be established, or a stream that died before reporting an exit code. It
 * never makes a command run twice: commands listed in `ChainSpec.NON_IDEMPOTENT` are
 * executed exactly once, whatever the caller passes (see [AdbService]).
 *
 * Usage: [attach] once from the application (it also starts the keep-alive loop).
 */
object AdbCommand {
    /** Channel-failure retries used when a caller does not pass its own count. */
    const val DEFAULT_RETRIES = 5

    const val DEFAULT_TIMEOUT_MS = 30_000L

    /** The self-check: `id` for the identity, `/proc/self/status` for `Seccomp`. */
    const val SELF_CHECK_COMMAND = "id; cat /proc/self/status"
    const val SELF_CHECK_TIMEOUT_MS = 15_000L

    /** Bind the application context once and start keeping the channel alive. */
    fun attach(context: Context) = AdbService.attach(context)

    /** Where log lines go when a caller does not pass its own sink. */
    fun setLogger(sink: (String) -> Unit) = AdbService.setLogger(sink)

    /** Notified whenever the held channel becomes usable or stops being usable. */
    fun setLivenessListener(sink: ((Boolean) -> Unit)?) = AdbService.setLivenessListener(sink)

    /** Run one command on the held channel, (re)establishing it if necessary. */
    suspend fun exec(
        command: String,
        retries: Int = DEFAULT_RETRIES,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS,
        onLog: ((String) -> Unit)? = null,
    ): AdbService.Result = withContext(Dispatchers.IO) {
        /* The CLI and the platform resolver block; the chain calls this from the main
         * dispatcher, so the blocking belongs here and not on the caller's thread. */
        AdbService.exec(
            command = command,
            timeoutMs = timeoutMs,
            rounds = retries,
            onLog = onLog ?: AdbService.defaultLogger(),
        )
    }

    /** Make sure the channel exists and answers a round trip. */
    suspend fun ensure(retries: Int = DEFAULT_RETRIES, onLog: ((String) -> Unit)? = null): Boolean =
        withContext(Dispatchers.IO) {
            AdbService.ensure(rounds = retries, onLog = onLog ?: AdbService.defaultLogger())
        }

    /**
     * Send a local file to the device (`adb push`).
     *
     * The device-side `cp` is not an option: the app's own files are unreadable by uid 2000
     * (checked on the PJA110: `/data/app/<pkg>/lib` is not listable by shell).
     */
    suspend fun push(
        localPath: String,
        remotePath: String,
        onLog: ((String) -> Unit)? = null,
    ): Boolean = withContext(Dispatchers.IO) {
        AdbService.push(localPath, remotePath, onLog ?: AdbService.defaultLogger())
    }

    /**
     * Connect to the local root adbd -- chain step 7, `adb connect 127.0.0.1:5555`.
     *
     * From here on the service routes commands to that transport; the wireless one died with
     * the adbd restart of step 6. `adb connect` legitimately fails for the first rounds while
     * adbd is still coming back up, hence [rounds].
     */
    suspend fun connectRoot(
        endpoint: String,
        rounds: Int,
        onLog: ((String) -> Unit)? = null,
    ): Boolean = withContext(Dispatchers.IO) {
        AdbService.connectRoot(endpoint, rounds, onLog ?: AdbService.defaultLogger())
    }

    /** Run one command on the root adbd (steps 7-9). */
    suspend fun execOnRoot(
        command: String,
        retries: Int = DEFAULT_RETRIES,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS,
        onLog: ((String) -> Unit)? = null,
    ): AdbService.Result = withContext(Dispatchers.IO) {
        /* An explicit serial, never the "whatever is connected" path: after step 6 the
         * wireless transport is dead, and falling back to it would reconnect the very
         * session the root adbd replaced. */
        AdbService.execOn(
            serial = ChainSpec.ADB_ENDPOINT,
            command = command,
            timeoutMs = timeoutMs,
            rounds = retries,
            onLog = onLog ?: AdbService.defaultLogger(),
        )
    }
}
