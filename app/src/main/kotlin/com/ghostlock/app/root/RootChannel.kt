package com.ghostlock.app.root

/**
 * The chain's uid-0 command plane: four **intents**, executed by the isolated root service and
 * answered over the binder the app already holds.
 *
 * ## Why this is a binder and not a socket
 *
 * It used to be an AF_UNIX socket plus a token file under a shared directory. That needs a
 * filesystem path both sides can reach, and on some devices it simply does not (a parent
 * directory that does not exist yet, an SELinux label the isolated domain may not touch, a token
 * the other side cannot read). The app *already* holds a binder to that service -- that is how
 * the service is started at all -- so the actions ride the binder instead: no path, no token,
 * no directory to prepare, and one less thing that behaves differently per device.
 *
 * ## Why intents and not a command string
 *
 * There is deliberately no `exec(command)` here. What the chain may do to the device is the four
 * things declared in [IRootShellService], and the commands behind them are fixed in the library
 * (`app/src/main/jni/magica.cpp`): a command string on the wire would be both a local privilege
 * surface and a place for the two sides to drift apart.
 *
 * The one that forced the design is the adbd gate: `runcon <domain> setprop ...` **must** run in
 * a child process (property_service authorises against the caller's process context, and an
 * in-process `setcon` from a binder thread is refused outright -- measured 2026-10-02,
 * see `docs/analysis/uid0-command-plane.md`).
 *
 * The service is bound by `IsolatedRootShell`, so this class only resolves the current binder:
 * before that bind it throws, and the chain reports "the channel is not up yet" instead of
 * hanging.
 */
class RootChannel(private val service: () -> IRootShellService?) {

    /** True once the root service is bound and can take commands. */
    fun available(): Boolean = service() != null

    /** Human-readable identity of the command plane, for the preflight log line. */
    fun describe(): String =
        if (available()) "binder → uid-0 服务（内联命令）" else "binder 尚未绑定"

    /**
     * `id`: uid 0 and the SELinux context of the service process.
     *
     * This is the chain's identity check. It can only answer if the service is bound, alive and
     * running as uid 0 -- there is no file, socket or child process in between that could be
     * stale.
     */
    fun identity(): String = checked { it.channelIdentity() }

    /** `runcon u:r:adbd:s0 setprop service.adb.tcp.port 5555`: opens the adbd gate. */
    fun openAdbGate(): String = checked { it.channelOpenAdbGate() }

    /** `runcon u:r:usbd:s0 setprop ctl.restart adbd`: init restarts adbd (root, on 5555). */
    fun restartAdbd(): String = checked { it.channelRestartAdbd() }

    /**
     * `ss -lnt`: the listener table, for the chain's poll.
     *
     * Advisory by nature -- this runs in a child of the isolated process, and whether that
     * child's `/proc/net` view is the one adbd listens in is not guaranteed -- which is why the
     * chain logs a negative answer instead of acting on it.
     */
    fun listeners(): String = checked { it.channelListeners() }

    fun close() = Unit // the binder is owned by IsolatedRootShell, not by us

    /** Run one intent and turn the native failure marker into an exception. */
    private fun checked(action: (IRootShellService) -> String): String {
        val bound = service() ?: throw IllegalStateException(NOT_BOUND)
        val output = action(bound)
        if (output.contains(EXEC_FAILED)) {
            throw IllegalStateException("通道执行失败：${output.trim()}")
        }
        return output
    }

    companion object {
        /**
         * Marker the native side uses for "the intent never ran, or the command failed" (a spawn
         * failure, a timeout, a non-zero exit) -- never for "it ran and printed nothing".
         */
        const val EXEC_FAILED = "__GHOSTLOCK_EXEC_FAILED__"

        private const val NOT_BOUND = "root 服务还没绑定（通道未就绪）"
    }
}
