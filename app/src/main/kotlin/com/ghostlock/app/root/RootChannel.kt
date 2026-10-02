package com.ghostlock.app.root

/**
 * The chain's uid-0 command plane: one short shell command per call, run **in the isolated
 * root process** and returned as text.
 *
 * ## Why this is a binder and not a socket
 *
 * It used to be an AF_UNIX socket plus a token file under a shared directory. That needs a
 * filesystem path both sides can reach, and on some devices it simply does not (a parent
 * directory that does not exist yet, an SELinux label the isolated domain may not touch, a token
 * the other side cannot read). The app *already* holds a binder to that service -- that is how
 * the service is started at all -- so the commands ride the binder instead: no path, no token,
 * no directory to prepare, and one less thing that behaves differently per device.
 *
 * What is unchanged is what matters: the command runs as the isolated process's uid 0 with the
 * capabilities that process has (`CapEff=0x1c0`), i.e. exactly the identity the chain's uid-0
 * steps used to get over the socket. Each call is one-shot (`sh -c <cmd>`), which is all the
 * chain ever needed -- it runs `setprop`, `runcon`, `id`, `ss -lnt`, nothing interactive.
 *
 * The service is bound by `IsolatedRootShell`, so this class only resolves the current binder:
 * before that bind it throws, and the chain reports "the channel is not up yet" instead of
 * hanging.
 */
class RootChannel(private val service: () -> IRootShellService?) {

    /** True once the root service is bound and can take commands. */
    fun available(): Boolean = service() != null

    /** Human-readable identity of the command plane, for the preflight log line. */
    fun describe(): String = if (available()) "binder → uid-0 服务" else "binder 尚未绑定"

    /** Run one short command as uid 0; see the class note. */
    fun exec(command: String, timeoutMs: Int = 30_000): String {
        val bound = service() ?: throw IllegalStateException("root 服务还没绑定（通道未就绪）")
        val output = bound.execShell(command, timeoutMs)
        if (output.contains(EXEC_FAILED)) {
            throw IllegalStateException("通道执行失败：${output.trim()}")
        }
        return output
    }

    fun close() = Unit // the binder is owned by IsolatedRootShell, not by us

    companion object {
        /** Marker the native side uses for "the command never ran" (spawn failure / timeout). */
        const val EXEC_FAILED = "__GHOSTLOCK_EXEC_FAILED__"
    }
}
