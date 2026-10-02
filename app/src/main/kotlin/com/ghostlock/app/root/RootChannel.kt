package com.ghostlock.app.root

/**
 * The chain's uid-0 command plane: three typed actions, executed **in the isolated root process**
 * and answered over the binder the app already holds.
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
 * ## Why actions and not command strings
 *
 * The command plane was one short shell string per call (`execShell`) after the socket, which
 * looks equivalent and is not: the far side is a capless uid 0 that cannot spawn a child with its
 * own identity (Android drops a spawned child to the app uid -- measured on the PJA110, where the
 * isolated process is uid 0 and its `ProcessBuilder` child printed `uid=90000(u0_i0)`), and a
 * cached process can be frozen mid-command by the freezer. Every step the chain needs is a
 * syscall or one property write, so each of them is an action here -- nothing to spawn, nothing
 * to parse, nothing to lose.
 *
 * Each call is one-shot, which is all the chain ever needed.
 *
 * The service is bound by `IsolatedRootShell`, so this class only resolves the current binder:
 * before that bind it throws, and the chain reports "the channel is not up yet" instead of
 * hanging.
 */
class RootChannel(private val service: () -> IRootShellService?) {

    /** True once the root service is bound and can take actions. */
    fun available(): Boolean = service() != null

    /** Human-readable identity of the command plane, for the preflight log line. */
    fun describe(): String =
        if (available()) "binder → uid-0 服务（原生动作）" else "binder 尚未绑定"

    /**
     * Who the isolated process is: uid 0 and its SELinux context, in the shape `id` prints.
     *
     * This is the chain's identity check. It can only answer if the service is bound, alive and
     * running as uid 0 -- there is no file, socket or child process in between that could be
     * stale.
     */
    fun identity(): String = checked { it.channelIdentity() }

    /**
     * `runcon <domain> setprop <name> <value>`, in the service process.
     *
     * The domain borrow is the point (it is why the chain can open the adbd gate at all), and the
     * write reaches property_service -- see the AIDL doc for why that matters.
     */
    fun setPropInDomain(domain: String, name: String, value: String): String =
        checked { it.setPropInDomain(domain, name, value) }

    /**
     * Is anything listening on [port]?  See [PortProbe] for the three possible answers.
     *
     * Unlike the two actions above this one never throws for a negative answer: "not listening"
     * and "cannot tell" are answers, and the caller decides what they mean.
     */
    fun waitForPort(port: Int, timeoutMs: Int): PortProbe {
        val bound = service() ?: throw IllegalStateException(NOT_BOUND)
        return PortProbe.parse(bound.waitForPort(port, timeoutMs))
    }

    fun close() = Unit // the binder is owned by IsolatedRootShell, not by us

    /** Run one action and turn the native failure marker into an exception. */
    private fun checked(action: (IRootShellService) -> String): String {
        val bound = service() ?: throw IllegalStateException(NOT_BOUND)
        val output = action(bound)
        if (output.contains(EXEC_FAILED)) {
            throw IllegalStateException("通道执行失败：${output.trim()}")
        }
        return output
    }

    /**
     * What the listener probe saw.
     *
     * [listening] is **null** when the probe could not tell -- the service answers
     * "unreadable: …" when it cannot read the kernel's socket table from inside the isolated
     * process. null is not a failure: "I cannot see it" and "it is not there" are different
     * statements, and the chain reacts to them differently (a positive answer ends the wait, the
     * other two leave the verdict to `adb connect`).
     */
    data class PortProbe(val listening: Boolean?, val detail: String) {
        companion object {
            fun parse(answer: String): PortProbe = when {
                answer.startsWith("listening:") -> PortProbe(true, answer)
                answer.startsWith("not-listening:") -> PortProbe(false, answer)
                else -> PortProbe(null, answer)
            }
        }
    }

    companion object {
        /** Marker the native side uses for "the action never ran" (a null argument, a failure). */
        const val EXEC_FAILED = "__GHOSTLOCK_EXEC_FAILED__"

        private const val NOT_BOUND = "root 服务还没绑定（通道未就绪）"
    }
}
