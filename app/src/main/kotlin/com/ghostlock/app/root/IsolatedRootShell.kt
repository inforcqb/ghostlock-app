package com.ghostlock.app.root

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.util.Log
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import kotlin.coroutines.resume

/**
 * Starts this app's own uid-0 root service and keeps it bound.
 *
 * ## Why this class exists
 *
 * The chain's third step used to launch an *external* app instead:
 * `am start -n io.github.vvb2060.puellamagi/.MainActivity`. That app is not installed
 * on this handset, so the step could only ever fail (`Activity class ... does not
 * exist`) and the chain then waited for a channel nobody served -- the stale
 * `rshell.sock` file left behind by an earlier boot made the wait look successful
 * until the first connect failed with `Connection refused`.
 *
 * Magica's root service is ported into this app ([RootShellService] +
 * `libmagica2.so` + [AppZygote]), so the chain starts it itself.
 *
 * ## The binding rules
 *
 * * it MUST be `bindIsolatedService()`: a plain `bindService()` does not put the
 *   service into its own isolated process, and `setresuid(0)` only works from a
 *   process that was born with the right credentials. The caller is this app (the
 *   process that owns the service) -- binding from the Shizuku user service, which
 *   runs as uid 2000, is not allowed for an isolated service.
 * * [RootShellService.onBind] already does `root()` and `start_shell_server()`; the
 *   two AIDL calls below only confirm it, so a silent failure cannot be mistaken for
 *   a working channel.
 * * [release] is deliberately NOT called by the chain: unbinding destroys the isolated
 *   process, and with it the uid-0 shell server the next steps still talk to. The
 *   service lives until the app (or the framework) goes away, which matches the
 *   lifetime the verified chain assumes.
 */
class IsolatedRootShell(private val context: Context) {

    @Volatile
    private var bound: IRootShellService? = null

    private var connection: ServiceConnection? = null

    fun isReady(): Boolean = bound != null

    /**
     * Bind the isolated service (if not already bound) and require that it reports both
     * a uid-0 process and a listening channel. Throws with a diagnosis on any failure;
     * the returned string is what the chain prints.
     */
    suspend fun launch(): String {
        val service = withTimeout(BIND_TIMEOUT_MS) { bindOrNull() }
            ?: throw IllegalStateException(
                "bindIsolatedService() did not connect to .root.RootShellService within " +
                    "${BIND_TIMEOUT_MS / 1000}s -- the isolated process did not start " +
                    "(check logcat -s ${RootShellService.TAG})",
            )
        if (!service.ensureRoot()) {
            throw IllegalStateException(
                "the isolated process is not uid 0: ensureRoot() == false -- " +
                    "the AppZygote capset hook did not take effect " +
                    "(check logcat -s ${RootShellService.TAG})",
            )
        }
        if (!service.startChannel()) {
            throw IllegalStateException(
                "startChannel() == false: the uid-0 shell server is not listening on " +
                    RootShellService.CHANNEL_SOCK,
            )
        }
        return "uid-0 root service ready: bound, ensureRoot=ok, startChannel=ok " +
            "(channel ${RootShellService.CHANNEL_SOCK})"
    }

    private suspend fun bindOrNull(): IRootShellService? {
        bound?.let { return it }
        return suspendCancellableCoroutine { continuation ->
            val conn = object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                    Log.i(RootShellService.TAG, "isolated root service connected: $name")
                    val service = IRootShellService.Stub.asInterface(binder)
                    bound = service
                    if (continuation.isActive) continuation.resume(service)
                }

                override fun onServiceDisconnected(name: ComponentName) {
                    Log.w(RootShellService.TAG, "isolated root service disconnected: $name")
                    bound = null
                    if (continuation.isActive) continuation.resume(null)
                }
            }
            connection = conn
            val requested = runCatching {
                context.bindIsolatedService(
                    Intent(context, RootShellService::class.java),
                    Context.BIND_AUTO_CREATE,
                    INSTANCE_NAME,
                    context.mainExecutor,
                    conn,
                )
            }.getOrElse { error ->
                Log.e(
                    RootShellService.TAG,
                    "bindIsolatedService threw: ${error::class.simpleName}: ${error.message}",
                )
                false
            }
            if (!requested && continuation.isActive) continuation.resume(null)
        }
    }

    /** See the class note: the chain does not release the binding. */
    fun release() {
        val conn = connection ?: return
        runCatching { context.unbindService(conn) }
        connection = null
        bound = null
    }

    companion object {
        /** Instance name of the isolated service; per-service, and stable across binds. */
        const val INSTANCE_NAME = "ghostlock-root"

        /** Starting an isolated process means forking the app zygote; give it room. */
        const val BIND_TIMEOUT_MS = 90_000L
    }
}
