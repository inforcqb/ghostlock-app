package com.ghostlock.app.root

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.Process
import android.util.Log
import kotlinx.coroutines.TimeoutCancellationException
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
     *
     * [onLog] receives the diagnosis as it happens, because the interesting failure is a
     * silent `false` from the framework (see [logServiceFacts]) that leaves no trace in
     * logcat.
     */
    suspend fun launch(onLog: (String) -> Unit = {}): String {
        logServiceFacts(onLog)
        val service = try {
            withTimeout(BIND_TIMEOUT_MS) { bindOrNull(onLog) }
        } catch (timeout: TimeoutCancellationException) {
            throw IllegalStateException(
                "bindIsolatedService() 在 ${BIND_TIMEOUT_MS / 1000}s 内没有回调 onServiceConnected" +
                    " —— 隔离进程没有起来（logcat -s ${RootShellService.TAG}）",
                timeout,
            )
        } ?: throw IllegalStateException(
            "bindIsolatedService() 立刻返回 false：框架拒绝了这次绑定（不是超时）。" +
                "上面那行 service info 是关键——若 isolatedProcess/useAppZygote 是 false，" +
                "说明声明没生效；否则是 AMS 策略拒绝了隔离绑定",
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

    /**
     * What the framework thinks of the service, before anything is bound.
     *
     * `bindIsolatedService` reports failure by returning false -- no exception, and no
     * logcat line of ours -- so a run that failed that way left no evidence at all. These
     * are the facts: the service must be visible to THIS app and must be declared
     * isolated, which also requires the AppZygote preload class.
     */
    private fun logServiceFacts(onLog: (String) -> Unit) {
        val component = ComponentName(context, RootShellService::class.java)
        val info = runCatching {
            context.packageManager.getServiceInfo(component, 0)
        }.getOrElse { error ->
            onLog("[!] getServiceInfo($component) 失败：${error::class.simpleName}: ${error.message}")
            null
        } ?: return
        onLog(
            "[*] service info: ${component.flattenToShortString()} exported=${info.exported} " +
                "isolatedProcess=${(info.flags and FLAG_ISOLATED_PROCESS) != 0} " +
                "appZygote=${(info.flags and FLAG_USE_APP_ZYGOTE) != 0} " +
                "flags=0x${info.flags.toString(16)} processName=${info.processName} " +
                "appUid=${context.applicationInfo.uid}",
        )
    }

    private suspend fun bindOrNull(onLog: (String) -> Unit): IRootShellService? {
        bound?.let { return it }
        return suspendCancellableCoroutine { continuation ->
            val conn = object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                    Log.i(RootShellService.TAG, "isolated root service connected: $name")
                    onLog("[*] 隔离服务已连接：${name.flattenToShortString()} (pid=${Process.myPid()})")
                    val service = IRootShellService.Stub.asInterface(binder)
                    bound = service
                    if (continuation.isActive) continuation.resume(service)
                }

                override fun onServiceDisconnected(name: ComponentName) {
                    Log.w(RootShellService.TAG, "isolated root service disconnected: $name")
                    onLog("[!] 隔离服务断开：${name.flattenToShortString()}")
                    bound = null
                    if (continuation.isActive) continuation.resume(null)
                }
            }
            connection = conn
            onLog("[*] bindIsolatedService(instance=$INSTANCE_NAME, flags=BIND_AUTO_CREATE) …")
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
                onLog("[!] bindIsolatedService 抛异常：${error::class.simpleName}: ${error.message}")
                false
            }
            onLog("[*] bindIsolatedService -> $requested")
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
        /**
         * Instance name of the isolated service: per-service, stable across binds, and it
         * must be a plain identifier. `"ghostlock-root"` was rejected on the device with
         * `IllegalArgumentException: Illegal instanceName` -- the hyphen is not allowed --
         * and `bindIsolatedService` then returned false immediately.
         */
        const val INSTANCE_NAME = "ghostlockRoot"

        /** Starting an isolated process means forking the app zygote; give it room. */
        const val BIND_TIMEOUT_MS = 90_000L

        /**
         * `ServiceInfo.FLAG_ISOLATED_PROCESS` and `ServiceInfo.FLAG_USE_APP_ZYGOTE`.
         *
         * Literals on purpose: the matching `ServiceInfo` *fields* (`isolatedProcess`,
         * `useAppZygote`) are @hide and do not compile against the public SDK, and the
         * app-zygote flag constant is not public either. Values verified on the device:
         * a correctly declared service reports `flags=0xa` (1<<1 | 1<<3).
         */
        private const val FLAG_ISOLATED_PROCESS = 1 shl 1
        private const val FLAG_USE_APP_ZYGOTE = 1 shl 3
    }
}
