package com.ghostlock.app.root

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.Process
import android.util.Log
import kotlinx.coroutines.CancellationException
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
 * * [RootShellService.onBind] already does `root()`; the two AIDL calls below only
 *   confirm it, so a silent failure cannot be mistaken for a working channel.
 * * [release] is deliberately NOT called by the chain: unbinding destroys the isolated
 *   process, and with it the uid-0 command plane every later step talks to. The
 *   service lives until the app (or the framework) goes away, which matches the
 *   lifetime the verified chain assumes.
 *
 * ## When it does not become uid 0
 *
 * A failed round is not re-polled forever and it is not fatal on the first try either:
 * the process is **killed and pulled up again** ([restart]), up to [SERVICE_RESTART_ROUNDS]
 * rounds. The AppZygote capset hook either fired in that process or it did not, so a
 * process that answers "not uid 0" [CHANNEL_START_ATTEMPTS] times is not going to change
 * its mind -- a new process is the only thing that can.
 */
class IsolatedRootShell(private val context: Context) {

    @Volatile
    private var bound: IRootShellService? = null

    private var connection: ServiceConnection? = null

    fun isReady(): Boolean = bound != null

    /**
     * Start the isolated service and require that it really is uid 0.
     *
     * **Restarted on failure, at most [SERVICE_RESTART_ROUNDS] times** (the user's call,
     * 2026-10-03): a round is "bind + `ensureRoot()` + [CHANNEL_START_ATTEMPTS] identity
     * reads [CHANNEL_START_RETRY_MS] apart", and a round that never sees uid=0 means the
     * process is not going to recover on its own -- the AppZygote capset hook either fired
     * in *that* process or it did not.  So the process is killed and pulled up again
     * ([restart]) instead of being re-polled, and only the third failed round throws.
     *
     * Killing it is safe *because the round failed*: nothing in a process that never reached
     * uid 0 has forged kernel state yet (the parks that must not die are the ones the engine
     * creates, and those are only reached after a successful identity read).
     */
    suspend fun launch(onLog: (String) -> Unit = {}): String {
        logServiceFacts(onLog)
        var lastFailure: String? = null
        for (round in 1..SERVICE_RESTART_ROUNDS) {
            if (round > 1) {
                onLog(
                    "[!] 第 ${round - 1} 轮没拿到 uid=0（$lastFailure）⇒ " +
                        "杀掉隔离进程重新拉起（第 $round/$SERVICE_RESTART_ROUNDS 轮）",
                )
                restart(onLog)
            }
            val outcome = try {
                Result.success(startOnce(onLog))
            } catch (cancelled: CancellationException) {
                /* Not a failed round: the caller went away. Re-running three rounds of
                 * bind + 9 s of identity reads after a cancel would keep the app busy for
                 * minutes for nothing. */
                throw cancelled
            } catch (error: Exception) {
                Result.failure(error)
            }
            outcome.getOrNull()?.let { return it }
            lastFailure = outcome.exceptionOrNull()?.message ?: "未知原因"
            onLog("[!] 隔离 root 服务第 $round/$SERVICE_RESTART_ROUNDS 轮失败：$lastFailure")
        }
        throw IllegalStateException(
            "隔离 root 服务重启 $SERVICE_RESTART_ROUNDS 轮都没能给出 uid=0：" +
                "最后一次失败：$lastFailure（logcat -s ${RootShellService.TAG}）",
        )
    }

    /**
     * One round: bind, require uid 0, run [CHANNEL_START_ATTEMPTS] identity reads.
     *
     * Throws with a diagnosis on any failure; the string it returns on success is what the
     * chain prints.
     */
    private suspend fun startOnce(onLog: (String) -> Unit): String {
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
        /* startChannel() is a self-test: it reads the identity (`id`, in a child of the service)
         * and requires uid=0. The isolated process may need a moment before that works on a cold
         * or loaded device -- measured: the first answer can still be the pre-escalation uid --
         * so retry instead of failing the whole chain on the first miss:
         * CHANNEL_START_ATTEMPTS attempts, CHANNEL_START_RETRY_MS apart.
         *
         * These attempts are *inside* one round: if all of them miss, the process is not
         * warming up, it is wrong -- [launch] then kills it and starts a new one, up to
         * SERVICE_RESTART_ROUNDS rounds. */
        var channelStarted = false
        for (attempt in 1..CHANNEL_START_ATTEMPTS) {
            /* Ask the service who it is rather than only whether it is happy: the verdict alone
             * ("false") wastes a whole chain run when a device misbehaves, and the text is the
             * diagnosis. */
            val identity = runCatching { service.channelIdentity() }.getOrElse { error ->
                "抛异常 ${error::class.java.simpleName}: ${error.message}"
            }
            onLog("[*] 通道自检 第 $attempt/$CHANNEL_START_ATTEMPTS 次：${identity.trim().take(200)}")
            if (identity.contains("uid=0")) {
                channelStarted = true
                break
            }
            if (attempt < CHANNEL_START_ATTEMPTS) Thread.sleep(CHANNEL_START_RETRY_MS)
        }
        if (!channelStarted) {
            throw IllegalStateException(
                "通道自检失败 $CHANNEL_START_ATTEMPTS 次" +
                    "（${CHANNEL_START_ATTEMPTS * (CHANNEL_START_RETRY_MS / 1000)}s）：" +
                    "通过 binder 读身份没有拿到 uid=0 —— 本轮判负，" +
                    "会杀掉这个隔离进程重新拉起（最多 $SERVICE_RESTART_ROUNDS 轮）" +
                    "(check logcat -s ${RootShellService.TAG})",
            )
        }
        /* Bring up the second command plane -- and this is the only place that does it.
         *
         * [IRootShellService.startChannel] re-reads the identity and then starts
         * `gl_server` (`app/src/main/jni/gl_server.cpp`) on 127.0.0.1:5038, the transport the
         * chain falls back to when the root adbd is not there ([RootExec] on the Kotlin side,
         * `RootCommand` as its client).  Nothing else may start it: a second bind would fail
         * and a restart of this process would leave an orphan.
         *
         * The boolean is the *identity* verdict, not "the listener is up" -- a bind failure
         * makes the native side fork a `runcon u:r:system_server:s0` child that binds
         * instead, and the rc is logged by the service.  What proves the plane end to end is
         * the first command the chain sends through it. */
        val started = runCatching { service.startChannel() }.getOrElse { error ->
            onLog("[!] startChannel() 抛异常：${error::class.java.simpleName}: ${error.message}")
            false
        }
        onLog("[*] Magica startChannel()（uid-0 命令面 127.0.0.1:5038）-> $started")
        if (!started) {
            throw IllegalStateException(
                "startChannel() == false：服务进程没有确认 uid=0（这一轮判负，会重新拉起）",
            )
        }
        /* Ported Magica's own "enable root shell" step, run automatically (the upstream
         * app needed a button for it): ensureRoot + the adbd root patch, i.e. the
         * resetprop/restart of adbd that makes an adb shell come back as uid 0. It is
         * non-fatal here -- the chain opens the TCP gate through the channel instead --
         * but its result is worth having in the log. */
        val adbRoot = runCatching { service.adbRoot() }.getOrElse { error ->
            onLog("[!] adbRoot() 抛异常：${error::class.simpleName}: ${error.message}")
            false
        }
        onLog("[*] Magica adbRoot()（内置 resetprop/adbd 重启逻辑）-> $adbRoot")
        onLog("[*] adb 公钥相关逻辑已移除：配对时 adbd 已登记本机密钥，无需再写 adb_keys")
        return "uid-0 root service ready: bound, ensureRoot=ok, startChannel=ok(uid=0 over binder), " +
            "adbRoot=$adbRoot"
    }

    /** The bound service, for the chain's command plane ([RootChannel]); null before [launch]. */
    fun serviceOrNull(): IRootShellService? = bound

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

    /**
     * Kill the isolated process and drop the binding, so that the next bind forks a *new*
     * one.
     *
     * Three steps, in this order, because the framework decides the process's fate:
     *
     *  1. [IRootShellService.destroy] asks the service to `stopSelf()`. This is the only
     *     handle the app has on that process: `Process.killProcess(pid)` from here is
     *     denied (different uid, and an isolated process is not ours to signal) and the
     *     shell is not root yet.
     *  2. `unbindService()`: an isolated process exists for its binding, and nothing may
     *     be bound to it any more.
     *  3. a short settle delay, so the next `bindIsolatedService()` does not race the
     *     teardown and attach to the process we just asked to die.
     *
     * Every step is best-effort: `destroy()` on an already-dead binder throws
     * `DeadObjectException`, which is exactly the state we are trying to reach.
     */
    private fun restart(onLog: (String) -> Unit) {
        val service = bound
        bound = null
        val conn = connection
        connection = null
        runCatching { service?.destroy() }.onFailure { error ->
            onLog("[*] destroy() 没能送达（进程可能已经没了）：${error.message}")
        }
        if (conn != null) runCatching { context.unbindService(conn) }
        onLog("[*] 隔离服务已停（destroy + unbind），${RESTART_SETTLE_MS}ms 后重新拉起")
        Thread.sleep(RESTART_SETTLE_MS)
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
        /** startChannel() retry policy: a cold isolated process may not answer at once. */
        const val CHANNEL_START_ATTEMPTS = 3
        const val CHANNEL_START_RETRY_MS = 3_000L

        /**
         * How many times the isolated process may be killed and started over when it never
         * reports uid 0: three rounds, the user's number. [CHANNEL_START_ATTEMPTS] identity
         * reads happen inside each of them.
         */
        const val SERVICE_RESTART_ROUNDS = 3

        /** How long the framework gets to reap a killed isolated process before the next bind. */
        const val RESTART_SETTLE_MS = 2_000L

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
