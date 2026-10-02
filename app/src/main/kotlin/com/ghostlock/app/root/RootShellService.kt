package com.ghostlock.app.root

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.Process
import android.util.Log

/**
 * Name of the JNI module that carries the ported Magica code.
 *
 * One definition, three consumers that MUST stay in sync:
 * `System.loadLibrary(NATIVE_LIB_NAME)` here and in [AppZygote],
 * `libmagica2.so` (the file the build produces) and `LOCAL_MODULE := magica2`
 * in `app/src/main/jni/Android.mk`.
 *
 * It is a `const val`, so the compiler inlines it and referencing it never loads
 * another class (important in [AppZygote]: nothing of this package may need to be
 * initialised inside the app zygote).
 */
internal const val NATIVE_LIB_NAME = "magica2"

/**
 * The logcat tag of the port (`TAG` in `app/src/main/jni/logging.h`), shared by
 * [RootShellService], [AppZygote] and the native code so that one
 * `adb logcat -s GhostlockRoot` shows both sides of a run.
 */
internal const val ROOT_LOG_TAG = "GhostlockRoot"

/**
 * The isolated root service: the port of Magica's `MagicaService`.
 *
 * ## Why it exists
 *
 * `setresuid(0)` only works from a process that was born with the right
 * credentials, so the act of becoming uid 0 has to happen in an **isolated
 * process** (`android:isolatedProcess="true"`, `android:useAppZygote="true"`) that
 * the app zygote -- and therefore [AppZygote]'s `System.loadLibrary` -- has
 * already prepared.  Declared in `app/src/main/AndroidManifest.xml` as
 * `.root.RootShellService`.
 *
 * The result on this handset is `uid=0 u:r:isolated_app:s0` with
 * `CapEff=0x1c0`, `CapBnd=0`, `NoNewPrivs=1`: uid 0, but no capabilities at all.
 * Everything here is written around that fact -- see the header of
 * `app/src/main/jni/magica.cpp`.
 *
 * ## What it does and does not do
 *
 * * `onBind` runs `root()` (the escalation `root()` requires, and it must succeed before any
 *   command can run as uid 0).
 * * The command plane is the **binder**, and it carries three *typed actions* --
 *   [IRootShellService.channelIdentity], [IRootShellService.setPropInDomain],
 *   [IRootShellService.waitForPort] -- each of them native code running in this process.
 *   No shell and no fork: a spawned child loses the escalated uid on this platform
 *   (measured: the isolated process is uid 0, its `ProcessBuilder` child printed
 *   `uid=90000(u0_i0)`), and a frozen cached process never gets to run its command at all.
 *   Not a single IP socket is opened here either -- an isolated process has no AF_INET
 *   (measured), which is why the listener probe reads `/proc/net/tcp{,6}`.
 * * `adb_root()` (the adbd patch) is **not** called on bind: it blocks up to 15 s
 *   and it restarts adbd, so it is only reachable through the AIDL method below.
 * * The libsu-based `RemoteProcess*` plumbing of upstream is deliberately NOT
 *   ported: the command plane is the binder.
 *
 * ## Calling convention
 *
 * The caller has to bind it as an isolated service -- a plain `bindService()`
 * would not give the service its own isolated process:
 *
 * ```
 * context.bindIsolatedService(
 *     Intent(context, RootShellService::class.java),
 *     Context.BIND_AUTO_CREATE,
 *     "ghostlock-root",            // instance name, per-service
 *     context.mainExecutor,
 *     connection,
 * )
 * ```
 *
 * ## Logging
 *
 * Everything lands under the logcat tag [TAG] (= the native `TAG` of
 * `logging.h`), so `adb logcat -s GhostlockRoot` shows both sides of one run.
 */
class RootShellService : Service() {

    private val binder: IRootShellService.Stub = object : IRootShellService.Stub() {

        /** The marker the caller parses: "this action never ran", never "it printed nothing". */
        private fun failure(what: String, error: Throwable): String {
            val reason = "__GHOSTLOCK_EXEC_FAILED__: $what 抛异常 " +
                "${error::class.java.simpleName}: ${error.message}"
            Log.e(TAG, reason)
            return reason
        }

        override fun ensureRoot(): Boolean = root()

        /**
         * Self-test: the command plane is this binder, so "is the channel up?" means "does the
         * service really report a uid-0 identity?" -- a stronger statement than the old "the
         * socket exists" check, and it needs no filesystem at all.
         */
        override fun startChannel(): Boolean {
            val identity = runCatching { channelIdentity() }.getOrElse { error ->
                "抛异常 ${error::class.java.simpleName}: ${error.message}"
            }
            val rooted = identity.contains("uid=0")
            Log.i(TAG, "startChannel: identity=${identity.trim()} -> $rooted")
            return rooted
        }

        override fun adbRoot(): Boolean = root() && adb_root()

        /*
         * The three actions.  All of them are **native on purpose**: this is the process that
         * holds uid 0 and the borrowed SELinux domain, and a JVM-side `Runtime`/`ProcessBuilder`
         * spawn would drop back to the app uid (measured: `uid=90000(u0_i0)`), while these calls
         * stay in this process, with this uid, with no child to lose anything to.
         *
         * A native failure is turned into the `__GHOSTLOCK_EXEC_FAILED__` marker so the caller
         * sees "the action never ran" and not an empty answer.
         */
        override fun channelIdentity(): String {
            return runCatching { channel_identity() }.getOrElse { error ->
                failure("identity", error)
            } ?: ""
        }

        override fun setPropInDomain(domain: String, name: String, value: String): String {
            return runCatching { channel_set_prop(domain, name, value) }.getOrElse { error ->
                failure("setPropInDomain", error)
            } ?: ""
        }

        override fun waitForPort(port: Int, timeoutMs: Int): String {
            return runCatching { channel_wait_port(port, timeoutMs) }.getOrElse { error ->
                "unreadable: ${error::class.java.simpleName}: ${error.message}".also {
                    Log.e(TAG, "waitForPort: $it")
                }
            } ?: "unreadable: the native call returned nothing"
        }

        override fun destroy() {
            Log.i(TAG, "destroy() requested by the caller")
            stopSelf()
        }
    }

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "onCreate: uid=${Process.myUid()} pid=${Process.myPid()}")
    }

    /**
     * `root()` first: it is what makes this process uid 0, and every command the caller sends
     * runs with that identity.
     *
     * The binder is returned even when `root()` fails: the caller can then ask
     * [IRootShellService.ensureRoot] / [IRootShellService.startChannel] what actually happened
     * instead of getting a null binder with no explanation.
     */
    override fun onBind(intent: Intent?): IBinder {
        val rooted = root()
        Log.i(TAG, "root() -> $rooted (uid=${Process.myUid()} pid=${Process.myPid()})")
        return binder
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy")
        super.onDestroy()
    }

    /*
     * The native registrations, kept by name and signature: JNI_OnLoad in
     * app/src/main/jni/magica.cpp does
     *
     *     FindClass("com/ghostlock/app/root/RootShellService")
     *     RegisterNatives({ "root", "adb_root", "channel_identity", "channel_set_prop",
     *                       "channel_wait_port" } ...)
     *
     * so this class must not be renamed or obfuscated (see app/proguard-rules.pro)
     * and these names must not change.  They are *instance* methods here (not
     * `@JvmStatic` members of a companion object) on purpose: the JNI lookup key is
     * the plain JVM method name, and an instance method cannot be confused with the
     * companion's static bridge.
     *
     * The old socket server (`start_shell_server` / `set_channel_dir`) and the shell-string
     * plane (`exec_shell`) are no longer registered: the command plane is the binder, and it
     * carries typed actions instead of command strings.
     */
    private external fun root(): Boolean

    private external fun adb_root(): Boolean

    /** uid 0 + this process's SELinux context, in the shape `id` prints. */
    private external fun channel_identity(): String?

    /** setcon(<domain>) -> property_set(name, value) -> setcon(back); see the AIDL doc. */
    private external fun channel_set_prop(domain: String, name: String, value: String): String?

    /** "listening: …" / "not-listening: …" / "unreadable: …"; see the AIDL doc. */
    private external fun channel_wait_port(port: Int, timeoutMs: Int): String?

    companion object {
        /** The logcat tag of both this class and the native code (see [ROOT_LOG_TAG]). */
        const val TAG = ROOT_LOG_TAG

        init {
            /*
             * Fallback load.  The load-bearing one is AppZygote.doPreload, which
             * installs the capset hook in the APP ZYGOTE so every isolated process
             * inherits it.  By the time this class is initialised in the isolated
             * child the library is already loaded (System.loadLibrary is a no-op
             * then, and JNI_OnLoad does not run a second time), so this line only
             * matters when the app-zygote path is not used at all -- and on such a
             * build the escalation may fail even though the natives resolve.
             */
            System.loadLibrary(NATIVE_LIB_NAME)
        }
    }
}
