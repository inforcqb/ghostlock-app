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
 * * The command plane is the **binder**: [IRootShellService.execShell] runs one short shell
 *   command in this process and returns its combined output, so the app needs neither a shared
 *   directory nor a token.  Not a single IP socket is opened here -- an isolated process
 *   has no AF_INET.
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
        override fun ensureRoot(): Boolean = root()

        /**
         * Self-test: the command plane is the binder itself now, so "is the channel up?" means
         * "does a command really run as uid 0 through it?" -- a stronger statement than the old
         * "the socket exists" check, and it needs no filesystem at all.
         */
        override fun startChannel(): Boolean {
            val identity = runCatching { execShell("id", 15_000) }.getOrDefault("")
            val rooted = identity.contains("uid=0")
            Log.i(TAG, "startChannel: identity=${identity.trim()} -> $rooted")
            return rooted
        }

        override fun adbRoot(): Boolean = root() && adb_root()

        /** The chain's command plane from the uid-0 channel step on; see the AIDL doc. */
        override fun execShell(command: String, timeoutMs: Int): String =
            exec_shell(command, timeoutMs) ?: ""

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
     *     RegisterNatives({ "root", "adb_root", "exec_shell" } ...)
     *
     * so this class must not be renamed or obfuscated (see app/proguard-rules.pro)
     * and these names must not change.  They are *instance* methods here (not
     * `@JvmStatic` members of a companion object) on purpose: the JNI lookup key is
     * the plain JVM method name, and an instance method cannot be confused with the
     * companion's static bridge.
     *
     * The old socket server (`start_shell_server` / `set_channel_dir`) is no longer
     * registered: the command plane is the binder now (see [IRootShellService.execShell]).
     */
    private external fun root(): Boolean

    private external fun adb_root(): Boolean

    /** One shell command as uid 0; the JNI side captures its combined output. */
    private external fun exec_shell(command: String, timeoutMs: Int): String?

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
