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
 * * `onBind` runs `root()` and then `start_shell_server()` (that order is
 *   upstream's, and it is required: the server refuses to start unless it is
 *   already uid 0).
 * * The server it starts is an AF_UNIX socket + token under
 *   [CHANNEL_DIR]; the app talks to it through [RootChannel], and `adb shell`
 *   (uid 2000) through the device-side `rshell` wrapper.  Not a single IP socket
 *   is opened here -- an isolated process has no AF_INET.
 * * `adb_root()` (the adbd patch) is **not** called on bind: it blocks up to 15 s
 *   and it restarts adbd, so it is only reachable through the AIDL method below.
 * * The libsu-based `RemoteProcess*` plumbing of upstream is deliberately NOT
 *   ported: the command plane is the UNIX socket.
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

        override fun startChannel(): Boolean = start_shell_server()

        override fun adbRoot(): Boolean = root() && adb_root()

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
     * `root()` first, `start_shell_server()` second, upstream's order: the shell
     * server is the point of this service, and it requires uid 0.
     *
     * The binder is returned even when `root()` fails: the caller can then ask
     * [IRootShellService.ensureRoot] / [IRootShellService.startChannel] what
     * actually happened instead of getting a null binder with no explanation.
     */
    override fun onBind(intent: Intent?): IBinder {
        val rooted = root()
        Log.i(TAG, "root() -> $rooted (uid=${Process.myUid()} pid=${Process.myPid()})")
        if (start_shell_server()) {
            Log.i(TAG, "root shell server: $CHANNEL_SOCK (token $CHANNEL_TOKEN)")
        } else {
            Log.w(TAG, "root shell server: not started")
        }
        return binder
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy")
        super.onDestroy()
    }

    /*
     * The three native registrations of upstream MagicaService, kept by name and
     * signature: JNI_OnLoad in app/src/main/jni/magica.cpp does
     *
     *     FindClass("com/ghostlock/app/root/RootShellService")
     *     RegisterNatives({ "root", "adb_root", "start_shell_server" } ...)
     *
     * so this class must not be renamed or obfuscated (see app/proguard-rules.pro)
     * and these three names must not change.  They are *instance* methods here (not
     * `@JvmStatic` members of a companion object) on purpose: the JNI lookup key is
     * the plain JVM method name, and an instance method cannot be confused with the
     * companion's static bridge.
     */
    private external fun root(): Boolean

    private external fun adb_root(): Boolean

    private external fun start_shell_server(): Boolean

    companion object {
        /** The logcat tag of both this class and the native code (see [ROOT_LOG_TAG]). */
        const val TAG = ROOT_LOG_TAG

        /** The device directory shared with adb shell (uid 2000) and the host tooling. */
        const val CHANNEL_DIR = "/data/local/tmp/gl-w1"
        const val CHANNEL_SOCK = "$CHANNEL_DIR/rshell.sock"
        const val CHANNEL_TOKEN = "$CHANNEL_DIR/rshell.token"

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
