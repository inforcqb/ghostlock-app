package com.ghostlock.app.root

import android.app.ZygotePreload
import android.content.pm.ApplicationInfo
import android.util.Log

/**
 * App-zygote preload of the ported Magica library.  Registered in
 * `app/src/main/AndroidManifest.xml` as
 * `android:zygotePreloadName="com.ghostlock.app.root.AppZygote"`.
 *
 * ## This ordering is load-bearing -- do not "move the load into the service"
 *
 * `doPreload` runs in the **app zygote**, i.e. before any isolated service process
 * exists.  `JNI_OnLoad` of `libmagica2.so` (see `app/src/main/jni/magica.cpp`)
 * then patches the PLT of `/system/lib64/libandroid_runtime.so` so that the
 * runtime's `capset` call is skipped, and every isolated process forked from this
 * zygote inherits the patched mapping.  If the library were loaded only inside the
 * isolated process, that `capset` would already have run, the process would keep
 * `CapBnd=0`, and `setresuid(0)` would fail (or trap: `SIGSYS` is only logged).
 *
 * [RootShellService] keeps a fallback `System.loadLibrary` in its companion
 * initialiser, but in the normal path it is a no-op: the library is already loaded
 * by the time the isolated child initialises that class.
 *
 * A failure to load is rethrown on purpose: a root service whose native side is
 * missing cannot do anything useful, and the exception shows up in logcat under
 * [ROOT_LOG_TAG] instead of surfacing later as an unexplained
 * `UnsatisfiedLinkError` inside the service.
 */
class AppZygote : ZygotePreload {

    override fun doPreload(appInfo: ApplicationInfo) {
        Log.i(ROOT_LOG_TAG, "app zygote preload: loading lib$NATIVE_LIB_NAME.so")
        try {
            System.loadLibrary(NATIVE_LIB_NAME)
        } catch (t: UnsatisfiedLinkError) {
            Log.e(
                ROOT_LOG_TAG,
                "app zygote preload: lib$NATIVE_LIB_NAME.so did not load, so the capset " +
                    "hook is NOT installed and the root service cannot escalate",
                t,
            )
            throw t
        }
        Log.i(ROOT_LOG_TAG, "app zygote preload: lib$NATIVE_LIB_NAME.so loaded (capset hook installed)")
    }
}
