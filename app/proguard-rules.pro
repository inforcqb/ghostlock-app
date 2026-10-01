# Ported Magica: the isolated root service and its app-zygote preload.
#
# RootShellService is looked up BY NAME from native code -- JNI_OnLoad in
# app/src/main/jni/magica.cpp does FindClass("com/ghostlock/app/root/RootShellService")
# and then RegisterNatives for "root"/"adb_root"/"start_shell_server" with the
# signatures ()Z.  Renaming the class or those three methods (or stripping them as
# "unused") makes the registrations fail, which in turn makes every native call
# throw UnsatisfiedLinkError, so keep the whole class including its members.
-keep class com.ghostlock.app.root.RootShellService { *; }
# Named by android:zygotePreloadName in the manifest and instantiated by the app
# zygote before anything else of ours runs.
-keep class com.ghostlock.app.root.AppZygote { *; }
# Control-plane AIDL of the isolated service (the .Stub is what RootShellService
# implements; the app binds it through IRootShellService.Stub.asInterface).
-keep interface com.ghostlock.app.root.IRootShellService { *; }
-keep class com.ghostlock.app.root.IRootShellService$Stub { *; }

# Bundled Conscrypt: libadb reaches it by name
# (Class.forName("org.conscrypt.OpenSSLProvider")), so it must survive R8 with that
# name, and Conscrypt itself is entered through reflection for the TLS exporter.
-keep class org.conscrypt.OpenSSLProvider { *; }
-keep class org.conscrypt.Conscrypt { *; }
-keepnames class org.conscrypt.**
# Conscrypt's KitKat / pre-KitKat SSLSocket adapters reference platform classes that
# no longer exist; they are unreachable on API 34+. Without these two lines R8 fails
# the release build with "Missing classes detected" (measured 2026-09-29).
-dontwarn com.android.org.conscrypt.SSLParametersImpl
-dontwarn org.apache.harmony.xnet.provider.jsse.SSLParametersImpl
