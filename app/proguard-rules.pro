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

# Bundled Conscrypt, libadb and the sun-security certificate provider are GONE (2026-10-01):
# the bundled platform-tools `adb` does pairing and the channel with its own key, so none of
# those libraries are on the classpath any more -- and with them went the
# `com.android.org.conscrypt.SSLParametersImpl` / `org.apache.harmony...` -dontwarn lines
# that only existed to make R8 accept Conscrypt's unreachable KitKat adapters.
