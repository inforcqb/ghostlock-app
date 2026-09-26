# Shizuku binds GhostlockUserService by component name and talks over the
# generated AIDL stubs; R8 must keep both sides in release builds.
-keep class com.ghostlock.app.shizuku.GhostlockUserService { *; }
-keep interface com.ghostlock.app.shizuku.IGhostlockUserService { *; }
-keep interface com.ghostlock.app.shizuku.IGhostlockCallback { *; }
-keep class com.ghostlock.app.shizuku.IGhostlockUserService$Stub { *; }
-keep class com.ghostlock.app.shizuku.IGhostlockCallback$Stub { *; }

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
