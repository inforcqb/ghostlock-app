# ndk-build description of the ported Magica root-shell JNI library (libmagica2.so).
#
# THIS FILE IS NOT WIRED INTO THE BUILD.  The app is built with option (b) of the
# port brief: the root `Makefile` target `magica2jni` produces
# `.build/jni/libmagica2.so` with the same NDK clang++ that already builds the
# app's own binary, and the root Gradle task `prepareMagica2JniLibs` copies it into
# the APK's jniLibs.  AGP's externalNativeBuild is deliberately NOT used because
# CI's NDK is ONDK (`NDK_ROOT`/`ANDROID_NDK_HOME`), which AGP cannot resolve, and
# because ndk-build here would additionally require `buildFeatures { prefab = true }`
# plus the `org.lsposed.libcxx:libcxx` dependency and its repository.
#
# It is kept (a) as the faithful record of the upstream module layout and flags and
# (b) so that switching to
# `externalNativeBuild { ndkBuild { path = file("src/main/jni/Android.mk") } }`
# later is a small change in app/build.gradle.kts.  If that switch is made, the
# module name (`magica2`) must stay identical to libmagica2.so and to
# System.loadLibrary("magica2") in AppZygote/RootShellService.

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE           := magica2
LOCAL_SRC_FILES        := magica.cpp
LOCAL_LDLIBS           := -llog
LOCAL_STATIC_LIBRARIES := lsplt system_properties cxx
include $(BUILD_SHARED_LIBRARY)

include $(LOCAL_PATH)/lsplt/Android.mk
include $(LOCAL_PATH)/system_properties/Android.mk
$(call import-module,prefab/cxx)
