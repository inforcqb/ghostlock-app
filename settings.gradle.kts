@file:Suppress("UnstableApiUsage")

pluginManagement {
    repositories {
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        mavenCentral()
        // Kept for the optional switch to AGP's ndk-build wiring of the ported Magica JNI
        // library: upstream resolves `org.lsposed.libcxx:libcxx` (prefab libc++, needed when
        // APP_STL := none) from JitPack.  The current wiring builds that .so from the root
        // Makefile instead and pulls no Maven artifact -- see app/src/main/jni/Android.mk.
        maven("https://jitpack.io")
    }
}

rootProject.name = "GhostLock"
include(":app")
