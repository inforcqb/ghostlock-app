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
        // `org.lsposed.libcxx:libcxx` (the libc++ used by the ported Magica JNI build,
        // which compiles with APP_STL := none + prefab) is published on JitPack.
        maven("https://jitpack.io")
    }
}

rootProject.name = "GhostLock"
include(":app")
