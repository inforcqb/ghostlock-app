# Upstream (Magica fork) ndk-build application settings, kept for the record; see
# Android.mk in this directory -- the app is actually built with the root
# Makefile's `magica2jni` target (option (b)), which mirrors these flags without
# ndk-build:
#   * -fvisibility=hidden / -fvisibility-inlines-hidden: load-bearing.  Together
#     with -Wl,-exclude-libs,ALL it keeps the vendored resetprop (and libc++) from
#     being exported out of libmagica2.so, and keeps libc's own
#     __system_property_* from interposing on the bundled ones.
#   * APP_STL := none is what the prefab `cxx` setup implies; the Makefile target
#     instead links the NDK's default static libc++ into the .so, which keeps this
#     file free of the prefab/libcxx dependency.
#   * The LTO flags are dropped in the Makefile target: LTO buys little for one
#     .so and costs a lot of CI time.
# APP_CONLYFLAGS is irrelevant here: app/src/main/jni has no C sources.

APP_LDFLAGS    := -Wl,-exclude-libs,ALL -Wl,--gc-sections -Wl,--strip-all -Wl,--icf=all -flto
APP_CFLAGS     := -Wall -Wextra -Werror -fvisibility=hidden -fvisibility-inlines-hidden
APP_CFLAGS     += -flto
APP_CONLYFLAGS := -std=c23
APP_CPPFLAGS   := -std=c++23
APP_STL        := none
