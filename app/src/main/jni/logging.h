#pragma once

/* Magica's logging macros (upstream file, Magica is Unlicense).  The only change
 * in the port is TAG: it was "Magica", and device-side diagnosis now filters with
 * `adb logcat -s GhostlockRoot`.
 *
 * NDEBUG is deliberately NOT defined for this library: the LOGD/LOGV lines
 * ("Skip capset", "resetprop: update prop ...", "CommitHook success") are the
 * cheapest evidence that the app-zygote capset hook was really installed, and the
 * first device run needs them.  Revisit if release log volume ever matters. */

#include <android/log.h>

#ifdef NDEBUG
#define LOGV(...)
#define LOGD(...)
#else
#define LOGV(...) (__android_log_print(ANDROID_LOG_VERBOSE, TAG, __VA_ARGS__))
#define LOGD(...) (__android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__))
#endif

#define LOGI(...) (__android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__))
#define LOGW(...) (__android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__))
#define LOGE(...) (__android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__))
#define PLOGE(fmt, args...) LOGE(fmt " failed with %d: %s\n", ##args, errno, strerror(errno))

#define TAG "GhostlockRoot"
