package com.ghostlock.app.wireless

/**
 * Logcat tag of the whole wireless-debugging flow.
 *
 * It used to live on `WirelessAdb` (the libadb client). That class is gone -- the bundled
 * `adb` CLI carries both the wireless-debugging channel and the root adbd now -- but the tag
 * stays, because it is what a `adb logcat -s GhostlockWireless` on the device is looking for.
 */
const val WIRELESS_TAG = "GhostlockWireless"

/**
 * One line naming [error] and the chain of causes behind it.
 *
 * A bare `simpleName` hides the interesting part (`AdbException` with the real message in its
 * cause), and a null message used to print as `error: null`.
 */
fun describeThrowable(error: Throwable?): String {
    if (error == null) return "原因不明"
    return buildString {
        append(error::class.java.simpleName)
        error.message?.let { append(": ").append(it) }
        var cause = error.cause
        var depth = 0
        while (cause != null && depth < 3 && cause !== error) {
            append(" <- ").append(cause::class.java.simpleName)
            cause.message?.let { append(": ").append(it) }
            cause = cause.cause
            depth++
        }
    }
}
