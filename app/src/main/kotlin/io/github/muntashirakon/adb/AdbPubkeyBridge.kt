package io.github.muntashirakon.adb

import java.security.interfaces.RSAPublicKey

/**
 * Bridge into the library's own package.
 *
 * `AndroidPubkey` is package-private, so only a class in this exact package may call it --
 * which is precisely why this file exists here instead of in the app's own package.
 * Hand-rolling AOSP's 524-byte `RSAPublicKey` structure (n0inv, little-endian modulus,
 * rr = R^2 mod n, exponent) is a needless risk: one wrong byte and adbd rejects the
 * client's AUTH signature, which shows up only as "Unable to establish a new connection".
 */
object AdbPubkeyBridge {
    /** One `adb_keys` line: base64 of Android's binary RSA public key format + name. */
    fun line(publicKey: RSAPublicKey, name: String): String {
        val raw: Any? = AndroidPubkey.encodeWithName(publicKey, name)
        return when (raw) {
            is String -> raw.trim()
            is ByteArray -> String(raw, Charsets.UTF_8).trim()
            else -> error("unexpected AndroidPubkey.encodeWithName result: $raw")
        }
    }
}