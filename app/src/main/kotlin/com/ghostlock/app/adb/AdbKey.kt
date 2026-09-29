package com.ghostlock.app.adb

import android.util.Base64
import io.github.muntashirakon.adb.AndroidPubkey
import java.io.File
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.security.KeyPairGenerator

/**
 * The app's own ADB key pair, generated early on purpose.
 *
 * The order matters: the public key is what has to be pushed to
 * `/data/misc/adb/adb_keys` once the uid-0 channel is up, so the key pair must exist
 * BEFORE anything waits on that channel -- otherwise there is nothing to push.
 *
 * `publicKeyLine()` is the exact content of one `adb_keys` line: base64 of Android's
 * binary RSA public key format (produced by libadb's [AndroidPubkey], so that the
 * struct -- n0inv, little-endian modulus, rr = R^2 mod n, exponent -- is not hand-rolled)
 * followed by a name. Pushing this line is our equivalent of `adb pair`.
 */
class AdbKey(val privateKey: PrivateKey, val publicKey: RSAPublicKey) {

    /** One line, exactly as it must appear in `/data/misc/adb/adb_keys`. */
    val publicKeyLine: String
        get() = Base64.encodeToString(AndroidPubkey.encode(publicKey), Base64.NO_WRAP) +
            " " + NAME

    /** A short, stable fingerprint used to keep the push idempotent. */
    val fingerprint: String
        get() = Base64.encodeToString(
            java.security.MessageDigest.getInstance("SHA-256").digest(publicKey.encoded),
            Base64.NO_WRAP,
        ).take(16)

    companion object {
        const val NAME = "ghostlock@localhost"
        private const val PRIVATE_FILE = "adbkey.pk8"
        private const val PUBLIC_FILE = "adbkey.pub.der"

        @Volatile
        private var cached: AdbKey? = null

        /** Load the stored key pair, generating it on first use. */
        @Synchronized
        fun load(dir: File): AdbKey {
            cached?.let { return it }
            val privateFile = File(dir, PRIVATE_FILE)
            val publicFile = File(dir, PUBLIC_FILE)
            val key = if (privateFile.isFile && privateFile.length() > 0L &&
                publicFile.isFile && publicFile.length() > 0L
            ) {
                val factory = KeyFactory.getInstance("RSA")
                AdbKey(
                    factory.generatePrivate(PKCS8EncodedKeySpec(privateFile.readBytes())),
                    factory.generatePublic(X509EncodedKeySpec(publicFile.readBytes())) as RSAPublicKey,
                )
            } else {
                val generator = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
                val pair = generator.generateKeyPair()
                privateFile.writeBytes(pair.private.encoded)
                publicFile.writeBytes(pair.public.encoded)
                AdbKey(pair.private, pair.public as RSAPublicKey)
            }
            cached = key
            return key
        }
    }
}