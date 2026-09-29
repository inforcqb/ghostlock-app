package com.ghostlock.app.adb

import android.util.Base64
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * The app's own ADB key pair, generated EARLY on purpose.
 *
 * Order matters: the public key is what has to be pushed to `/data/misc/adb/adb_keys`
 * once the uid-0 channel is up, so the key pair must exist before anything waits on that
 * channel -- otherwise there is nothing to push.
 *
 * [publicKeyLine] is exactly one line of `adb_keys`: base64 of Android's binary RSA
 * public key format plus a name. Pushing it is our equivalent of `adb pair`; the client
 * still has to answer adbd's AUTH challenge with a signature (libadb does that part).
 */
class AdbKey(val privateKey: PrivateKey, val publicKey: RSAPublicKey) {

    /** One line, exactly as it must appear in `/data/misc/adb/adb_keys`. */
    val publicKeyLine: String
        get() = Base64.encodeToString(encode(publicKey), Base64.NO_WRAP) + " " + NAME

    /** Short fingerprint of the public key, used to keep the push idempotent. */
    val fingerprint: String
        get() = Base64.encodeToString(
            MessageDigest.getInstance("SHA-256").digest(publicKey.encoded),
            Base64.NO_WRAP,
        ).take(16)

    companion object {
        const val NAME = "ghostlock@localhost"

        private const val PRIVATE_FILE = "adbkey.pk8"
        private const val PUBLIC_FILE = "adbkey.pub.der"
        private const val MODULUS_BYTES = 256
        private const val MODULUS_WORDS = MODULUS_BYTES / 4

        @Volatile
        private var cached: AdbKey? = null

        /** Load the stored key pair, generating it on first use. */
        fun load(dir: File): AdbKey = synchronized(this) {
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
            key
        }

        /**
         * Android's binary RSA public key format (`RSAPublicKey` in AOSP's adb):
         *
         *     u32 modulus_size_words;      // 64 for a 2048-bit key
         *     u32 n0inv;                   // -1 / n[0] mod 2^32
         *     u8  modulus[256];            // little-endian
         *     u8  rr[256];                 // R^2 mod n, little-endian, R = 2^2048
         *     u32 exponent;                // little-endian
         *
         * libadb exposes an encoder for this, but its class is package-private, so the
         * 524 bytes are built here. `adb_keys` stores base64 of exactly this blob.
         */
        fun encode(key: RSAPublicKey): ByteArray {
            val modulus = key.modulus
            val two32 = BigInteger.ONE.shiftLeft(32)
            val n0inv = modulus.and(two32.subtract(BigInteger.ONE)).modInverse(two32)
                .negate().mod(two32)
            val rr = BigInteger.ONE.shiftLeft(4096).mod(modulus)
            val out = ByteArray(4 + 4 + MODULUS_BYTES + MODULUS_BYTES + 4)
            var offset = 0

            fun putU32(value: Long) {
                out[offset++] = (value and 0xff).toByte()
                out[offset++] = ((value shr 8) and 0xff).toByte()
                out[offset++] = ((value shr 16) and 0xff).toByte()
                out[offset++] = ((value shr 24) and 0xff).toByte()
            }

            fun putLittleEndian(value: BigInteger) {
                val bytes = value.toByteArray()
                val usable = minOf(bytes.size, MODULUS_BYTES)
                for (i in 0 until usable) {
                    out[offset + i] = bytes[bytes.size - 1 - i]
                }
                offset += MODULUS_BYTES
            }

            putU32(MODULUS_WORDS.toLong())
            putU32(n0inv.toLong())
            putLittleEndian(modulus)
            putLittleEndian(rr)
            putU32(key.publicExponent.toLong())
            return out
        }
    }
}