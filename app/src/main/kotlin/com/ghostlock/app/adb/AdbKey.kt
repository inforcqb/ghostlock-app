package com.ghostlock.app.adb

import android.sun.security.x509.AlgorithmId
import android.sun.security.x509.CertificateAlgorithmId
import android.sun.security.x509.CertificateIssuerName
import android.sun.security.x509.CertificateSerialNumber
import android.sun.security.x509.CertificateSubjectName
import android.sun.security.x509.CertificateValidity
import android.sun.security.x509.CertificateVersion
import android.sun.security.x509.CertificateX509Key
import android.sun.security.x509.X500Name
import android.sun.security.x509.X509CertImpl
import android.sun.security.x509.X509CertInfo
import android.util.Base64
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.util.Date
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
class AdbKey(
    val privateKey: PrivateKey,
    val publicKey: RSAPublicKey,
    val certificate: Certificate,
) {

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
        private const val CERT_FILE = "adbkey.cert.der"
        private const val MODULUS_BYTES = 256
        private const val MODULUS_WORDS = MODULUS_BYTES / 4
        private const val VALIDITY_MS = 3650L * 24 * 60 * 60 * 1000
        private const val ALGORITHM = "SHA1withRSA"

        @Volatile
        private var cached: AdbKey? = null

        /** Load the stored key pair, generating it on first use. */
        fun load(dir: File): AdbKey = synchronized(this) {
            cached?.let { return it }
            val privateFile = File(dir, PRIVATE_FILE)
            val publicFile = File(dir, PUBLIC_FILE)
            val certFile = File(dir, CERT_FILE)
            val key = if (privateFile.isFile && privateFile.length() > 0L &&
                publicFile.isFile && publicFile.length() > 0L &&
                certFile.isFile && certFile.length() > 0L
            ) {
                val factory = KeyFactory.getInstance("RSA")
                AdbKey(
                    factory.generatePrivate(PKCS8EncodedKeySpec(privateFile.readBytes())),
                    factory.generatePublic(X509EncodedKeySpec(publicFile.readBytes())) as RSAPublicKey,
                    readCertificate(certFile),
                )
            } else {
                val generator = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
                val pair = generator.generateKeyPair()
                privateFile.writeBytes(pair.private.encoded)
                publicFile.writeBytes(pair.public.encoded)
                val certificate = generateCertificate(pair.private, pair.public)
                certFile.writeBytes(certificate.encoded)
                AdbKey(pair.private, pair.public as RSAPublicKey, certificate)
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
        private fun readCertificate(file: File): Certificate =
            CertificateFactory.getInstance("X.509").generateCertificate(file.inputStream())

        /**
         * A self-signed certificate for our adb key.
         *
         * libadb refuses to connect unless the connection carries both a private key and a
         * certificate; the certificate itself is only used for the wireless-pairing TLS
         * handshake, which we do not use (we authorize by writing the public key into
         * /data/misc/adb/adb_keys). Any valid self-signed certificate will do, and it is
         * created once, together with the key.
         */
        private fun generateCertificate(privateKey: PrivateKey, publicKey: PublicKey): Certificate {
            val info = X509CertInfo()
            val subject = X500Name("CN=" + NAME)
            info.set(
                X509CertInfo.VALIDITY,
                CertificateValidity(Date(), Date(System.currentTimeMillis() + VALIDITY_MS)),
            )
            info.set(X509CertInfo.SERIAL_NUMBER, CertificateSerialNumber(BigInteger(64, SecureRandom())))
            info.set(X509CertInfo.SUBJECT, CertificateSubjectName(subject))
            info.set(X509CertInfo.ISSUER, CertificateIssuerName(subject))
            info.set(X509CertInfo.KEY, CertificateX509Key(publicKey))
            info.set(X509CertInfo.VERSION, CertificateVersion(CertificateVersion.V3))
            info.set(
                X509CertInfo.ALGORITHM_ID,
                CertificateAlgorithmId(AlgorithmId(AlgorithmId.sha1WithRSAEncryption_oid)),
            )
            val certificate = X509CertImpl(info)
            certificate.sign(privateKey, ALGORITHM)
            return certificate
        }
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