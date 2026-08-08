package com.reimen.cifra.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Valida HChaCha20 y XChaCha20-Poly1305 contra vectores generados con
 * libsodium (el lado C++): nonce de 24 bytes, tag de 16 al final.
 */
class XChaCha20Poly1305Test {

    private fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0)
        return ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    @Test
    fun `hchacha20 matches libsodium crypto_core_hchacha20`() {
        val key = ByteArray(32) { it.toByte() }
        val input = ByteArray(16) { (0x10 + it).toByte() }
        val out = XChaCha20Poly1305.hChaCha20(key, input)
        assertArrayEquals(
            hexToBytes("0bde6e74ec830a779b754eec40483c2c3dda34a9267b79b25ac58f5b2e114251"),
            out
        )
    }

    @Test
    fun `encrypt matches libsodium xchacha20poly1305_ietf`() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(24) { it.toByte() }
        val aad = "1|xchacha20poly1305_ietf|argon2id|3|65536".toByteArray(Charsets.US_ASCII)
        val plaintext = "Vector de interoperabilidad XChaCha20-Poly1305".toByteArray(Charsets.UTF_8)

        val ct = XChaCha20Poly1305.encrypt(key, nonce, aad, plaintext)
        assertArrayEquals(
            hexToBytes("c8a76c0bffa0adca56644fa0bf37da873b225ac49fbf71821b7b5b9665ee9d381d6ed7d6714a590bb9ec9f6aff14d3ccb9b9a00648b05c3a1d85c2a8be8d"),
            ct
        )
    }

    @Test
    fun `decrypt recovers the plaintext and rejects tampering`() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(24) { it.toByte() }
        val aad = "1|xchacha20poly1305_ietf|argon2id|3|65536".toByteArray(Charsets.US_ASCII)
        val plaintext = "Vector de interoperabilidad XChaCha20-Poly1305".toByteArray(Charsets.UTF_8)

        val ct = XChaCha20Poly1305.encrypt(key, nonce, aad, plaintext)
        val back = XChaCha20Poly1305.decrypt(key, nonce, aad, ct)
        assertArrayEquals(plaintext, back)

        val tampered = ct.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertThrows(AeadAuthException::class.java) {
            XChaCha20Poly1305.decrypt(key, nonce, aad, tampered)
        }
    }

    @Test
    fun `encrypt empty message still yields a 16 byte tag`() {
        val key = ByteArray(32) { 7 }
        val nonce = ByteArray(24) { 9 }
        val ct = XChaCha20Poly1305.encrypt(key, nonce, ByteArray(0), ByteArray(0))
        assertEquals(16, ct.size)
        val back = XChaCha20Poly1305.decrypt(key, nonce, ByteArray(0), ct)
        assertEquals(0, back.size)
    }

    @Test
    fun `wrong aad fails authentication`() {
        val key = ByteArray(32) { 3 }
        val nonce = ByteArray(24) { 5 }
        val ct = XChaCha20Poly1305.encrypt(key, nonce, "aad-a".toByteArray(), "m".toByteArray())
        assertThrows(AeadAuthException::class.java) {
            XChaCha20Poly1305.decrypt(key, nonce, "aad-b".toByteArray(), ct)
        }
    }

    @Test
    fun `hex helper sanity`() {
        assertEquals("00ff10", hex(byteArrayOf(0x00, 0xff.toByte(), 0x10)))
    }
}
