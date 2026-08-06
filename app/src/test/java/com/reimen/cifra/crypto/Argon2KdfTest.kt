package com.reimen.cifra.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Valida Argon2Kdf contra los vectores de prueba oficiales del RFC 9106
 * (Apéndice A.3, Argon2id, versión 0x13) antes de confiar en la implementación.
 */
class Argon2KdfTest {

    private fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0)
        return ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }

    @Test
    fun `argon2id rfc9106 vector with secret and ad`() {
        // RFC 9106 A.3: password 32x0x01, salt 16x0x02, secret 8x0x03, ad 12x0x04
        val password = CharArray(32) { 0x01.toChar() }
        val salt = ByteArray(16) { 0x02 }
        val pepper = ByteArray(8) { 0x03 }
        val additional = ByteArray(12) { 0x04 }

        val key = Argon2Kdf.deriveKey(
            password = password,
            salt = salt,
            pepper = pepper,
            memKib = 32,
            iterations = 3,
            parallelism = 4,
            additional = additional
        )

        val expected = hexToBytes(
            "0d640df58d78766c08c037a34a8b53c9" +
                "d01ef0452d75b65eb52520e96b01e659"
        )
        assertArrayEquals(expected, key)
    }

    @Test
    fun `same inputs produce same key`() {
        val password = "sup3r-secreto".toCharArray()
        val salt = ByteArray(16) { 7 }
        val a = Argon2Kdf.deriveKey(password, salt, null, 64, 2, 1)
        val b = Argon2Kdf.deriveKey(password, salt, null, 64, 2, 1)
        assertArrayEquals(a, b)
    }

    @Test
    fun `different pepper produces different key`() {
        val password = "clave".toCharArray()
        val salt = ByteArray(16) { 9 }
        val with = Argon2Kdf.deriveKey(password, salt, ByteArray(4) { 1 }, 64, 2, 1)
        val without = Argon2Kdf.deriveKey(password, salt, null, 64, 2, 1)
        org.junit.Assert.assertFalse("con pepper debe diferir de sin pepper", with.contentEquals(without))

        val emptyPepper = Argon2Kdf.deriveKey(password, salt, ByteArray(0), 64, 2, 1)
        org.junit.Assert.assertTrue(
            "pepper vacío debe equivaler a null",
            without.contentEquals(emptyPepper)
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `invalid memory rejected`() {
        Argon2Kdf.deriveKey("x".toCharArray(), ByteArray(16), null, 0, 2, 1)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `invalid parallelism rejected`() {
        Argon2Kdf.deriveKey("x".toCharArray(), ByteArray(16), null, 64, 2, 0)
    }

    @Test
    fun `key length is 32 bytes`() {
        val key = Argon2Kdf.deriveKey("k".toCharArray(), ByteArray(16) { 3 }, null, 64, 2, 1)
        assertEquals(32, key.size)
    }
}
