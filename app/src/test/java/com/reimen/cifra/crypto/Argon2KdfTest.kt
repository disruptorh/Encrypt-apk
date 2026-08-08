package com.reimen.cifra.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Valida Argon2Kdf y BLAKE2b contra vectores generados con libsodium
 * (el lado C++): mismo Argon2id (p=1) y misma cadena de pepper por BLAKE2b.
 * Si estos vectores cuadran, la clave derivada en Android es idéntica a la de C++.
 */
class Argon2KdfTest {

    private fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0)
        return ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }

    private fun salt12(): ByteArray = ByteArray(16) { i -> (i + 1).toByte() }

    @Test
    fun `argon2id matches libsodium no pepper`() {
        val key = Argon2Kdf.deriveKey("sup3r-secreto".toCharArray(), ByteArray(16) { 0x07 }, null, 64, 2, 1)
        assertArrayEquals(
            hexToBytes("158436f68c0df14fd56aedc3df78cc98c2107c2d9379ce38e6b76eba4f732de5"),
            key
        )
    }

    @Test
    fun `argon2id with pepper matches libsodium blake2b binding`() {
        val pepper = "pepper-de-verificación".toByteArray(Charsets.UTF_8)
        val key = Argon2Kdf.deriveKey("sup3r-secreto".toCharArray(), salt12(), pepper, 64, 2, 1)
        assertArrayEquals(
            hexToBytes("8a725815348ebc5ee1347c570a15b4c0e86483c05f05d6e960001734e7636c09"),
            key
        )
    }

    @Test
    fun `standard profile matches libsodium`() {
        val key = Argon2Kdf.deriveKey("sup3r-secreto".toCharArray(), salt12(), null, 65536, 3, 1)
        assertArrayEquals(
            hexToBytes("2c77f84b160f4139539bf50d09e9474c4ffeeac2b1171d9db1c469fdc4dc35f4"),
            key
        )
    }

    @Test
    fun `blake2b unkeyed matches libsodium`() {
        assertArrayEquals(
            hexToBytes("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"),
            Blake2b.hash("abc".toByteArray())
        )
    }

    @Test
    fun `blake2b keyed matches libsodium`() {
        val key = ByteArray(32) { 0x11 }
        assertArrayEquals(
            hexToBytes("6dd3e15acd731e4db8203560adc0dab65c5465703583ac780772ac3c66e41c23"),
            Blake2b.hash("keyed message".toByteArray(), key)
        )
    }

    @Test
    fun `blake2b keyed empty matches libsodium`() {
        val key = ByteArray(32) { 0x11 }
        assertArrayEquals(
            hexToBytes("3f48d440bb4ef0d944ebfc4b0be97c8279506247e883034dc18debd51f5cb0d1"),
            Blake2b.hash(ByteArray(0), key)
        )
    }

    @Test
    fun `blake2b multi block matches libsodium`() {
        val data = ByteArray(150) { i -> (i * 3 + 1).toByte() }
        assertArrayEquals(
            hexToBytes("481ad2f257155f7f913bff5e97bb3b9f1a08ca7c9125c47f32d6751ff9ac4cfc"),
            Blake2b.hash(data)
        )
    }

    @Test
    fun `blake2b keyed full block matches libsodium`() {
        val key = ByteArray(32) { 0x11 }
        val data = ByteArray(128) { i -> i.toByte() }
        assertArrayEquals(
            hexToBytes("78de0da2faf62b45e5cef3306b4620caf19b8f3848197d4fdde86c0255bf946e"),
            Blake2b.hash(data, key)
        )
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
        assertFalse("con pepper debe diferir de sin pepper", with.contentEquals(without))

        val emptyPepper = Argon2Kdf.deriveKey(password, salt, ByteArray(0), 64, 2, 1)
        assertTrue(
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
