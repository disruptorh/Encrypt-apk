package com.reimen.cifra.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Robustez del parser del sobre frente a entradas adversariales:
 * JSON malformado, Base64 inválido, campos ausentes y parámetros fuera de rango.
 */
class EnvelopeTest {

    private fun validBlob(): String =
        CryptoEngine.encrypt(
            "x".toByteArray(), "pw".toCharArray(), null, CryptoEngine.KdfProfile(64, 2, 1, "Test")
        )

    @Test
    fun `roundtrip envelope`() {
        val e = Envelope(
            1, "argon2id", 64, 2, 1,
            ByteArray(16) { 1 }, ByteArray(12) { 2 }, ByteArray(32) { 3 }
        )
        val blob = Envelope.toBase64(e)
        val back = Envelope.fromBase64(blob)
        assertEquals(e.version, back.version)
        assertEquals(e.kdf, back.kdf)
        assertEquals(e.memKib, back.memKib)
        assertEquals(e.iterations, back.iterations)
        assertEquals(e.parallelism, back.parallelism)
        org.junit.Assert.assertArrayEquals(e.salt, back.salt)
        org.junit.Assert.assertArrayEquals(e.nonce, back.nonce)
        org.junit.Assert.assertArrayEquals(e.ciphertext, back.ciphertext)
    }

    @Test
    fun `output is url-safe base64 without padding`() {
        val blob = validBlob()
        assertTrue(blob.isNotBlank())
        assertFalse(blob.contains('='))
        assertFalse(blob.contains('+'))
        assertFalse(blob.contains('/'))
    }

    @Test
    fun `garbage base64 rejected`() {
        assertThrows(EnvelopeException::class.java) { Envelope.fromBase64("¡¡no-base64!!") }
    }

    @Test
    fun `non-json content rejected`() {
        val blob = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("esto no es json".toByteArray())
        assertThrows(EnvelopeException::class.java) { Envelope.fromBase64(blob) }
    }

    @Test
    fun `missing field rejected`() {
        val json = """{"v":1,"kdf":"argon2id"}"""
        val blob = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray())
        assertThrows(EnvelopeException::class.java) { Envelope.fromBase64(blob) }
    }

    @Test
    fun `unsupported version rejected`() {
        val json = """{"v":99,"kdf":"argon2id","mem_kib":64,"iters":2,"parallelism":1,
            "salt":"AAAAAAAAAAAAAAAAAAAAAA","nonce":"AAAAAAAAAAAAAAAAAA",
            "ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"""
        val blob = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray())
        val e = assertThrows(EnvelopeException::class.java) { Envelope.fromBase64(blob) }
        assertEquals(true, e.message!!.contains("Versión"))
    }

    @Test
    fun `unknown kdf rejected`() {
        val json = """{"v":1,"kdf":"scrypt","mem_kib":64,"iters":2,"parallelism":1,
            "salt":"AAAAAAAAAAAAAAAAAAAAAA","nonce":"AAAAAAAAAAAAAAAAAA",
            "ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"""
        val blob = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray())
        assertThrows(EnvelopeException::class.java) { Envelope.fromBase64(blob) }
    }

    @Test
    fun `params out of range rejected`() {
        // mem_kib = 0
        val json = """{"v":1,"kdf":"argon2id","mem_kib":0,"iters":2,"parallelism":1,
            "salt":"AAAAAAAAAAAAAAAAAAAAAA","nonce":"AAAAAAAAAAAAAAAAAA",
            "ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"""
        val blob = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray())
        assertThrows(EnvelopeException::class.java) { Envelope.fromBase64(blob) }
    }

    @Test
    fun `bad salt length rejected`() {
        // salt de 8 bytes (debe ser 16)
        val json = """{"v":1,"kdf":"argon2id","mem_kib":64,"iters":2,"parallelism":1,
            "salt":"AAAAAAAAAAA","nonce":"AAAAAAAAAAAAAAAAAA",
            "ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"""
        val blob = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray())
        assertThrows(EnvelopeException::class.java) { Envelope.fromBase64(blob) }
    }

    @Test
    fun `too short ciphertext rejected`() {
        // ciphertext de 8 bytes (menos que el tag GCM de 16)
        val json = """{"v":1,"kdf":"argon2id","mem_kib":64,"iters":2,"parallelism":1,
            "salt":"AAAAAAAAAAAAAAAAAAAAAA","nonce":"AAAAAAAAAAAAAAAAAA",
            "ciphertext":"AAAAAAAAAAA"}"""
        val blob = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray())
        assertThrows(EnvelopeException::class.java) { Envelope.fromBase64(blob) }
    }
}
