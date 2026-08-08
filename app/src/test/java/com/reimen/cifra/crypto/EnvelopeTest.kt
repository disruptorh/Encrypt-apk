package com.reimen.cifra.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Robustez del parser del sobre frente a entradas adversariales:
 * JSON malformado, Base64 inválido, campos ausentes/desconocidos y parámetros
 * fuera de rango.
 */
class EnvelopeTest {

    // Base64 URL-safe sin padding de N bytes a cero.
    private val salt16 = "AAAAAAAAAAAAAAAAAAAAAA" // 16 bytes
    private val nonce24 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 24 bytes
    private val cipher32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 32 bytes
    private val salt8 = "AAAAAAAAAAA" // 8 bytes
    private val nonce12 = "AAAAAAAAAAAAAAAA" // 12 bytes
    private val cipher8 = "AAAAAAAAAAA" // 8 bytes

    private fun b64(s: String): String =
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray())

    private fun validBlob(): String =
        CryptoEngine.encrypt(
            "x".toByteArray(), "pw".toCharArray(), null, CryptoEngine.KdfProfile(64, 2, "Test")
        )

    @Test
    fun `roundtrip envelope`() {
        val e = Envelope(
            1, Envelope.AEAD_NAME, Envelope.KDF_NAME, 2, 64,
            ByteArray(16) { 1 }, ByteArray(24) { 2 }, ByteArray(32) { 3 }
        )
        val blob = Envelope.toBase64(e)
        val back = Envelope.fromBase64(blob)
        assertEquals(e.version, back.version)
        assertEquals(e.aead, back.aead)
        assertEquals(e.kdf, back.kdf)
        assertEquals(e.ops, back.ops)
        assertEquals(e.memKib, back.memKib)
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
        val json = """{"v":1,"aead":"xchacha20poly1305_ietf","kdf":"argon2id"}"""
        assertThrows(EnvelopeException::class.java) { Envelope.fromBase64(b64(json)) }
    }

    @Test
    fun `unknown field rejected`() {
        val json = """{"v":1,"aead":"xchacha20poly1305_ietf","kdf":"argon2id","ops":2,"mem_kib":64,
            "salt":"$salt16","nonce":"$nonce24","ciphertext":"$cipher32","x":1}"""
        assertThrows(EnvelopeException::class.java) { Envelope.fromBase64(b64(json)) }
    }

    @Test
    fun `unsupported version rejected`() {
        val json = """{"v":99,"aead":"xchacha20poly1305_ietf","kdf":"argon2id","ops":2,"mem_kib":64,
            "salt":"$salt16","nonce":"$nonce24","ciphertext":"$cipher32"}"""
        val e = assertThrows(EnvelopeException::class.java) { Envelope.fromBase64(b64(json)) }
        assertEquals(true, e.message!!.contains("Versión"))
    }

    @Test
    fun `unknown aead rejected`() {
        val json = """{"v":1,"aead":"aes-256-gcm","kdf":"argon2id","ops":2,"mem_kib":64,
            "salt":"$salt16","nonce":"$nonce24","ciphertext":"$cipher32"}"""
        assertThrows(EnvelopeException::class.java) { Envelope.fromBase64(b64(json)) }
    }

    @Test
    fun `unknown kdf rejected`() {
        val json = """{"v":1,"aead":"xchacha20poly1305_ietf","kdf":"scrypt","ops":2,"mem_kib":64,
            "salt":"$salt16","nonce":"$nonce24","ciphertext":"$cipher32"}"""
        assertThrows(EnvelopeException::class.java) { Envelope.fromBase64(b64(json)) }
    }

    @Test
    fun `params out of range rejected`() {
        // mem_kib = 0
        val json = """{"v":1,"aead":"xchacha20poly1305_ietf","kdf":"argon2id","ops":2,"mem_kib":0,
            "salt":"$salt16","nonce":"$nonce24","ciphertext":"$cipher32"}"""
        assertThrows(EnvelopeException::class.java) { Envelope.fromBase64(b64(json)) }

        // ops = 0
        val json2 = """{"v":1,"aead":"xchacha20poly1305_ietf","kdf":"argon2id","ops":0,"mem_kib":64,
            "salt":"$salt16","nonce":"$nonce24","ciphertext":"$cipher32"}"""
        assertThrows(EnvelopeException::class.java) { Envelope.fromBase64(b64(json2)) }
    }

    @Test
    fun `bad salt length rejected`() {
        // salt de 8 bytes (debe ser 16)
        val json = """{"v":1,"aead":"xchacha20poly1305_ietf","kdf":"argon2id","ops":2,"mem_kib":64,
            "salt":"$salt8","nonce":"$nonce24","ciphertext":"$cipher32"}"""
        assertThrows(EnvelopeException::class.java) { Envelope.fromBase64(b64(json)) }
    }

    @Test
    fun `bad nonce length rejected`() {
        // nonce de 12 bytes (debe ser 24)
        val json = """{"v":1,"aead":"xchacha20poly1305_ietf","kdf":"argon2id","ops":2,"mem_kib":64,
            "salt":"$salt16","nonce":"$nonce12","ciphertext":"$cipher32"}"""
        assertThrows(EnvelopeException::class.java) { Envelope.fromBase64(b64(json)) }
    }

    @Test
    fun `too short ciphertext rejected`() {
        // ciphertext de 8 bytes (menos que el tag de 16)
        val json = """{"v":1,"aead":"xchacha20poly1305_ietf","kdf":"argon2id","ops":2,"mem_kib":64,
            "salt":"$salt16","nonce":"$nonce24","ciphertext":"$cipher8"}"""
        assertThrows(EnvelopeException::class.java) { Envelope.fromBase64(b64(json)) }
    }
}
