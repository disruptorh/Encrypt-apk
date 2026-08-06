package com.reimen.cifra.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Round-trip cifrar→descifrar para múltiples tamaños, y negativos
 * (contraseña/pepper incorrectos, ciphertext corrupto).
 *
 * Se usa un perfil liviano (64 KiB / t=2 / p=1) para que los tests sean rápidos.
 */
class CryptoEngineTest {

    private val fastProfile = CryptoEngine.KdfProfile(64, 2, 1, "Test")

    private fun encrypt(pw: String, pepper: String? = null, data: String = "hola"): String =
        CryptoEngine.encrypt(
            data.toByteArray(Charsets.UTF_8),
            pw.toCharArray(),
            pepper?.toCharArray(),
            fastProfile
        )

    private fun decrypt(blob: String, pw: String, pepper: String? = null): String =
        String(CryptoEngine.decrypt(blob, pw.toCharArray(), pepper?.toCharArray()), Charsets.UTF_8)

    @Test
    fun `roundtrip empty text`() {
        val blob = CryptoEngine.encrypt(ByteArray(0), "pw".toCharArray(), null, fastProfile)
        val out = CryptoEngine.decrypt(blob, "pw".toCharArray(), null)
        assertTrue(out.isEmpty())
    }

    @Test
    fun `roundtrip single char`() {
        assertEquals("x", decrypt(encrypt("pw", data = "x"), "pw"))
    }

    @Test
    fun `roundtrip 10KB`() {
        val big = "A".repeat(10_000)
        assertEquals(big, decrypt(encrypt("pw", data = big), "pw"))
    }

    @Test
    fun `roundtrip utf8 emojis`() {
        val emojis = "Héllo wörld 🌍 🔐 ñ ñandú 中文"
        assertEquals(emojis, decrypt(encrypt("pw", data = emojis), "pw"))
    }

    @Test
    fun `roundtrip with pepper`() {
        val data = "mensaje super secreto"
        val blob = CryptoEngine.encrypt(data.toByteArray(), "pw".toCharArray(), "pep".toCharArray(), fastProfile)
        assertEquals(data, decrypt(blob, "pw", "pep"))
    }

    @Test
    fun `wrong password fails cleanly`() {
        val blob = encrypt("correcta")
        assertThrows(CryptoEngine.CryptoException::class.java) {
            decrypt(blob, "incorrecta")
        }
    }

    @Test
    fun `wrong pepper fails cleanly`() {
        val blob = CryptoEngine.encrypt("m".toByteArray(), "pw".toCharArray(), "real".toCharArray(), fastProfile)
        val e = assertThrows(CryptoEngine.CryptoException::class.java) {
            decrypt(blob, "pw", "falso")
        }
        assertTrue(e.message!!.contains("contraseña", ignoreCase = true) ||
            e.message!!.contains("secreto", ignoreCase = true) ||
            e.message!!.contains("autenticación", ignoreCase = true))
    }

    @Test
    fun `missing pepper fails when one was used`() {
        val blob = CryptoEngine.encrypt("m".toByteArray(), "pw".toCharArray(), "real".toCharArray(), fastProfile)
        assertThrows(CryptoEngine.CryptoException::class.java) {
            decrypt(blob, "pw", null)
        }
    }

    @Test
    fun `corrupted ciphertext fails`() {
        val blob = encrypt("pw", data = "dato a proteger")
        val envelope = Envelope.fromBase64(blob)
        val tampered = envelope.copy(ciphertext = envelope.ciphertext.copyOf().also { it[0] = (it[0] + 1).toByte() })
        val tamperedBlob = Envelope.toBase64(tampered)
        assertThrows(CryptoEngine.CryptoException::class.java) {
            decrypt(tamperedBlob, "pw")
        }
    }

    @Test
    fun `encrypt produces unique nonce each time`() {
        val a = encrypt("pw", data = "mismo")
        val b = encrypt("pw", data = "mismo")
        assertNotEquals("dos cifrados del mismo texto no deben coincidir", a, b)
    }

    @Test
    fun `envelope carries kdf parameters`() {
        val blob = CryptoEngine.encrypt(
            "data".toByteArray(Charsets.UTF_8), "pw".toCharArray(), null, CryptoEngine.KdfProfile.STANDARD
        )
        val envelope = Envelope.fromBase64(blob)
        assertEquals(Envelope.KDF_NAME, envelope.kdf)
        assertEquals(CryptoEngine.KdfProfile.STANDARD.memKib, envelope.memKib)
        assertEquals(CryptoEngine.KdfProfile.STANDARD.iterations, envelope.iterations)
        assertEquals(CryptoEngine.KdfProfile.STANDARD.parallelism, envelope.parallelism)
        assertEquals(16, envelope.salt.size)
        assertEquals(12, envelope.nonce.size)
    }

    @Test
    fun `maximum profile still decrypts`() {
        val blob = CryptoEngine.encrypt("d".toByteArray(), "pw".toCharArray(), null, CryptoEngine.KdfProfile.MAXIMUM)
        assertFalse(blob.isBlank())
    }

    @Test
    fun `empty password rejected on encrypt`() {
        assertThrows(CryptoEngine.CryptoException::class.java) {
            CryptoEngine.encrypt("d".toByteArray(), CharArray(0), null, fastProfile)
        }
    }

    @Test
    fun `empty password rejected on decrypt`() {
        assertThrows(CryptoEngine.CryptoException::class.java) {
            CryptoEngine.decrypt("eyJ2IjoxfQ", CharArray(0), null)
        }
    }

    @Test
    fun `blank blob rejected`() {
        assertThrows(CryptoEngine.CryptoException::class.java) {
            CryptoEngine.decrypt("   ", "pw".toCharArray(), null)
        }
    }

    @Test
    fun `memory budget allows small input`() {
        assertTrue(CryptoEngine.checkSizeBudget(64, 10_000L))
    }

    @Test
    fun `memory budget rejects oversized input with maximum profile`() {
        assertFalse(CryptoEngine.checkSizeBudget(CryptoEngine.KdfProfile.MAXIMUM.memKib, Long.MAX_VALUE / 10))
    }
}
