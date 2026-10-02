package com.reimen.cifra.crypto

import org.bouncycastle.crypto.modes.ChaCha20Poly1305 as BcChaCha20Poly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.Random

/**
 * La API de streaming de XChaCha20-Poly1305 tiene que dar exactamente lo mismo
 * que la versión de una pasada, que a su vez está anclada al vector de libsodium
 * y a los blobs del lado C++. Aquí se comprueba que trocear no cambia ni un
 * byte, incluidos los trocees que parten bloques de 64 de ChaCha20 y de 16 de
 * Poly1305 por la mitad.
 */
class XChaCha20Poly1305StreamingTest {

    private fun bytes(n: Int, seed: Long = 1) =
        ByteArray(n).also { Random(seed).nextBytes(it) }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    /** Cifra en streaming con el troceo indicado; el tag va detrás del ciphertext. */
    private fun encryptInChunks(key: ByteArray, nonce: ByteArray, aad: ByteArray, pt: ByteArray, chunk: Int): ByteArray {
        val body = ByteArrayOutputStream()
        val buf = ByteArray(chunk)
        val enc = XChaCha20Poly1305.Encryptor(key, nonce, aad)
        var off = 0
        while (off < pt.size) {
            val n = minOf(chunk, pt.size - off)
            enc.update(pt, off, n, buf, 0)
            body.write(buf, 0, n)
            off += n
        }
        val out = body.toByteArray()
        val full = out + ByteArray(XChaCha20Poly1305.TAG_BYTES)
        enc.finish(full, out.size)
        enc.close()
        return full
    }

    private fun decryptInChunks(key: ByteArray, nonce: ByteArray, aad: ByteArray, ct: ByteArray, chunk: Int): ByteArray {
        val bodyLen = ct.size - XChaCha20Poly1305.TAG_BYTES
        val out = ByteArray(bodyLen)
        val buf = ByteArray(chunk)
        val dec = XChaCha20Poly1305.Decryptor(key, nonce, aad)
        var off = 0
        while (off < bodyLen) {
            val n = minOf(chunk, bodyLen - off)
            dec.update(ct, off, n, buf, 0)
            System.arraycopy(buf, 0, out, off, n)
            off += n
        }
        dec.finish(ct, bodyLen)
        dec.close()
        return out
    }

    private fun bcEncrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, pt: ByteArray): ByteArray {
        val subkey = XChaCha20Poly1305.deriveSubkey(key, nonce)
        val nonce2 = XChaCha20Poly1305.deriveNonce(nonce)
        val c = BcChaCha20Poly1305()
        c.init(true, ParametersWithIV(KeyParameter(subkey), nonce2))
        c.processAADBytes(aad, 0, aad.size)
        val out = ByteArray(pt.size + XChaCha20Poly1305.TAG_BYTES)
        var n = c.processBytes(pt, 0, pt.size, out, 0)
        n += c.doFinal(out, n)
        return out.copyOf(n)
    }

    /** Todos los tamaños queinterestan: 1, los que no alinean con 16 ni con 64, y el propio. */
    private val chunkSizes = listOf(1, 3, 7, 15, 16, 17, 31, 63, 64, 65, 100, 1000)

    @Test
    fun `streaming encryption is byte identical to bouncy castle for every chunk size`() {
        val key = bytes(32, 2)
        val nonce = bytes(24, 3)
        for (aadLen in listOf(0, 1, 15, 16, 17, 35, 64, 65)) {
            for (ptLen in listOf(0, 1, 15, 16, 17, 31, 63, 64, 65, 200)) {
                val aad = bytes(aadLen, 4)
                val pt = bytes(ptLen, 5)
                val expected = bcEncrypt(key, nonce, aad, pt)
                for (chunk in chunkSizes) {
                    val actual = encryptInChunks(key, nonce, aad, pt, chunk)
                    assertArrayEquals(
                        "BC difiere con chunk=$chunk aad=$aadLen pt=$ptLen",
                        expected,
                        actual,
                    )
                }
            }
        }
    }

    @Test
    fun `streaming decryption returns the plaintext for every chunk size`() {
        val key = bytes(32, 6)
        val nonce = bytes(24, 7)
        for (ptLen in listOf(0, 1, 15, 16, 17, 31, 63, 64, 65, 200, 5000)) {
            val aad = bytes(ptLen % 40, 8)
            val pt = bytes(ptLen, 9)
            val ct = XChaCha20Poly1305.encrypt(key, nonce, aad, pt)
            for (chunk in chunkSizes) {
                assertArrayEquals(
                    "ida y vuelta falla con chunk=$chunk ptLen=$ptLen",
                    pt,
                    decryptInChunks(key, nonce, aad, ct, chunk),
                )
            }
        }
    }

    @Test
    fun `one-shot and streaming agree with the libsodium vector`() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(24) { it.toByte() }
        val aad = "1|xchacha20poly1305_ietf|argon2id|3|65536".toByteArray(Charsets.US_ASCII)
        val pt = "Vector de interoperabilidad XChaCha20-Poly1305".toByteArray(Charsets.UTF_8)
        val expected = "c8a76c0bffa0adca56644fa0bf37da873b225ac49fbf71821b7b5b9665ee9d38" +
            "1d6ed7d6714a590bb9ec9f6aff14d3ccb9b9a00648b05c3a1d85c2a8be8d"
        assertEquals(expected, hex(encryptInChunks(key, nonce, aad, pt, 7)))
        assertEquals(expected, hex(XChaCha20Poly1305.encrypt(key, nonce, aad, pt)))
    }

    @Test
    fun `tampering anywhere in the ciphertext or the tag is rejected`() {
        val key = bytes(32, 10)
        val nonce = bytes(24, 11)
        val aad = bytes(35, 12)
        val pt = bytes(300, 13)
        val ct = XChaCha20Poly1305.encrypt(key, nonce, aad, pt)
        for (i in ct.indices) {
            val bad = ct.copyOf().also { it[i] = (it[i].toInt() xor 0x40).toByte() }
            assertThrows("el índice $i debería rechazarse", AeadAuthException::class.java) {
                XChaCha20Poly1305.decrypt(key, nonce, aad, bad)
            }
        }
    }

    @Test
    fun `wrong aad nonce or key is rejected`() {
        val key = bytes(32, 14)
        val nonce = bytes(24, 15)
        val aad = bytes(20, 16)
        val ct = XChaCha20Poly1305.encrypt(key, nonce, aad, bytes(64, 17))
        assertThrows(AeadAuthException::class.java) {
            XChaCha20Poly1305.decrypt(key, nonce, bytes(20, 18), ct)
        }
        assertThrows(AeadAuthException::class.java) {
            XChaCha20Poly1305.decrypt(key, bytes(24, 19), aad, ct)
        }
        assertThrows(AeadAuthException::class.java) {
            XChaCha20Poly1305.decrypt(bytes(32, 20), nonce, aad, ct)
        }
    }

    /**
     * [decryptToVerified] retiene la cola del plaintext: si el tag falla, lo
     * escrito en [out] se queda en `len - TAG_BYTES`, es decir, nunca llega a
     * existir el último bloque descifrado sin autenticar.
     */
    @Test
    fun `decryptToVerified withholds the tail until the tag checks out`() {
        val key = bytes(32, 21)
        val nonce = bytes(24, 22)
        val aad = bytes(35, 23)
        val pt = bytes(1000, 24)
        val ct = XChaCha20Poly1305.encrypt(key, nonce, aad, pt)
        val bodyLen = ct.size - XChaCha20Poly1305.TAG_BYTES

        // Camino bueno: llega todo.
        val out = ByteArray(bodyLen)
        val n = XChaCha20Poly1305.decryptToVerified(key, nonce, aad, ct, 0, ct.size, out, 0)
        assertEquals(bodyLen, n)
        assertArrayEquals(pt, out)

        // Camino malo: el tag no verifica y la cola nunca se escribe.
        val bad = ct.copyOf().also { it[bodyLen] = (it[bodyLen].toInt() xor 1).toByte() }
        val out2 = ByteArray(bodyLen)
        assertThrows(AeadAuthException::class.java) {
            XChaCha20Poly1305.decryptToVerified(key, nonce, aad, bad, 0, bad.size, out2, 0)
        }
        val written = bodyLen - XChaCha20Poly1305.TAG_BYTES
        assertArrayEquals("lo no verificado debe ser un prefijo del plaintext", pt.copyOf(written), out2.copyOf(written))
        assertTrue(
            "la cola retenida debe seguir a cero",
            out2.copyOfRange(written, bodyLen).all { it == 0.toByte() },
        )
    }

    @Test
    fun `ciphertext shorter than the tag is rejected before touching the mac`() {
        val key = bytes(32, 25)
        val nonce = bytes(24, 26)
        assertThrows(AeadAuthException::class.java) {
            XChaCha20Poly1305.decrypt(key, nonce, ByteArray(0), ByteArray(15))
        }
        assertThrows(AeadAuthException::class.java) {
            XChaCha20Poly1305.decrypt(key, nonce, ByteArray(0), ByteArray(0))
        }
    }

    @Test
    fun `state is unusable after finish and close`() {
        val key = bytes(32, 27)
        val nonce = bytes(24, 28)
        val aad = ByteArray(8)
        val pt = bytes(100, 29)

        val enc = XChaCha20Poly1305.Encryptor(key, nonce, aad)
        enc.update(pt, 0, pt.size, ByteArray(100), 0)
        enc.finish(ByteArray(16))
        assertThrows(IllegalStateException::class.java) { enc.finish(ByteArray(16)) }
        assertThrows(IllegalStateException::class.java) { enc.update(pt, 0, 1, ByteArray(1), 0) }

        val ct = XChaCha20Poly1305.encrypt(key, nonce, aad, pt)
        val bodyLen = ct.size - XChaCha20Poly1305.TAG_BYTES
        val dec = XChaCha20Poly1305.Decryptor(key, nonce, aad)
        dec.update(ct, 0, bodyLen, ByteArray(bodyLen), 0)
        dec.finish(ct, bodyLen)
        assertThrows(IllegalStateException::class.java) { dec.finish(ct, bodyLen) }
        assertThrows(IllegalStateException::class.java) { dec.update(ct, 0, 1, ByteArray(1), 0) }
    }

    @Test
    fun `update rejects ranges that do not fit`() {
        val key = bytes(32, 30)
        val nonce = bytes(24, 31)
        val enc = XChaCha20Poly1305.Encryptor(key, nonce, ByteArray(0))
        assertThrows(IllegalArgumentException::class.java) { enc.update(ByteArray(10), 5, 10, ByteArray(10), 0) }
        assertThrows(IllegalArgumentException::class.java) { enc.update(ByteArray(10), 0, 5, ByteArray(4), 0) }
        assertThrows(IllegalArgumentException::class.java) { enc.update(ByteArray(10), 0, 5, ByteArray(5), 1) }
    }

    @Test
    fun `a message much larger than the chunk survives the roundtrip`() {
        val key = bytes(32, 32)
        val nonce = bytes(24, 33)
        val aad = bytes(35, 34)
        val pt = bytes(1 shl 20, 35)   // 1 MiB, 16 veces el chunk por defecto
        val ct = encryptInChunks(key, nonce, aad, pt, 64 * 1024)
        assertEquals(pt.size + XChaCha20Poly1305.TAG_BYTES, ct.size)
        assertArrayEquals(pt, decryptInChunks(key, nonce, aad, ct, 64 * 1024))
        assertArrayEquals(
            "un solo update debe dar lo mismo que troceado",
            XChaCha20Poly1305.encrypt(key, nonce, aad, pt),
            ct,
        )
    }
}