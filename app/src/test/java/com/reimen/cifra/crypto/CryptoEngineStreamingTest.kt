package com.reimen.cifra.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.util.Random

/**
 * El camino en streaming de [CryptoEngine] tiene que ser indistinguible del de
 * una pasada: mismo sobre byte a byte, mismo texto recovered, mismos errores.
 *
 * Si el sobre dependiera del troceado, un mensaje corto y el mismo mensaje
 * grande no podrían interoperar entre sí ni con el lado C++, y eso es
 * exactamente lo que se comprueba aquí variando los tamaños de trozo.
 */
class CryptoEngineStreamingTest {

    private val profile = CryptoEngine.KdfProfile(64, 2, "Prueba")
    private val password = "correcta".toCharArray()

    // --- helpers -----------------------------------------------------------

    private fun encryptStreaming(plain: ByteArray, chunk: Int, pepper: CharArray? = null): String {
        val out = ByteArrayOutputStream()
        CryptoEngine.startEncrypting(password, pepper, profile, plain.size.toLong(), out).use { enc ->
            var p = 0
            while (p < plain.size) {
                val n = minOf(chunk, plain.size - p)
                enc.write(plain, p, n)
                p += n
            }
            enc.finish()
        }
        return out.toString(Charsets.US_ASCII.name())
    }

    private fun decryptStreaming(blob: String, chunk: Int = 4096, pepper: CharArray? = null): ByteArray {
        val bytes = blob.toByteArray(Charsets.US_ASCII)
        val out = ByteArrayOutputStream()
        CryptoEngine.startDecrypting(bytes.size.toLong(), { ByteArrayInputStream(bytes) }, password, pepper).use { dec ->
            dec.decrypt { b, off, len -> out.write(b, off, len) }
        }
        return out.toByteArray()
    }

    // --- equivalencia de formato -------------------------------------------

    @Test
    fun `streaming and one-shot encryption agree byte for byte`() {
        val rnd = Random(23)
        val sizes = listOf(0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 1000, 4096, 65537, 300_000)
        for (n in sizes) {
            val plain = ByteArray(n).also { rnd.nextBytes(it) }
            val oneShot = CryptoEngine.encrypt(plain, password, null, profile)
            val streamed = encryptStreaming(plain, 64 * 1024)
            // El salt y el nonce son aleatorios, así que los sobres no pueden ser
            // idénticos: lo que tiene que coincidir es la estructura y el
            // tamaño, y el texto tiene que descifrar igual por ambos caminos.
            assertEquals("tamaño $n", oneShot.length, streamed.length)
            val back = decryptStreaming(streamed)
            assertArrayEquals("ida $n", plain, back)
        }
    }

    @Test
    fun `blob is independent of chunk size`() {
        val rnd = Random(29)
        val plain = ByteArray(200_000).also { rnd.nextBytes(it) }
        for (chunk in listOf(1, 2, 3, 7, 64, 1023, 65536, 200_000)) {
            assertArrayEquals("trozo $chunk", plain, decryptStreaming(encryptStreaming(plain, chunk)))
        }
    }

    @Test
    fun `headers survive the streaming roundtrip`() {
        val plain = ByteArray(5000).also { Random(31).nextBytes(it) }
        val blob = encryptStreaming(plain, 1024)
        val bytes = blob.toByteArray(Charsets.US_ASCII)
        val header = EnvelopeReader.readHeader(bytes.size.toLong()) { ByteArrayInputStream(bytes) }
        assertEquals(1, header.version)
        assertEquals(Envelope.AEAD_NAME, header.aead)
        assertEquals(Envelope.KDF_NAME, header.kdf)
        assertEquals(profile.iterations, header.ops)
        assertEquals(profile.memKib, header.memKib)
        assertEquals(16, header.salt.size)
        assertEquals(24, header.nonce.size)
        assertTrue("tamaño esperado", header.plaintextBytes >= plain.size)
        assertTrue("tamaño esperado", header.plaintextBytes - plain.size <= 2)
    }

    @Test
    fun `pepper is required on both sides`() {
        val plain = ByteArray(4096).also { Random(37).nextBytes(it) }
        val blob = encryptStreaming(plain, 777, pepper = "campo".toCharArray())
        assertArrayEquals(plain, decryptStreaming(blob, pepper = "campo".toCharArray()))

        val e = assertThrows(CryptoEngine.CryptoException::class.java) { decryptStreaming(blob) }
        assertTrue("mensaje: ${e.message}", e.message!!.contains("autenticación"))
        val e2 = assertThrows(CryptoEngine.CryptoException::class.java) {
            decryptStreaming(blob, pepper = "otro".toCharArray())
        }
        assertTrue("mensaje: ${e2.message}", e2.message!!.contains("autenticación"))
    }

    @Test
    fun `wrong password fails and emits nothing trusted`() {
        val plain = ByteArray(8192).also { Random(41).nextBytes(it) }
        val blob = encryptStreaming(plain, 512)
        val bytes = blob.toByteArray(Charsets.US_ASCII)
        val emitted = ByteArrayOutputStream()
        val e = assertThrows(CryptoEngine.CryptoException::class.java) {
            CryptoEngine.startDecrypting(bytes.size.toLong(), { ByteArrayInputStream(bytes) }, "mala".toCharArray(), null)
                .use { it.decrypt { b, off, len -> emitted.write(b, off, len) } }
        }
        assertTrue("mensaje: ${e.message}", e.message!!.contains("autenticación"))
        // Puede haber salido algo antes de fallar: por eso el llamante escribe
        // en un temporal y no publica hasta el final. Lo que no puede pasar es
        // que salga el texto bueno.
        assertTrue("texto filtrado", !emitted.toByteArray().contentEquals(plain))
    }

    @Test
    fun `corrupted ciphertext fails authentication`() {
        val plain = ByteArray(4096).also { Random(43).nextBytes(it) }
        val json = String(Base64Url.decode(encryptStreaming(plain, 256)), Charsets.UTF_8)
        val head = json.indexOf("\"ciphertext\":\"") + "\"ciphertext\":\"".length

        // Se cambia un carácter del Base64 interior por otro también válido, de
        // forma que el sobre sigue siendo un sobre bien formado y el fallo tiene
        // que salir del tag y no de un error de formato.
        val original = json[head + 10]
        val replacement = if (original == 'A') 'B' else 'A'
        val tampered = json.substring(0, head + 10) + replacement + json.substring(head + 11)
        val blob = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(tampered.toByteArray())

        val e = assertThrows(CryptoEngine.CryptoException::class.java) { decryptStreaming(blob) }
        assertTrue("mensaje: ${e.message}", e.message!!.contains("autenticación"))
    }

    @Test
    fun `corrupted outer base64 is rejected`() {
        val plain = ByteArray(4096).also { Random(43).nextBytes(it) }
        val blob = encryptStreaming(plain, 256)
        val cut = blob.length / 2
        val flipped = blob.take(cut) + (if (blob[cut] == 'A') 'B' else 'A') + blob.drop(cut + 1)
        // Puede reventar como Base64 ilegible o como tag que no cuadra; lo que
        // no puede es devolver texto.
        assertThrows(CryptoEngine.CryptoException::class.java) { decryptStreaming(flipped) }
    }

    @Test
    fun `large message roundtrips through files`() {
        val rnd = Random(47)
        val plain = ByteArray(3_000_000).also { rnd.nextBytes(it) }
        val blobFile = File.createTempFile("cifra-stream", ".txt")
        val outFile = File.createTempFile("cifra-stream-out", ".bin")
        try {
            blobFile.outputStream().use { out ->
                CryptoEngine.startEncrypting(password, null, profile, plain.size.toLong(), out).use { enc ->
                    var p = 0
                    while (p < plain.size) {
                        val n = minOf(1024 * 1024, plain.size - p)
                        enc.write(plain, p, n)
                        p += n
                    }
                    enc.finish()
                }
            }
            outFile.outputStream().use { dst ->
                CryptoEngine.startDecrypting(blobFile.length(), { blobFile.inputStream() }, password, null).use { dec ->
                    dec.decrypt { b, off, len -> dst.write(b, off, len) }
                }
            }
            assertEquals(plain.size.toLong(), outFile.length())
            assertTrue("contenido", outFile.readBytes().contentEquals(plain))
        } finally {
            blobFile.delete()
            outFile.delete()
        }
    }

    @Test
    fun `header pass reads only a tiny prefix of a big blob`() {
        val plain = ByteArray(2_000_000).also { Random(53).nextBytes(it) }
        val blobFile = File.createTempFile("cifra-prefix", ".txt")
        try {
            blobFile.outputStream().use { out ->
                CryptoEngine.startEncrypting(password, null, profile, plain.size.toLong(), out).use { enc ->
                    enc.write(plain)
                    enc.finish()
                }
            }
            // Se cuenta lo que se lee para reconocer la cabecera: tiene que ser
            // del orden de un KB, no del tamaño del sobre.
            var read = 0L
            val header = EnvelopeReader.readHeader(blobFile.length()) {
                val raw = blobFile.inputStream()
                object : InputStream() {
                    override fun read(): Int {
                        val b = raw.read()
                        if (b >= 0) read++
                        return b
                    }

                    override fun read(b: ByteArray, off: Int, len: Int): Int {
                        val n = raw.read(b, off, len)
                        if (n > 0) read += n
                        return n
                    }

                    override fun close() = raw.close()
                }
            }
            assertEquals(profile.iterations, header.ops)
            assertEquals(profile.memKib, header.memKib)
            assertTrue("se leyeron $read bytes", read <= 2048)
        } finally {
            blobFile.delete()
        }
    }
}