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
 * El camino en streaming tiene que ser indistinguible del camino que carga todo
 * en memoria, y ambos tienen que ser indistinguibles del sobre que produce el
 * lado C++. Eso es lo que se comprueba aquí: el formato no puede depender de si
 * el mensaje cabía en el heap.
 */
class EnvelopeStreamingTest {

    private fun envelopeFor(ciphertext: ByteArray, ops: Int = 2, memKib: Int = 64): Envelope =
        Envelope(
            1, Envelope.AEAD_NAME, Envelope.KDF_NAME, ops, memKib,
            ByteArray(16) { (it + 1).toByte() },
            ByteArray(24) { (it * 3 + 2).toByte() },
            ciphertext
        )

    private fun blobOf(ciphertext: ByteArray): String = Envelope.toBase64(envelopeFor(ciphertext))

    private fun streamBlob(ciphertext: ByteArray, chunk: Int = 7): String {
        val out = ByteArrayOutputStream()
        val w = EnvelopeWriter.new(out, 2, 64, ByteArray(16) { (it + 1).toByte() }, ByteArray(24) { (it * 3 + 2).toByte() })
        var p = 0
        while (p < ciphertext.size) {
            val n = minOf(chunk, ciphertext.size - p)
            w.write(ciphertext, p, n)
            p += n
        }
        w.finish()
        return out.toString(Charsets.US_ASCII.name())
    }

    private fun asciiBytes(s: String) = s.toByteArray(Charsets.US_ASCII)

    /** Fuente que entrega como mucho [chunk] bytes por lectura. */
    private fun trickled(blob: String, chunk: Int): () -> InputStream = {
        val data = asciiBytes(blob)
        object : InputStream() {
            private var p = 0
            override fun read(): Int {
                if (p >= data.size) return -1
                return data[p++].toInt() and 0xff
            }

            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (p >= data.size) return -1
                val n = minOf(len, chunk, data.size - p)
                System.arraycopy(data, p, b, off, n)
                p += n
                return n
            }
        }
    }

    // -----------------------------------------------------------------------
    // Escritura
    // -----------------------------------------------------------------------

    @Test
    fun `streaming writer is byte-identical to the in-memory writer`() {
        val rnd = Random(7)
        val lengths = (0..80).toList() + listOf(255, 256, 257, 1000, 4095, 4096, 65537)
        for (n in lengths) {
            val ct = ByteArray(n).also { rnd.nextBytes(it) }
            assertEquals("longitud $n", blobOf(ct), streamBlob(ct))
            for (chunk in listOf(1, 2, 3, 5, 64, 100000)) {
                assertEquals("longitud $n trozo $chunk", blobOf(ct), streamBlob(ct, chunk))
            }
        }
    }

    @Test
    fun `writer accepts all profiles`() {
        for (ops in 1..Envelope.OPS_MAX) {
            for (memKib in listOf(8, 64, 1024, Envelope.MEM_KIB_MAX)) {
                val e = Envelope(
                    1, Envelope.AEAD_NAME, Envelope.KDF_NAME, ops, memKib,
                    ByteArray(16) { 9 }, ByteArray(24) { 8 }, ByteArray(48) { 7 }
                )
                assertEquals(e, Envelope.fromBase64(Envelope.toBase64(e)))
            }
        }
    }

    // -----------------------------------------------------------------------
    // Lectura
    // -----------------------------------------------------------------------

    @Test
    fun `streaming reader recovers the ciphertext exactly`() {
        val rnd = Random(11)
        val lengths = listOf(16, 17, 18, 19, 31, 32, 33, 1000, 4096, 65537, 200_000)
        for (n in lengths) {
            val ct = ByteArray(n).also { rnd.nextBytes(it) }
            val blob = blobOf(ct)
            val data = asciiBytes(blob)

            val header = EnvelopeReader.readHeader(data.size.toLong()) { ByteArrayInputStream(data) }
            // readHeader solo conoce la longitud del blob, así que la cifra es
            // una cota: como mucho dos bytes de más, que es lo que se desvía un
            // Base64 sin relleno al reservar sin saberlo.
            assertTrue("cota $n", header.ciphertextBytes >= ct.size)
            assertTrue("cota $n", header.ciphertextBytes - ct.size <= 2)
            assertEquals("salt $n", 16, header.salt.size)
            assertEquals("nonce $n", 24, header.nonce.size)

            val out = ByteArrayOutputStream()
            EnvelopeReader.streamCiphertext(header, data.size.toLong(), { ByteArrayInputStream(data) }) { b, off, len ->
                out.write(b, off, len)
            }
            assertArrayEquals("ciphertext $n", ct, out.toByteArray())
        }
    }

    @Test
    fun `header of a blob with no declared size still yields the exact ciphertext`() {
        // Hay proveedores de SAF que no dicen cuánto mide el documento. El sobre
        // es válido igual: lo que se pierde es la cota previa, no el resultado.
        val rnd = Random(23)
        listOf(16, 17, 64, 1000, 65537).forEach { n ->
            val ct = ByteArray(n).also { rnd.nextBytes(it) }
            val blob = blobOf(ct)
            val data = asciiBytes(blob)

            val header = EnvelopeReader.readHeader(-1L) { ByteArrayInputStream(data) }
            assertEquals(
                "la cabecera debe declararse sin cota cuando el tamaño se desconoce",
                EnvelopeHeader.UNKNOWN_CHARS,
                header.ciphertextChars
            )

            val out = ByteArrayOutputStream()
            EnvelopeReader.streamCiphertext(header, -1L, { ByteArrayInputStream(data) }) { b, off, len ->
                out.write(b, off, len)
            }
            assertArrayEquals(ct, out.toByteArray())
        }
    }

    @Test
    fun `a blob with no declared size is still rejected when malformed`() {
        // Perder el tamaño no puede convertir un sobre roto en uno válido: la
        // comprobación de delimitadores sigue siendo la que manda.
        val full = blobOf(ByteArray(64).also { Random(5).nextBytes(it) })
        val truncated = full.dropLast(40)
        val header = EnvelopeReader.readHeader(-1L) { ByteArrayInputStream(asciiBytes(truncated)) }
        assertThrows(EnvelopeException::class.java) {
            EnvelopeReader.streamCiphertext(header, -1L, { ByteArrayInputStream(asciiBytes(truncated)) }) { _, _, _ -> }
        }
    }

    @Test
    fun `streaming reader works with tiny reads`() {
        val ct = ByteArray(5000).also { Random(3).nextBytes(it) }
        val data = asciiBytes(blobOf(ct))
        for (chunk in listOf(1, 2, 3, 4, 7, 13, 64, 999)) {
            val header = EnvelopeReader.readHeader(data.size.toLong(), trickled(blobOf(ct), chunk))
            val out = ByteArrayOutputStream()
            EnvelopeReader.streamCiphertext(header, data.size.toLong(), trickled(blobOf(ct), chunk)) { b, off, len ->
                out.write(b, off, len)
            }
            assertArrayEquals("trozo $chunk", ct, out.toByteArray())
        }
    }

    @Test
    fun `readHeader agrees with parseHeader`() {
        val ct = ByteArray(3000).also { Random(5).nextBytes(it) }
        val json = Base64Url.decode(blobOf(ct))
        val data = asciiBytes(blobOf(ct))
        val a = EnvelopeReader.parseHeader(json)
        val b = EnvelopeReader.readHeader(data.size.toLong()) { ByteArrayInputStream(data) }
        assertEquals(a.version, b.version)
        assertEquals(a.aead, b.aead)
        assertEquals(a.kdf, b.kdf)
        assertEquals(a.ops, b.ops)
        assertEquals(a.memKib, b.memKib)
        assertArrayEquals(a.salt, b.salt)
        assertArrayEquals(a.nonce, b.nonce)
        assertEquals(a.ciphertextStartInJson, b.ciphertextStartInJson)
    }

    @Test
    fun `reads from a file`() {
        val ct = ByteArray(120_000).also { Random(13).nextBytes(it) }
        val blob = blobOf(ct)
        val file = File.createTempFile("cifra-envelope", ".txt")
        try {
            file.writeBytes(asciiBytes(blob))
            val header = EnvelopeReader.readHeader(file.length()) { file.inputStream() }
            assertTrue(header.plaintextBytes > 0)
            val out = File.createTempFile("cifra-plain", ".bin")
            try {
                file.inputStream().use { raw ->
                    out.outputStream().use { dst ->
                        EnvelopeReader.streamCiphertext(header, file.length(), { file.inputStream() }) { b, off, len ->
                            dst.write(b, off, len)
                        }
                    }
                }
                assertArrayEquals(ct, out.readBytes())
            } finally {
                out.delete()
            }
        } finally {
            file.delete()
        }
    }

    // -----------------------------------------------------------------------
    // Rechazo de sobres manipulados
    // -----------------------------------------------------------------------

    private fun expectRejected(blob: String, what: String) {
        val data = asciiBytes(blob)
        val e = assertThrows("debería rechazar: $what", EnvelopeException::class.java) {
            val header = EnvelopeReader.readHeader(data.size.toLong()) { ByteArrayInputStream(data) }
            EnvelopeReader.streamCiphertext(header, data.size.toLong(), { ByteArrayInputStream(data) }) { _, _, _ -> }
        }
        assertTrue("mensaje poco informativo para $what: ${e.message}", !e.message.isNullOrBlank())
    }

    @Test
    fun `rejects truncated blob`() {
        val blob = blobOf(ByteArray(64) { 5 })
        expectRejected(blob.dropLast(10), "recortado por el final")
        expectRejected(blob.dropLast(1), "recortado por un carácter")
        expectRejected(blob.dropLast(blob.length / 2), "recortado por la mitad")
    }

    @Test
    fun `rejects trailing garbage`() {
        val blob = blobOf(ByteArray(64) { 5 })
        expectRejected(blob + "AAAA", "basura después del cierre")
        expectRejected(blob + "A", "un carácter de más")
    }

    @Test
    fun `rejects mangled terminator`() {
        val json = String(Base64Url.decode(blobOf(ByteArray(64) { 5 })), Charsets.UTF_8)
        expectRejected(
            java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.replace("\"}", "\",\"x\"").toByteArray()),
            "cierre del objeto sustituido"
        )
    }

    @Test
    fun `tolerates whitespace in the outer base64`() {
        // Pegar y copiar mete saltos de línea. El contenido sigue siendo el
        // mismo sobre, así que tiene que descifrar igual: la longitud deducida
        // queda desalineada, pero el final del campo lo localiza el recorrido,
        // no la cuenta. Si alguna vez se usara esa cuenta para validar, esto
        // sería un rechazo falso.
        val ct = ByteArray(64) { 5 }
        val spaced = blobOf(ct).chunked(40).joinToString("\n")
        val data = asciiBytes(spaced)
        val header = EnvelopeReader.readHeader(data.size.toLong()) { ByteArrayInputStream(data) }
        val out = ByteArrayOutputStream()
        EnvelopeReader.streamCiphertext(header, data.size.toLong(), { ByteArrayInputStream(data) }) { b, off, len ->
            out.write(b, off, len)
        }
        assertArrayEquals(ct, out.toByteArray())
    }

    @Test
    fun `rejects bad profile in streaming mode`() {
        val ct = ByteArray(64) { 5 }
        val cases = listOf(
            """{"v":2,"aead":"xchacha20poly1305_ietf","kdf":"argon2id","ops":2,"mem_kib":64,"salt":"${b64(16)}","nonce":"${b64(24)}","ciphertext":"${b64(64)}"}""" to "versión",
            """{"v":1,"aead":"rot13","kdf":"argon2id","ops":2,"mem_kib":64,"salt":"${b64(16)}","nonce":"${b64(24)}","ciphertext":"${b64(64)}"}""" to "aead",
            """{"v":1,"aead":"xchacha20poly1305_ietf","kdf":"argon2id","ops":2,"mem_kib":64,"salt":"${b64(16)}","nonce":"${b64(24)}","ciphertext":"${b64(64)}","extra":1}""" to "campo extra",
            """{"v":1,"v":1,"aead":"xchacha20poly1305_ietf","kdf":"argon2id","ops":2,"mem_kib":64,"salt":"${b64(16)}","nonce":"${b64(24)}","ciphertext":"${b64(64)}"}""" to "campo duplicado",
            """{"v":1,"aead":"xchacha20poly1305_ietf","kdf":"argon2id","ops":0,"mem_kib":64,"salt":"${b64(16)}","nonce":"${b64(24)}","ciphertext":"${b64(64)}"}""" to "ops cero",
            """{"v":1,"aead":"xchacha20poly1305_ietf","kdf":"argon2id","ops":2,"mem_kib":0,"salt":"${b64(16)}","nonce":"${b64(24)}","ciphertext":"${b64(64)}"}""" to "mem cero"
        )
        for ((json, what) in cases) {
            val blob = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray())
            assertThrows("debería rechazar $what", EnvelopeException::class.java) {
                Envelope.fromBase64(blob)
            }
            expectRejected(blob, what)
        }
    }

    @Test
    fun `rejects header only`() {
        expectRejected(
            java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("""{"v":1,"aead":"xchacha20poly1305_ietf","kdf":"argon2id","ops":2,"mem_kib":64,"salt":"${b64(16)}","nonce":"${b64(24)}"}""".toByteArray()),
            "sin ciphertext"
        )
    }

    private fun b64(n: Int): String = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(n) { 3 })
}