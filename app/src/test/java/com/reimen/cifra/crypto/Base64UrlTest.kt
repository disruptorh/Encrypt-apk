package com.reimen.cifra.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

/**
 * Base64 URL-safe por trozos.
 *
 * La comparación de referencia es `java.util.Base64`, que es la referencia
 * que hay que mantener: el formato del sobre no puede cambiar ni un bit.
 *
 * El foco está en las colas de 1 y 2 bytes, que son las que produzcan un grupo
 * Base64 incompleto. Ahí es donde se esconde un error de desplazamiento que
 * solo aparece con longitudes que no son múltiplo de 3, y como el sobre acaba
 * codificado dos veces, un fallo así se propaga a prácticamente cualquier
 * mensaje cuyo tamaño no caiga en la suerte.
 */
class Base64UrlTest {

    private fun reference(bytes: ByteArray): String =
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    @Test
    fun `matches java util for every length up to 200`() {
        val data = ByteArray(200) { (it * 31 + 7).toByte() }
        for (n in 0..200) {
            val slice = data.copyOf(n)
            assertEquals("longitud $n", reference(slice), Base64Url.encode(slice))
            assertArrayEquals("ida $n", slice, Base64Url.decode(reference(slice)))
        }
    }

    @Test
    fun `every byte value round-trips`() {
        val all = ByteArray(256) { it.toByte() }
        for (n in listOf(1, 2, 3, 254, 255, 256)) {
            val slice = all.copyOf(n)
            assertArrayEquals(slice, Base64Url.decode(Base64Url.encode(slice)))
        }
    }

    @Test
    fun `encoding is independent of chunking`() {
        val data = ByteArray(5000) { (it % 251).toByte() }
        val whole = Base64Url.encode(data)
        for (chunk in listOf(1, 2, 3, 4, 5, 7, 16, 63, 64, 1024, 4096)) {
            val out = ByteArrayOutputStream()
            val enc = Base64Url.Encoder(out)
            var p = 0
            while (p < data.size) {
                val n = minOf(chunk, data.size - p)
                enc.update(data, p, n)
                p += n
            }
            enc.finish()
            assertEquals("trozo $chunk", whole, out.toString(Charsets.US_ASCII.name()))
        }
    }

    @Test
    fun `decoding is independent of chunking`() {
        val data = ByteArray(4096) { (it * 17).toByte() }
        val text = Base64Url.encode(data)
        for (chunk in listOf(1, 2, 3, 4, 5, 7, 16, 63, 64, 1024, 4096)) {
            val out = ByteArrayOutputStream()
            val dec = Base64Url.Decoder { b, off, len -> out.write(b, off, len) }
            var p = 0
            while (p < text.length) {
                val n = minOf(chunk, text.length - p)
                dec.update(text, p, n)
                p += n
            }
            dec.finish()
            assertArrayEquals("trozo $chunk", data, out.toByteArray())
        }
    }

    /** El camino por bytes debe dar exactamente lo mismo que el de cadena. */
    @Test
    fun `byte and char decoding agree`() {
        val data = ByteArray(1000) { (it * 13).toByte() }
        val text = Base64Url.encode(data)
        val out = ByteArrayOutputStream()
        val dec = Base64Url.Decoder { b, off, len -> out.write(b, off, len) }
        val bytes = text.toByteArray(Charsets.US_ASCII)
        for (i in bytes.indices) dec.update(bytes, i, 1)
        dec.finish()
        assertArrayEquals(data, out.toByteArray())
    }

    @Test
    fun `tolerates whitespace padding and standard alphabet`() {
        val data = ByteArray(37) { (it * 7 + 1).toByte() }
        val standard = java.util.Base64.getUrlEncoder().encodeToString(data)
        assertArrayEquals(data, Base64Url.decode(standard))

        val std = java.util.Base64.getEncoder().encodeToString(data)
        assertArrayEquals(data, Base64Url.decode(std))

        val spaced = standard.chunked(8).joinToString(" \n")
        assertArrayEquals(data, Base64Url.decode(spaced))
    }

    @Test
    fun `rejects invalid input`() {
        assertThrows(Base64Exception::class.java) { Base64Url.decode("A") }
        assertThrows(Base64Exception::class.java) { Base64Url.decode("AQI*") }
        assertThrows(Base64Exception::class.java) { Base64Url.decode("AQ==AQI=") }
    }

    @Test
    fun `length helpers agree with reality`() {
        val data = ByteArray(64) { (it * 3).toByte() }
        for (n in 0..64) {
            val slice = data.copyOf(n)
            val encoded = Base64Url.encode(slice)
            assertEquals("salida $n", Base64Url.encodedLength(n.toLong()), encoded.length.toLong())
            assertEquals("entrada $n", Base64Url.exactDecodedLength(encoded.length.toLong()), n.toLong())
            // La cota para reservar es >= que la exacta, y como mucho dos bytes
            // de diferencia: justo lo que se desvía al no haber relleno.
            val cap = Base64Url.decodedLength(encoded.length.toLong())
            assertTrue("cota $n", cap >= n && cap - n <= 2)
        }
    }
}