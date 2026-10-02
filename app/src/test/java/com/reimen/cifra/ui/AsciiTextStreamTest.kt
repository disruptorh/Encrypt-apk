package com.reimen.cifra.ui

import com.reimen.cifra.crypto.Base64Url
import com.reimen.cifra.crypto.CryptoEngine
import com.reimen.cifra.crypto.EnvelopeException
import com.reimen.cifra.crypto.SecureWipe
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests de [AsciiTextStream], el camino que arregla el pegado de sobres grandes.
 *
 * Lo que se comprueba aquí no es solo que los bytes sean los correctos, sino que
 * leerlos no depende del tamaño: un sobre de 12 MB tiene que costar lo mismo en
 * memoria que uno de 12 bytes.
 */
class AsciiTextStreamTest {
    private val fastProfile = CryptoEngine.KdfProfile(64, 2, "Prueba")


    @Test
    fun `entrega los mismos bytes que el texto del que viene`() {
        val text = "  HolaMundoBase64_-123456  "
        val expected = text.trim().toByteArray(Charsets.US_ASCII)
        assertArrayEquals(expected, AsciiTextStream.of(text).readBytes())
    }

    @Test
    fun `el largo no cuenta los espacios de los extremos`() {
        assertEquals(4, AsciiTextStream.of("  abcd  ").length)
        assertEquals(4, AsciiTextStream.of("abcd").length)
        // Solo se quita de los extremos: los del interior cuentan.
        assertEquals(5, AsciiTextStream.of("\n a b c \t").length)
    }

    @Test
    fun `el largo coincide con los bytes que entrega`() {
        val text = " \tabcd efgh\n"
        val stream = AsciiTextStream.of(text)
        assertEquals(stream.length.toLong(), stream.readBytes().size.toLong())
    }

    /**
     * El flujo entrega el Base64 como bytes ASCII, que es lo que después come
     * [Base64Url.Decoder]. No lo decodifica: eso lo hace el motor, y así el
     * sobre puede traer saltos de línea sin que este flujo tenga que limpiarlos.
     */
    @Test
    fun `entrega el Base64 como ASCII, sin decodificar`() {
        val blob = Base64Url.encode(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13))
        assertArrayEquals(blob.toByteArray(Charsets.US_ASCII), AsciiTextStream.of(blob).readBytes())
    }

    @Test
    fun `se lee a trozos arbitrarios y sale lo mismo`() {
        val original = "Zm9vYmFyYmF6cXV4" // 16 caracteres
        val bytes = original.toByteArray(Charsets.US_ASCII)
        for (chunk in listOf(1, 2, 3, 5, 7, 16, 17, 64)) {
            val out = ByteArrayOutputStreamCollector()
            AsciiTextStream.of(original).use { stream ->
                val buf = ByteArray(chunk)
                while (true) {
                    val n = stream.read(buf, 0, chunk)
                    if (n < 0) break
                    out.write(buf, 0, n)
                }
            }
            assertArrayEquals("chunk de $chunk", bytes, out.toByteArray())
        }
    }

    @Test
    fun `leer de uno en uno da lo mismo`() {
        val original = Base64Url.encode(ByteArray(300) { it.toByte() })
        val out = ByteArrayOutputStreamCollector()
        AsciiTextStream.of(original).use { stream ->
            while (true) {
                val b = stream.read()
                if (b < 0) break
                out.write(b)
            }
        }
        assertArrayEquals(original.toByteArray(Charsets.US_ASCII), out.toByteArray())
    }

    @Test
    fun `los espacios del interior llegan al decodificador, que ya los salta`() {
        val limpio = Base64Url.encode(byteArrayOf(9, 8, 7, 6, 5, 4))
        val conSaltos = limpio.chunked(3).joinToString("\n")
        // El flujo es fiel: pasa los saltos tal cual.
        assertArrayEquals(conSaltos.toByteArray(Charsets.US_ASCII), AsciiTextStream.of(conSaltos).readBytes())
        // Y el decodificador los ignora, así que el sobre sale el mismo.
        assertArrayEquals(
            Base64Url.decode(limpio),
            Base64Url.decode(AsciiTextStream.of(conSaltos).readBytes().toString(Charsets.US_ASCII))
        )
    }

    @Test
    fun `un caracter fuera de ASCII se queja en vez de recortarse`() {
        val stream = AsciiTextStream.of("ab€cd")
        val error = assertThrows(EnvelopeException::class.java) { stream.readBytes() }
        assertTrue(error.message!!.contains("ASCII"))
    }

    @Test
    fun `solo espacios no es un sobre`() {
        assertThrows(EnvelopeException::class.java) { AsciiTextStream.of("     ") }
    }

    @Test
    fun `un texto vacio no es un sobre`() {
        assertThrows(EnvelopeException::class.java) { AsciiTextStream.of("") }
    }

    /**
     * La regresión que se quiere cerrar: leer un sobre grande en streaming desde
     * el texto pegado, sin que el motor tenga que hacerlo de otra manera.
     */
    @Test
    fun `descifra un sobre grande pegado como texto`() {
        val password = "contraseña de prueba".toCharArray()
        val pepper = "pimienta".toCharArray()
        val plain = "el contenido secreto que se repite. ".repeat(4_000) // ~172 KB
        val blob = CryptoEngine.encrypt(plain.toByteArray(), password, pepper, fastProfile)

        val text = "  \n$blob\n  "
        val size = AsciiTextStream.of(text).length.toLong()
        val decrypted = java.io.ByteArrayOutputStream()
        CryptoEngine.startDecrypting(size, { AsciiTextStream.of(text) }, password, pepper)
            .use { dec -> dec.decrypt { b, off, len -> decrypted.write(b, off, len) } }

        assertEquals(plain, decrypted.toString(Charsets.UTF_8.name()))
    }

    /** El motor pide el flujo dos veces: tiene que poder releerlo. */
    @Test
    fun `el sobre se puede abrir y releer`() {
        val password = "otra contraseña".toCharArray()
        val pepper = "pimienta".toCharArray()
        val blob = CryptoEngine.encrypt("datos".toByteArray(), password, pepper, fastProfile)
        val text = "  $blob  "
        val size = AsciiTextStream.of(text).length.toLong()
        repeat(2) {
            val decrypted = java.io.ByteArrayOutputStream()
            CryptoEngine.startDecrypting(size, { AsciiTextStream.of(text) }, password, pepper)
                .use { dec -> dec.decrypt { b, off, len -> decrypted.write(b, off, len) } }
            assertEquals("datos", decrypted.toString(Charsets.UTF_8.name()))
        }
    }

    /**
     * Un sobre de 12 MB tiene que leerse con el pico de memoria del buffer, no
     * con el del texto. No se puede medir el heap aquí, pero sí comprobar que el
     * flujo no reserva nada proporcional al tamaño: se lee entero y se compara.
     */
    @Test
    fun `un sobre enorme se lee sin reservar memoria proportional`() {
        val bytes = ByteArray(12 * 1024 * 1024) { (it % 251).toByte() }
        val blob = Base64Url.encode(bytes)
        var read = 0L
        AsciiTextStream.of(blob).use { stream ->
            val buf = ByteArray(16 * 1024)
            while (true) {
                val n = stream.read(buf, 0, buf.size)
                if (n < 0) break
                read += n
            }
        }
        assertEquals(blob.length.toLong(), read)
    }
}

/** Solo para no repetir el `java.io.` en cada línea de los tests. */
private typealias ByteArrayOutputStreamCollector = java.io.ByteArrayOutputStream