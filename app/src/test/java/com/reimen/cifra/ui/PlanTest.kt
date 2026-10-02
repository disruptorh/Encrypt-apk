package com.reimen.cifra.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction

/**
 * Las decisiones de la pantalla, probadas sin emulador.
 *
 * Aquí no se comprueba que el cifrado funcione —eso lo cubren `crypto/` y la
 * interoperabilidad con C++— sino que la app *tome la decisión correcta*, que es
 * donde se concentran los errores silenciosos: un cálculo de tamaño equivocado no
 * rompe nada visiblemente, solo manda un archivo de 8 GB a la memoria.
 */
class PlanTest {

    // --- upperBoundForText ------------------------------------------------

    @Test
    fun `un texto vacío ocupa la cabecera y nada más`() {
        assertEquals(512L, Plan.upperBoundForText(0))
    }

    @Test
    fun `la cota del texto no se queda corta con emoji`() {
        // El fallo que motivó sacar esto: contar unidades UTF-16 como si fueran
        // bytes. Un emoji son 2 unidades y 4 bytes, así que la cuenta anterior
        // iba justo por la mitad.
        val emoji = "\uD83D\uDE00".repeat(100) // 100 emojis = 200 unidades = 400 bytes
        assertEquals(200, emoji.length)

        val bound = Plan.upperBoundForText(emoji.length)
        val real = emoji.toByteArray(Charsets.UTF_8).size.toLong()

        assertEquals("no debe quedarse corta", 400L, real)
        assertTrue("cota $bound < real $real", bound > real)
    }

    @Test
    fun `la cota del texto aguanta el peor caso de UTF-8`() {
        // Peor caso: caracteres BMP de 3 bytes (los emojis son 2 unidades para 4
        // bytes, o sea 2 por unidad, menos que 3).
        val worst = "€".repeat(500) // U+20AC = 3 bytes en UTF-8
        assertEquals(500, worst.length)
        val bound = Plan.upperBoundForText(worst.length)
        assertTrue(bound > worst.toByteArray(Charsets.UTF_8).size.toLong())
    }

    @Test
    fun `la cota del texto aguanta los tres planos y los suplentes sueltos`() {
        // U+20AC (BMP de 3 bytes), un par suplente, un emoji de 4 bytes, ASCII y
        // el carácter de reemplazo.
        val raw = "\u20AC\uD83D\uDE00\uD83D\uDE00A\uFFFD"
        // Codifica igual que UTF-8 de verdad, pero pasando por el codificador con
        // errores: los suplentes sueltos se sustituyen, y aun así la cota manda.
        val bytes = Charsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPLACE)
            .onUnmappableCharacter(CodingErrorAction.REPLACE)
            .encode(CharBuffer.wrap(raw))
        val bound = Plan.upperBoundForText(raw.length)
        assertTrue(bound > bytes.remaining().toLong())
    }

    @Test
    fun `la cota del texto crece siempre con la longitud`() {
        var anterior = 0L
        for (chars in listOf(0, 1, 10, 1000, 100_000, 1_000_000)) {
            val bound = Plan.upperBoundForText(chars)
            assertTrue("$chars → $bound", bound > anterior)
            anterior = bound
        }
    }

    // --- upperBoundForPlaintext ------------------------------------------

    @Test
    fun `un tamaño desconocido se propaga como desconocido`() {
        // Confundir -1 con "pequeño" haría elegir destino con un número
        // inventado, que es justo el error que hay que evitar.
        assertEquals(-1L, Plan.upperBoundForPlaintext(-1L))
    }

    @Test
    fun `un archivo de 1 MiB crece algo más de 16 sobre 9`() {
        val mebibyte = 1024L * 1024
        val bound = Plan.upperBoundForPlaintext(mebibyte)
        assertTrue("$bound", bound > mebibyte)
        assertTrue("$bound", bound < mebibyte * 2)
    }

    @Test
    fun `la cota del archivo aguanta el Base64 doble`() {
        // El sobre real es ceil(4/3) del Base64 interior, que a su vez es ceil(4/3)
        // del texto. Contexto: el factor real está justo por debajo de 16/9.
        val texto = 10_000_000L
        val bound = Plan.upperBoundForPlaintext(texto)
        val sobre = ((texto + 2) / 3 * 4)          // Base64 interior
        val exterior = ((sobre + 2) / 3 * 4)        // Base64 exterior
        assertTrue("cota $bound < sobre real $exterior", bound > exterior)
    }

    @Test
    fun `un tamaño absurdo satura en vez de desbordar a negativo`() {
        // Un desbordamiento a negativo se leería como "desconocido" y cambiaría
        // la decisión de destino justo en el caso más grande.
        val bound = Plan.upperBoundForPlaintext(Long.MAX_VALUE)
        assertEquals(Long.MAX_VALUE, bound)
        assertTrue("no debe desbordar a negativo", bound > 0)
        assertTrue("un tamaño absurdo tiene que ir a archivo", Plan.needsFile(bound, 256L * 1024))
    }

    @Test
    fun `la cota del archivo es monótona`() {
        var anterior = 0L
        for (bytes in listOf(1L, 2L, 1000L, 1L shl 20, 1L shl 30)) {
            val bound = Plan.upperBoundForPlaintext(bytes)
            assertTrue("$bytes → $bound (anterior $anterior)", bound > anterior)
            anterior = bound
        }
    }

    // --- utf8Length -------------------------------------------------------

    @Test
    fun `utf8Length coincide con lo que realmente se escribe`() {
        // Esto es lo que fija la barra de progreso: `done` cuenta los bytes que
        // el Utf8Writer emite, así que el total tiene que medirse igual.
        val casos = listOf(
            "" to 0,
            "hola" to 4,
            "caf\u00E9" to 5,           // 4 ASCII + 1 de 2 bytes
            "\u20AC" to 3,                // BMP de 3 bytes
            "\uD83D\uDE00" to 4,          // par suplente = 4 bytes, 2 unidades
            "\uD83D\uDE00\uD83D\uDE00" to 8,
            "a\uD83D\uDE00b\u20AC" to 9   // 1 + 4 + 1 + 3
        )
        for ((texto, esperado) in casos) {
            assertEquals(
                "\"$texto\"",
                esperado.toLong(),
                Plan.utf8Length(texto)
            )
        }
    }

    @Test
    fun `utf8Length cuenta los caracteres de tres y cuatro bytes`() {
        val texto = ("\u20AC\uD83D\uDE00\uD83D\uDC76\uD83C\uDF0D").repeat(10)
        assertEquals(
            texto.toByteArray(Charsets.UTF_8).size.toLong(),
            Plan.utf8Length(texto)
        )
    }

    @Test
    fun `utf8Length es exacto con texto mezclado largo`() {
        // Un recorte por bytes redondeado aquí se nota: basta un emoji de más.
        val texto = buildString {
            repeat(2000) {
                append("letra á€ ")
                append("\uD83D\uDE00")
                append(it)
            }
        }
        assertEquals(
            texto.toByteArray(Charsets.UTF_8).size.toLong(),
            Plan.utf8Length(texto)
        )
    }

    @Test
    fun `un suplente suelto no hace que utf8Length se quede corto`() {
        // Una String con un UTF-16 sin pareja: el codificador de Java escribe '?'
        // (1 byte) pero contar el valor del suplente da 3. Que sobre.
        val roto = "a\uD83Db"
        assertTrue(
            Plan.utf8Length(roto) >= roto.toByteArray(Charsets.UTF_8).size.toLong()
        )
    }

    @Test
    fun `la cota del texto sigue cubriendo la cuenta exacta`() {
        // upperBoundForText es el que decide memoria o archivo, así que tiene
        // que ser >= utf8Length siempre, aunque el cálculo sea más burdo.
        val textos = listOf(
            "a", "\u20AC", "\uD83D\uDE00", "x".repeat(5000),
            ("\uD83D\uDE00\u20ACa").repeat(500)
        )
        for (t in textos) {
            val exacto = Plan.upperBoundForPlaintext(Plan.utf8Length(t))
            val burdo = Plan.upperBoundForText(t.length)
            assertTrue(
                "texto de ${t.length} unidades: exacto=$exacto burdo=$burdo",
                exacto <= burdo
            )
        }
    }

    // --- needsFile --------------------------------------------------------

    @Test
    fun `un tamaño desconocido va a archivo`() {
        assertTrue(Plan.needsFile(-1L, 256L * 1024))
    }

    @Test
    fun `el límite en pantalla es exclusivo`() {
        val limite = 256L * 1024
        assertFalse("justo en el límite cabe en pantalla", Plan.needsFile(limite, limite))
        assertTrue("un byte más ya no", Plan.needsFile(limite + 1, limite))
    }

    @Test
    fun `un resultado pequeño se queda en pantalla`() {
        assertFalse(Plan.needsFile(512L, 256L * 1024))
    }

    // --- outputName -------------------------------------------------------

    @Test
    fun `propone un nombre a partir del archivo de entrada`() {
        assertEquals("notas.cifrado.txt", Plan.outputName("notas.txt", encrypting = true))
        assertEquals("notas.descifrado.txt", Plan.outputName("notas.txt", encrypting = false))
    }

    @Test
    fun `no duplica la extension en nombres con varios puntos`() {
        assertEquals("my.data.cifrado.txt", Plan.outputName("my.data.file", encrypting = true))
    }

    @Test
    fun `usa un nombre por defecto cuando la entrada es un texto`() {
        assertEquals("cifra.cifrado.txt", Plan.outputName(null, encrypting = true))
        assertEquals("cifra.descifrado.txt", Plan.outputName(null, encrypting = false))
    }

    @Test
    fun `un nombre que solo es un punto no deja el resultado sin nombre`() {
        // ".bashrc": substringBeforeLast('.') devuelve "" y el resultado sería
        // ".cifrado.txt", un nombre oculto.
        assertEquals("cifra.cifrado.txt", Plan.outputName(".bashrc", encrypting = true))
    }

    @Test
    fun `recorta los nombres que no caben en el limite del sistema de archivos`() {
        val larguisimo = "a".repeat(300) + ".txt"
        val nombre = Plan.outputName(larguisimo, encrypting = true)
        assertTrue(
            "el nombre propuesto mide ${nombre.toByteArray().size} bytes",
            nombre.toByteArray(Charsets.UTF_8).size <= Plan.MAX_NAME_BYTES
        )
        assertTrue(nombre.endsWith(".cifrado.txt"))
    }

    @Test
    fun `al recortar no parte un caracter multibyte`() {
        // Si el corte cae dentro de un carácter, el nombre deja de ser UTF-8
        // válido y el proveedor lo rechaza con un error que no explica nada.
        val conEuros = "€".repeat(200) + ".txt" // 200 × 3 = 600 bytes
        val nombre = Plan.outputName(conEuros, encrypting = true)
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        decoder.decode(ByteBuffer.wrap(nombre.toByteArray(Charsets.UTF_8)))
        assertTrue(nombre.endsWith(".cifrado.txt"))
    }

    @Test
    fun `recorta contando bytes y no caracteres`() {
        // Con nombres con acentos, recortar por caracteres dejaría el nombre por
        // encima de 255 bytes y el alta fallaría.
        val conAcentos = "á".repeat(200) + ".txt" // 200 × 2 = 400 bytes
        val nombre = Plan.outputName(conAcentos, encrypting = true)
        assertTrue(
            "mide ${nombre.toByteArray(Charsets.UTF_8).size} bytes",
            nombre.toByteArray(Charsets.UTF_8).size <= Plan.MAX_NAME_BYTES
        )
    }
}