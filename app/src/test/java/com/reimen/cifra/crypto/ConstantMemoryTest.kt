package com.reimen.cifra.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.RandomAccessFile
import kotlin.random.Random

/**
 * La promesa de la app es "un archivo de 40 GB se cifra igual de bien que uno de
 * 40 bytes". Aquí se comprueba, y no de palabra.
 *
 * La forma de comprobarlo no es mirar el código (que parece lineal) sino medir:
 * se cifra y se descifra un archivo bastante más grande que cualquier presupuesto
 * de memoria razonable mientras un hilo muestrea el heap. Si en algún momento la
 * memoria usada creciera con el tamaño del archivo, el pico sería de cientos de
 * megas y el test fallaría.
 *
 * El archivo se genera en disco con un patrón repetible, así que comprobar el
 * resultado es barato (hash) y no hace falta guardar los 256 MiB en ninguna parte.
 *
 * El pico del KDF (64 MiB de Argon2id) se mide aparte: es constante, no depende
 * del archivo, yoccurre antes de empezar a cifrar. Lo que se comprueba aquí es
 * que durante el cifrado y el descifrado **no** se suma al tamaño del mensaje.
 */
class ConstantMemoryTest {

    private val plaintextBytes = 256L * 1024 * 1024

    /** Escribe un archivo de [size] bytes cuyo contenido depende de la posición. */
    private fun patternedFile(size: Long, name: String): File {
        val f = File.createTempFile(name, ".bin")
        f.deleteOnExit()
        // Patrón de 4 KiB: suficiente para que un error de chunking se note y
        // barato de generar. La clave se mezcla al final.
        val block = ByteArray(4096)
        val rnd = Random(20260901)
        rnd.nextBytes(block)
        RandomAccessFile(f, "rw").use { raf ->
            var written = 0L
            while (written < size) {
                val n = minOf(block.size.toLong(), size - written).toInt()
                raf.write(block, 0, n)
                written += n
            }
        }
        return f
    }

    /** Huella del archivo, para no guardarlo en memoria. */
    private fun digest(f: File): ByteArray {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        f.inputStream().use { input ->
            val buf = ByteArray(256 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest()
    }

    /**
     * Corre [body] mientras se muestrea el heap usado y devuelve el pico, en
     * bytes, por encima de la línea base.
     */
    private fun peakUsedHeap(body: () -> Unit): Long {
        // Baseline en frío: sin esto elCollector vería la basura que dejó el test
        // anterior y las cifras no significarían nada.
        repeat(3) {
            System.gc()
            Thread.sleep(60)
        }
        val runtime = Runtime.getRuntime()
        val baseline = runtime.totalMemory() - runtime.freeMemory()

        val peak = java.util.concurrent.atomic.AtomicLong(baseline)
        val sampling = Thread {
            while (!Thread.currentThread().isInterrupted) {
                val used = runtime.totalMemory() - runtime.freeMemory()
                peak.accumulateAndGet(used) { a, b -> maxOf(a, b) }
                try {
                    Thread.sleep(2)
                } catch (e: InterruptedException) {
                    return@Thread
                }
            }
        }
        sampling.isDaemon = true
        sampling.start()
        try {
            body()
        } finally {
            sampling.interrupt()
            sampling.join(1000)
        }
        return peak.get() - baseline
    }

    @Test
    fun `streaming a 256 MiB no usa memoria proporcional al archivo`() {
        val plain = patternedFile(plaintextBytes, "cifra-plain")
        val blob = File.createTempFile("cifra-blob", ".bin").apply { deleteOnExit() }
        assertEquals(plain.length(), plaintextBytes)

        val original = digest(plain)

        val encryptPeak = peakUsedHeap {
            plain.inputStream().use { input ->
                blob.outputStream().buffered(1 shl 16).use { out ->
                    CryptoEngine
                        .startEncrypting(PASSWORD, null, CryptoEngine.KdfProfile.STANDARD, plaintextBytes, out)
                        .use { enc ->
                            val buf = ByteArray(1 shl 16)
                            while (true) {
                                val n = input.read(buf)
                                if (n < 0) break
                                enc.write(buf, 0, n)
                            }
                            enc.finish()
                        }
                }
            }
        }

        val roundTrip = digest(blob)
        val decryptPeak = peakUsedHeap {
            // `open` se invoca dos veces (cabecera y luego el campo entero) y cada
            // vez tiene que devolver una lectura nueva: la anterior ya está
            // consumida y cerrada. Por eso no se puede escribir `{ unFlujo }`.
            plain.delete()
            File(plain.parentFile, plain.name).outputStream().buffered(1 shl 16).use { out ->
                CryptoEngine
                    .startDecrypting(blob.length(), { blob.inputStream() }, PASSWORD, null)
                    .use { dec ->
                        dec.decrypt { b, off, len -> out.write(b, off, len) }
                    }
            }
        }

        assertArrayEquals("el archivo descifrado debe ser idéntico al original", original, digest(plain))

        // El techo es la memoria del KDF (64 MiB de Argon2id, constante e
        // inevitable) más un margen para el camino streaming. El margen no es
        // arbitrario grande: si alguien reintrodujera un `readBytes()` o un
        // `ByteArrayOutputStream`, aparecerían los 256 MiB del archivo por encima
        // de este techo y el test fallaría de golpe.
        val kdf = CryptoEngine.KdfProfile.STANDARD.memKib.toLong() * 1024
        val budget = kdf + 16L * 1024 * 1024
        println("cifrado: pico ${encryptPeak / 1024 / 1024} MiB (KDF ${kdf / 1024 / 1024} MiB + ${(encryptPeak - kdf) / 1024 / 1024} MiB de streaming)")
        println("descifrado: pico ${decryptPeak / 1024 / 1024} MiB (KDF ${kdf / 1024 / 1024} MiB + ${(decryptPeak - kdf) / 1024 / 1024} MiB de streaming)")
        println("archivo: ${plaintextBytes / 1024 / 1024} MiB de entrada")
        assertTrue(
            "el cifrado consumió ${encryptPeak / 1024 / 1024} MiB de heap para " +
                "${plaintextBytes / 1024 / 1024} MiB de entrada (techo: ${budget / 1024 / 1024} MiB)",
            encryptPeak < budget
        )
        assertTrue(
            "el descifrado consumió ${decryptPeak / 1024 / 1024} MiB de heap para " +
                "${plaintextBytes / 1024 / 1024} MiB de entrada (techo: ${budget / 1024 / 1024} MiB)",
            decryptPeak < budget
        )
    }

    @Test
    fun `el heap no crece al multiplicar por cuatro el tamaño de entrada`() {
        // Segunda evidencia, independiente de los números absolutos: el pico con
        // 64 MiB de entrada y con 256 MiB tiene que ser prácticamente el mismo.
        // Una implementación proporcional mostraría una diferencia de 4x.
        val small = patternedFile(64L * 1024 * 1024, "cifra-small")
        val big = patternedFile(256L * 1024 * 1024, "cifra-big")

        val smallPeak = peakUsedHeap { encryptTo(small, 64L * 1024 * 1024) }
        val bigPeak = peakUsedHeap { encryptTo(big, 256L * 1024 * 1024) }

        small.delete()
        big.delete()

        assertTrue(
            "con 64 MiB se usaron ${smallPeak / 1024} KiB y con 256 MiB ${bigPeak / 1024} KiB: " +
                "eso no es constante, es proporcional",
            bigPeak < smallPeak + 8L * 1024 * 1024
        )
    }

    private fun encryptTo(source: File, size: Long) {
        val out = File.createTempFile("cifra-mem", ".bin").apply { deleteOnExit() }
        source.inputStream().use { input ->
            out.outputStream().buffered(1 shl 16).use { sink ->
                CryptoEngine
                    .startEncrypting(PASSWORD, null, CryptoEngine.KdfProfile.STANDARD, size, sink)
                    .use { enc ->
                        val buf = ByteArray(1 shl 16)
                        while (true) {
                            val n = input.read(buf)
                            if (n < 0) break
                            enc.write(buf, 0, n)
                        }
                        enc.finish()
                    }
            }
        }
    }

    @Test
    fun `el presupuesto distingue entre contenido en memoria y contenido a trozos`() {
        val kdf = CryptoEngine.KdfProfile.STANDARD.memKib
        // Con el mensaje entero en memoria, 256 MiB no caben en el heap de un
        // móvil normal: ahí el factor 10x es real y el rechazo es correcto.
        val nada = 0L
        assertTrue(
            "un mensaje de 256 MiB en memoria debería rechazarse",
            !CryptoEngine.checkSizeBudget(kdf, 256L * 1024 * 1024, CryptoEngine.ContentCost.IN_MEMORY)
        )
        // A trozos, el mismo mensaje no tiene por qué caber en la memoria: solo
        // el KDF. Este es el bug que impedía cifrar archivos de verdad.
        assertTrue(
            "un mensaje de 256 MiB a trozos debería aceptarse",
            CryptoEngine.checkSizeBudget(kdf, 256L * 1024 * 1024, CryptoEngine.ContentCost.STREAMED)
        )
        // Y de hecho el motor acepta streaming de 256 MiB de verdad.
        val out = File.createTempFile("cifra-budget", ".bin").apply { deleteOnExit() }
        CryptoEngine
            .startEncrypting(PASSWORD, null, CryptoEngine.KdfProfile.STANDARD, 256L * 1024 * 1024, out.outputStream())
            .use { it.finish() }
        assertTrue("debería haber salido la cabecera del sobre", out.length() > 0)
        assertEquals(nada, 0L)
    }

    @Test
    fun `open se invoca dos veces y cada vez con una lectura nueva`() {
        // El contrato de `startDecrypting` es sutil y su fallo no da un mensaje
        // útil, así que se fija con un test: dos invocaciones, y la segunda tiene
        // que devolver un flujo que aún esté en su sitio.
        // Un sobre de verdad: el ciphertext tiene que pasar el tag, así que no
        // sirve un `Envelope` montado a mano con bytes inventados.
        val ciphertext = ByteArray(5000) { (it * 13).toByte() }
        val blob = CryptoEngine
            .encrypt(ciphertext, PASSWORD, null, CryptoEngine.KdfProfile.STANDARD)
            .toByteArray(Charsets.US_ASCII)

        var calls = 0
        val sink = ByteArrayOutputStream()
        CryptoEngine.startDecrypting(blob.size.toLong(), {
            calls++
            assertTrue("la invocación $calls devolvió un flujo ya cerrado", calls <= 2)
            ByteArrayInputStream(blob)
        }, PASSWORD, null).use { it.decrypt { b, off, len -> sink.write(b, off, len) } }

        assertEquals("open debe invocarse exactamente dos veces", 2, calls)
        assertArrayEquals(ciphertext, sink.toByteArray())
    }

    private companion object {
        val PASSWORD = "contraseña-de-prueba".toCharArray()
    }
}