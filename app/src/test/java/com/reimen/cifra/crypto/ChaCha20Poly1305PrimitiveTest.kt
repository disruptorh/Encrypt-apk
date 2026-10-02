package com.reimen.cifra.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

/**
 * Vectores oficiales de RFC 8439 (ChaCha20 §2.4.2 y Poly1305 §2.5.2) más
 * comprobaciones de equivalencia con Bouncy Castle, que es la implementación
 * de referencia usada por el resto del proyecto.
 */
class ChaCha20Poly1305PrimitiveTest {

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    @Test
    fun `chacha20 encryption matches RFC 8439 2_4_2`() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = hexToBytes("000000000000004a00000000")
        val plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
            .toByteArray(Charsets.US_ASCII)

        val cipher = ChaCha20Core(key, nonce, counter = 1)
        val out = ByteArray(plaintext.size)
        val n = cipher.process(plaintext, 0, plaintext.size, out, 0)
        cipher.wipe()
        assertEquals(plaintext.size, n)

        assertEquals(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d",
            hex(out)
        )
    }

    @Test
    fun `chacha20 block function matches RFC 8439 2_3_2`() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = hexToBytes("000000090000004a00000000")
        val out = ChaCha20Core.keyStreamBlock(key, nonce, counter = 1)
        assertEquals(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" +
                "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
            hex(out)
        )
    }

    @Test
    fun `chacha20 key stream block zero is distinct from block one`() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = hexToBytes("000000090000004a00000000")
        val block0 = ChaCha20Core.keyStreamBlock(key, nonce, 0)
        val block1 = ChaCha20Core.keyStreamBlock(key, nonce, 1)
        // El bloque 0 es la clave de la MAC y el 1 el primer bloque de texto:
        // tienen que diferir en cuanto al primer byte.
        assertNotEquals(block0[0].toInt(), block1[0].toInt())
        assertEquals(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" +
                "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
            hex(block1)
        )
    }

    @Test
    fun `poly1305 matches RFC 8439 2_5_2`() {
        val key = hexToBytes(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
        )
        val msg = "Cryptographic Forum Research Group".toByteArray(Charsets.US_ASCII)
        assertEquals("a8061dc1305136c6c22b8baf0c0127a9", hex(Poly1305(key).also { it.feed(msg, 0, msg.size) }.finishToByteArray()))
    }

    @Test
    fun `poly1305 of an empty message is just the second half of the key`() {
        val key = hexToBytes(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
        )
        // s = clave[16..32] y con h = 0 el tag es exactamente s.
        assertEquals("0103808afb0db2fd4abff6af4149f51b", hex(Poly1305(key).finishToByteArray()))
    }

    @Test
    fun `chacha20 is chunk-boundary independent`() {
        val key = ByteArray(32) { (it * 7).toByte() }
        val nonce = ByteArray(12) { (it * 3).toByte() }
        val msg = ByteArray(1000) { (it % 251).toByte() }

        val reference = ByteArray(msg.size).also { out ->
            ChaCha20Core(key, nonce, 1).process(msg, 0, msg.size, out, 0)
        }

        // Todos los tamaños de trozo, incluidos los que no alinean con el bloque
        // de 64 bytes ni con los 16 de Poly1305.
        for (chunk in listOf(1, 2, 3, 7, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128, 129, 333, 999, 1000)) {
            val core = ChaCha20Core(key, nonce, 1)
            val out = ByteArray(msg.size)
            var p = 0
            while (p < msg.size) {
                val n = minOf(chunk, msg.size - p)
                core.process(msg, p, n, out, p)
                p += n
            }
            core.wipe()
            assertArrayEquals("trozo de $chunk bytes", reference, out)
        }
    }

    @Test
    fun `poly1305 is chunk-boundary independent`() {
        val rnd = Random(1234)
        val key = ByteArray(32).also { rnd.nextBytes(it) }
        val msg = ByteArray(777).also { rnd.nextBytes(it) }

        val reference = Poly1305(key).also { it.feed(msg, 0, msg.size) }.finishToByteArray()

        for (chunk in listOf(1, 2, 3, 7, 15, 16, 17, 32, 48, 63, 64, 65, 100, 777)) {
            val mac = Poly1305(key)
            var p = 0
            while (p < msg.size) {
                val n = minOf(chunk, msg.size - p)
                mac.feed(msg, p, n)
                p += n
            }
            assertArrayEquals("trozo de $chunk bytes", reference, mac.finishToByteArray())
        }
    }

    @Test
    fun `poly1305 matches bouncy castle on random input of every length mod 16`() {
        val rnd = Random(99)
        for (len in 0..80) {
            val key = ByteArray(32).also { rnd.nextBytes(it) }
            val msg = ByteArray(len).also { rnd.nextBytes(it) }
            val mine = Poly1305(key).also { it.feed(msg, 0, msg.size) }.finishToByteArray()
            val theirs = referencePoly1305(key, msg)
            assertArrayEquals("longitud $len", theirs, mine)
        }
    }

    @Test
    fun `poly1305 detects a single flipped bit in the message`() {
        val key = ByteArray(32) { (it * 11).toByte() }
        val msg = ByteArray(200) { (it % 97).toByte() }
        val tag = Poly1305(key).also { it.feed(msg, 0, msg.size) }.finishToByteArray()
        for (i in msg.indices) {
            val tampered = msg.copyOf()
            tampered[i] = (tampered[i].toInt() xor 0x08).toByte()
            val other = Poly1305(key).also { it.feed(tampered, 0, tampered.size) }.finishToByteArray()
            assertNotEquals("cambio en el byte $i no detectado", tag.toList(), other.toList())
        }
    }

    @Test
    fun `constant time equals detects any single bit flip`() {
        val a = ByteArray(16) { 0x5a }
        val b = a.copyOf()
        assertTrue(Poly1305.constantTimeEquals(a, 0, b, 0, 16))
        for (i in 0 until 16) {
            val c = a.copyOf()
            c[i] = (c[i].toInt() xor 0x01).toByte()
            assertNotEquals("flip en el byte $i", true, Poly1305.constantTimeEquals(a, 0, c, 0, 16))
        }
    }
}
