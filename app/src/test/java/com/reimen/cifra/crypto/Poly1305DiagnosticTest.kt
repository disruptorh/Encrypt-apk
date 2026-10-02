package com.reimen.cifra.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import java.math.BigInteger
import java.util.Random

/**
 * Referencia independiente de Poly1305 en BigInteger (RFC 8439 §2.5) para
 * triangular divergencias. Compara las tres implementaciones sobre las mismas
 * entradas: la propia, la de Bouncy Castle y la de BigInteger.
 *
 * ElBigInteger es el judge's independiente: si las tres coinciden, un fallo
 * en la implementación propia no se debe a una referencia mal escrita.
 */
class Poly1305DiagnosticTest {

    private val P = (BigInteger.ONE shl 130) - BigInteger.valueOf(5)
    private val TWO_128 = BigInteger.ONE shl 128

    /** Recorte canónico de r: RFC 8439 §2.5, escrito como máscara de 128 bits. */
    private val CLAMP = BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16)

    /** Lectura little-endian de [len] bytes como entero sin signo. */
    private fun le(b: ByteArray, off: Int, len: Int): BigInteger {
        var v = BigInteger.ZERO
        for (i in 0 until len) {
            v = v.or(BigInteger.valueOf(b[off + i].toLong() and 0xff).shl(8 * i))
        }
        return v
    }

    /** Poly1305 "de libro": h = (h + bloque) * r mod p, tag = (h + s) mod 2^128. */
    private fun reference(key: ByteArray, msg: ByteArray): ByteArray {
        val r = le(key, 0, 16).and(CLAMP)
        val s = le(key, 16, 16)
        var acc = BigInteger.ZERO
        var i = 0
        while (i < msg.size) {
            val n = minOf(16, msg.size - i)
            // Cada bloque se interpreta como n bytes + un 1 en el byte n
            // (2^128 en los bloques completos).
            val block = le(msg, i, n).add(BigInteger.ONE.shl(8 * n))
            acc = acc.add(block).multiply(r).mod(P)
            i += n
        }
        val t = acc.add(s).mod(TWO_128)
        val out = ByteArray(16)
        var v = t
        for (k in 0 until 16) {
            out[k] = v.and(BigInteger.valueOf(0xff)).toInt().toByte()
            v = v.shiftRight(8)
        }
        return out
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private fun mine(key: ByteArray, msg: ByteArray) =
        Poly1305(key).also { it.feed(msg, 0, msg.size) }.finishToByteArray()

    private fun hexToBytes(hex: String) =
        ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }

    @Test
    fun `rfc 8439 2_5_2 vector agrees with bouncy castle and biginteger`() {
        val key = hexToBytes("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        val msg = "Cryptographic Forum Research Group".toByteArray(Charsets.US_ASCII)
        val expected = hexToBytes("a8061dc1305136c6c22b8baf0c0127a9")
        assertArrayEquals("rfc vector", expected, mine(key, msg))
        assertArrayEquals("bouncy castle", expected, referencePoly1305(key, msg))
        assertArrayEquals("biginteger", expected, reference(key, msg))
    }

    /**
     * Regresión del bug de extensión de signo: la palabra leída para el limb 4
     * tenía el bit 31 a uno, el `.toLong()` la extendía con unos y el `ushr`
     * posterior metía esos bits dentro del limb, así que el resultado solo
     * difería cuando el mensaje tenía el bit 127 del bloque puesto.
     */
    @Test
    fun `regression - limb 4 with the top bit of the 32 bit word set`() {
        val key = hexToBytes("465ea9dc0f9e30c15a566dada56aec9b489d32e824c3a6af7b912391c050b48e")
        val msg = hexToBytes("1ec7f878d067f0b250dcd76d9e83ebb0")
        val expected = hexToBytes("093bf7fe224affca83715fb4a1fa313e")
        assertEquals("sanity del caso", expected.toList(), reference(key, msg).toList())
        assertArrayEquals("bouncy castle", expected, referencePoly1305(key, msg))
        assertArrayEquals("propia", expected, mine(key, msg))
    }

    @Test
    fun `all three implementations agree on every length modulo 16`() {
        val rnd = Random(99)
        for (len in 0..80) {
            val key = ByteArray(32).also { rnd.nextBytes(it) }
            val msg = ByteArray(len).also { rnd.nextBytes(it) }
            val mineTag = mine(key, msg)
            assertArrayEquals(
                "bouncy castle diverge en len=$len (key=${hex(key)} msg=${hex(msg)})",
                referencePoly1305(key, msg),
                mineTag,
            )
            assertArrayEquals(
                "biginteger diverge en len=$len",
                reference(key, msg),
                mineTag,
            )
        }
    }

    /** r con el bit 31 de sus palabras a uno, paramachacar los 4 limb de recorte. */
    @Test
    fun `agreement when every r word has its high byte set`() {
        val rnd = Random(7)
        repeat(64) {
            val key = ByteArray(32).also { rnd.nextBytes(it) }
            // Fuerza los bytes 3, 7, 11, 15 a 0xff para que r tenga los bits
            // altos que el recorte debe eliminar.
            for (i in listOf(3, 7, 11, 15)) key[i] = 0xff.toByte()
            val msg = ByteArray(33).also { rnd.nextBytes(it) }
            assertArrayEquals(
                "bouncy castle diverge (key=${hex(key)})",
                referencePoly1305(key, msg),
                mine(key, msg),
            )
        }
    }
}