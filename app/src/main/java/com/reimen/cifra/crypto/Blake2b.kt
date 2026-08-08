package com.reimen.cifra.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * BLAKE2b (RFC 7693) en la variante de 256 bits, con soporte de clave opcional.
 *
 * Byte-a-byte compatible con `crypto_generichash(outlen = 32)` de libsodium:
 * el binding de "pepper" del lado C++ usa exactamente esta construcción
 * (`Blake2b(pepper)` sin clave, seguido de `Blake2b(clave = pepperKey)`).
 *
 * Bouncy Castle no expone BLAKE2b keyed de 256 bits (sus constructores con
 * clave fijan 512 bits), por lo que se implementa aquí según RFC 7693,
 * replicando la semántica de buffer de blake2b_update/final de libsodium.
 */
internal object Blake2b {

    private const val BLOCK_BYTES = 128
    private const val MAX_KEY_BYTES = 64

    private val IV = longArrayOf(
        0x6a09e667f3bcc908uL.toLong(), 0xbb67ae8584caa73buL.toLong(), 0x3c6ef372fe94f82buL.toLong(), 0xa54ff53a5f1d36f1uL.toLong(),
        0x510e527fade682d1uL.toLong(), 0x9b05688c2b3e6c1fuL.toLong(), 0x1f83d9abfb41bd6buL.toLong(), 0x5be0cd19137e2179uL.toLong()
    )

    // Tabla sigma de RFC 7693 (12 rondas, 8 G por ronda).
    private val SIGMA = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
        intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
        intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
        intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
        intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
        intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
        intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
        intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3)
    )

    /**
     * BLAKE2b-256. Sin clave si [key] es null; keyed (RFC 7693) si no.
     * [digestBytes] por defecto 32 (256 bits), como `crypto_generichash` de libsodium.
     */
    fun hash(data: ByteArray, key: ByteArray? = null, digestBytes: Int = 32): ByteArray {
        require(digestBytes in 1..64) { "digestBytes fuera de rango" }
        require(key == null || key.size in 1..MAX_KEY_BYTES) { "longitud de clave inválida" }
        val kk = key?.size ?: 0

        // Bloque de parámetros (RFC 7693 §2.5): digest | (kk << 8) | fanout(1) | depth(1)
        val h = LongArray(8)
        h[0] = IV[0] xor 0x01010000L xor digestBytes.toLong() xor (kk.toLong() shl 8)
        System.arraycopy(IV, 1, h, 1, 7)

        // Contador de 128 bits (como libsodium: t[0], t[1]).
        var t0 = 0L
        var t1 = 0L
        val buf = ByteArray(2 * BLOCK_BYTES)
        var buflen = 0

        fun increment(incr: Long) {
            t0 += incr
            if (t0 < incr) t1++
        }

        fun compress(last: Boolean) {
            val m = LongArray(16)
            val bb = ByteBuffer.wrap(buf, 0, BLOCK_BYTES).order(ByteOrder.LITTLE_ENDIAN)
            for (i in 0 until 16) m[i] = bb.getLong()
            val v = LongArray(16)
            System.arraycopy(h, 0, v, 0, 8)
            System.arraycopy(IV, 0, v, 8, 8)
            v[12] = v[12] xor t0
            v[13] = v[13] xor t1
            if (last) v[14] = v[14].inv()
            for (r in 0 until 12) {
                val s = SIGMA[r]
                g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
                g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
                g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
                g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
                g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
                g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
                g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
                g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
            }
            for (i in 0 until 8) h[i] = h[i] xor v[i] xor v[i + 8]
        }

        // init_key: la clave entra al buffer como primer bloque (sin comprimir),
        // exactamente como blake2b_init_key de libsodium.
        if (kk > 0) {
            System.arraycopy(key, 0, buf, 0, kk)
            buflen = BLOCK_BYTES
        }

        // update: buffer de 256 bytes; se comprime cuando quedaría más de un bloque.
        var off = 0
        var inlen = data.size
        while (inlen > 0) {
            val left = buflen
            val fill = 2 * BLOCK_BYTES - left
            if (inlen > fill) {
                System.arraycopy(data, off, buf, left, fill)
                buflen += fill
                increment(BLOCK_BYTES.toLong())
                compress(last = false)
                System.arraycopy(buf, BLOCK_BYTES, buf, 0, BLOCK_BYTES)
                buflen -= BLOCK_BYTES
                off += fill
                inlen -= fill
            } else {
                System.arraycopy(data, off, buf, left, inlen)
                buflen += inlen
                off += inlen
                inlen = 0
            }
        }

        // final: si quedó más de un bloque, el primero se comprime sin ser el último.
        if (buflen > BLOCK_BYTES) {
            increment(BLOCK_BYTES.toLong())
            compress(last = false)
            buflen -= BLOCK_BYTES
            System.arraycopy(buf, BLOCK_BYTES, buf, 0, BLOCK_BYTES)
        }
        increment(buflen.toLong())
        java.util.Arrays.fill(buf, buflen, 2 * BLOCK_BYTES, 0)
        compress(last = true)

        val full = ByteArray(64)
        ByteBuffer.wrap(full).order(ByteOrder.LITTLE_ENDIAN).asLongBuffer().put(h, 0, 8)
        return full.copyOf(digestBytes)
    }

    private fun g(v: LongArray, a: Int, b: Int, c: Int, d: Int, x: Long, y: Long) {
        v[a] += v[b] + x
        v[d] = java.lang.Long.rotateRight(v[d] xor v[a], 32)
        v[c] += v[d]
        v[b] = java.lang.Long.rotateRight(v[b] xor v[c], 24)
        v[a] += v[b] + y
        v[d] = java.lang.Long.rotateRight(v[d] xor v[a], 16)
        v[c] += v[d]
        v[b] = java.lang.Long.rotateRight(v[b] xor v[c], 63)
    }
}
