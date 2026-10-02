package com.reimen.cifra.crypto

/**
 * Poly1305 one-time authenticator (RFC 8439 §2.5) con interfaz incremental.
 *
 * Igual que [ChaCha20Core], el objetivo es no necesitar el mensaje entero: se
 * alimenta troce a troce y el acumulador son 5 limbs de 26 bits, así que la
 * memoria es constante (unos 100 bytes) para cualquier tamaño de entrada.
 *
 * [feed] acepta cualquier troceo (los bloques de 16 bytes se pueden partir
 * entre llamadas) y [finish] devuelve el tag de 16 bytes.
 *
 * ```
 * val mac = Poly1305(key32)
 * mac.feed(aad, 0, aad.size)
 * mac.feed(ciphertext, 0, ciphertext.size)
 * val tag = mac.finish()
 * ```
 */
class Poly1305(key: ByteArray) {

    init {
        require(key.size == KEY_BYTES) { "Poly1305: la clave debe tener $KEY_BYTES bytes" }
    }

    // r = clave[0..16] recortado; s = clave[16..32] (se suma al final).
    private val r0: Int
    private val r1: Int
    private val r2: Int
    private val r3: Int
    private val r4: Int

    /**
     * s se guarda como Long SIN signo. Con Int, una palabra con el bit 31
     * puesto se extendería con signos al sumarla al acumulador de 64 bits y
     * contaminaría el acarreo al siguiente limb.
     */
    private val s0: Long
    private val s1: Long
    private val s2: Long
    private val s3: Long

    // Acumulador h en limbs de 26 bits.
    private var h0 = 0L
    private var h1 = 0L
    private var h2 = 0L
    private var h3 = 0L
    private var h4 = 0L

    /** Bloque de 16 bytes a medio acumular entre llamadas. */
    private val block = ByteArray(BLOCK_BYTES)

    /** Bytes ya acumulados en [block]. */
    private var blockLen = 0

    private var finished = false

    init {
        val t0 = le32(key, 0)
        val t1 = le32(key, 4)
        val t2 = le32(key, 8)
        val t3 = le32(key, 12)
        // Recorte de RFC 8439 §2.5: los 4 bits altos de los bytes 3, 7, 11 y 15,
        // y los 2 bits altos de los bytes 4, 8 y 12, se ponen a cero.
        r0 = t0.toInt() and 0x3ffffff
        r1 = ((t0 ushr 26) or (t1 shl 6)).toInt() and 0x3ffff03
        r2 = ((t1 ushr 20) or (t2 shl 12)).toInt() and 0x3ffc0ff
        r3 = ((t2 ushr 14) or (t3 shl 18)).toInt() and 0x3f03fff
        r4 = (t3 ushr 8).toInt() and 0x0fffff
        s0 = le32(key, 16)
        s1 = le32(key, 20)
        s2 = le32(key, 24)
        s3 = le32(key, 28)
    }

    /**
     * Acumula [len] bytes de [input]. Se puede llamar tantas veces como haga
     * falta: los bloques de 16 bytes se agrupan internamente.
     */
    fun feed(input: ByteArray, off: Int, len: Int) {
        check(!finished) { "Poly1305: ya se emitió el tag" }
        if (len <= 0) return
        var i = off
        val end = off + len

        // Si queda un bloque a medias, complétalo primero.
        if (blockLen > 0) {
            val need = minOf(BLOCK_BYTES - blockLen, end - i)
            System.arraycopy(input, i, block, blockLen, need)
            blockLen += need
            i += need
            if (blockLen == BLOCK_BYTES) {
                processBlock(block, 0, FULL_BLOCK_HIBIT)
                blockLen = 0
            }
        }

        // Todos los bloques completos que quepan sin arrastrar.
        val whole = (end - i) / BLOCK_BYTES
        if (whole > 0) {
            processBlocks(input, i, whole)
            i += whole * BLOCK_BYTES
        }

        // Guarda el resto para la próxima llamada.
        if (i < end) {
            blockLen = end - i
            System.arraycopy(input, i, block, 0, blockLen)
        }
    }

    /**
     * Emite el tag de 16 bytes en [out] a partir de [outOff].
     *
     * @return 16.
     * @throws IllegalStateException si se llama dos veces.
     */
    fun finish(out: ByteArray, outOff: Int): Int {
        check(!finished) { "Poly1305: el tag ya fue emitido" }
        finished = true

        // El último bloque se completa con 0x01 y se trata como bloque corto
        // (sin el bit de 2^128).
        if (blockLen > 0) {
            java.util.Arrays.fill(block, blockLen, BLOCK_BYTES, 0.toByte())
            block[blockLen] = 1
            processBlock(block, 0, 0L)
            blockLen = 0
        }

        // Recarreo completo de h.
        var c = h1 ushr 26; h1 = h1 and 0x3ffffff
        h2 += c; c = h2 ushr 26; h2 = h2 and 0x3ffffff
        h3 += c; c = h3 ushr 26; h3 = h3 and 0x3ffffff
        h4 += c; c = h4 ushr 26; h4 = h4 and 0x3ffffff
        h0 += c * 5; c = h0 ushr 26; h0 = h0 and 0x3ffffff
        h1 += c

        // g = h - (2^130 - 5). Si el resultado "presta", h ya estaba reducido.
        var g0 = h0 + 5; c = g0 ushr 26; g0 = g0 and 0x3ffffff
        var g1 = h1 + c; c = g1 ushr 26; g1 = g1 and 0x3ffffff
        var g2 = h2 + c; c = g2 ushr 26; g2 = g2 and 0x3ffffff
        var g3 = h3 + c; c = g3 ushr 26; g3 = g3 and 0x3ffffff
        val g4 = h4 + c - (1L shl 26)

        // El desplazamiento tiene que ser LÓGICO: g4 es negativo y `shr`
        // devolvería -1 en lugar de 1. La máscara vale 0 si h < p (elegimos h)
        // y -1 si no (elegimos g), sin filtrar nada por temporización.
        val mask = (g4 ushr 63) - 1
        h0 = (h0 and mask.inv()) or (g0 and mask)
        h1 = (h1 and mask.inv()) or (g1 and mask)
        h2 = (h2 and mask.inv()) or (g2 and mask)
        h3 = (h3 and mask.inv()) or (g3 and mask)
        h4 = (h4 and mask.inv()) or (g4 and 0x3ffffffL)

        // Serializa h a 4 palabras de 32 bits.
        val f0 = h0 or (h1 shl 26)
        val f1 = (h1 ushr 6) or (h2 shl 20)
        val f2 = (h2 ushr 12) or (h3 shl 14)
        val f3 = (h3 ushr 18) or (h4 shl 8)

        // tag = (h + s) mod 2^128, con acarreo de 32 en 32 bits.
        //
        // Cada palabra se recorta a 32 bits ANTES de sumarle su mitad de s: las
        // combinaciones de arriba ocupan bits más allá del 31, y si ese basura
        // llegara al `ushr 32` del paso siguiente contaminaría el acarreo y
        // las tres últimas palabras del tag.
        var f = (f0 and 0xffffffffL) + s0; putLe32(out, outOff, f)
        f = (f1 and 0xffffffffL) + s1 + (f ushr 32); putLe32(out, outOff + 4, f)
        f = (f2 and 0xffffffffL) + s2 + (f ushr 32); putLe32(out, outOff + 8, f)
        f = (f3 and 0xffffffffL) + s3 + (f ushr 32); putLe32(out, outOff + 12, f)

        wipe()
        return TAG_BYTES
    }

    /** Atajo para mensajes pequeños: devuelve el tag como array nuevo. */
    fun finishToByteArray(): ByteArray = ByteArray(TAG_BYTES).also { finish(it, 0) }

    private fun processBlocks(input: ByteArray, off: Int, count: Int) {
        var p = off
        val limit = off + count * BLOCK_BYTES
        while (p < limit) {
            processBlock(input, p, FULL_BLOCK_HIBIT)
            p += BLOCK_BYTES
        }
    }

    /** h += (bloque de 16 bytes | hibit); h *= r, con recarreo de 26 en 26 bits. */
    private fun processBlock(m: ByteArray, off: Int, hibit: Long) {
        val r1x5 = r1 * 5L
        val r2x5 = r2 * 5L
        val r3x5 = r3 * 5L
        val r4x5 = r4 * 5L

        h0 += le32(m, off) and 0x3ffffffL
        h1 += (le32(m, off + 3) ushr 2) and 0x3ffffffL
        h2 += (le32(m, off + 6) ushr 4) and 0x3ffffffL
        h3 += (le32(m, off + 9) ushr 6) and 0x3ffffffL
        // El bit de 2^128 va con OR, no con suma: el limb puede tener ya el bit
        // 24 puesto y `|` es lo que exige el RFC 8439 §2.5.
        h4 += ((le32(m, off + 12) ushr 8) and 0x3ffffffL) or hibit

        // Multiplicación de 5x26 limbs. Todos los términos caben en Long:
        // h < 2^28 y r < 2^26, luego cada suma < 5 * 2^55 < 2^58.
        var d0 = h0 * r0 + h1 * r4x5 + h2 * r3x5 + h3 * r2x5 + h4 * r1x5
        var d1 = h0 * r1 + h1 * r0 + h2 * r4x5 + h3 * r3x5 + h4 * r2x5
        var d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * r4x5 + h4 * r3x5
        var d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * r4x5
        var d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0

        var c = d0 ushr 26; h0 = d0 and 0x3ffffff
        d1 += c; c = d1 ushr 26; h1 = d1 and 0x3ffffff
        d2 += c; c = d2 ushr 26; h2 = d2 and 0x3ffffff
        d3 += c; c = d3 ushr 26; h3 = d3 and 0x3ffffff
        d4 += c; c = d4 ushr 26; h4 = d4 and 0x3ffffff
        h0 += c * 5; c = h0 ushr 26; h0 = h0 and 0x3ffffff
        h1 += c
    }

    /** Sobrescribe el acumulador y el bloque pendiente. */
    fun wipe() {
        h0 = 0; h1 = 0; h2 = 0; h3 = 0; h4 = 0
        java.util.Arrays.fill(block, 0.toByte())
        blockLen = 0
    }

    companion object {
        const val KEY_BYTES = 32
        const val BLOCK_BYTES = 16
        const val TAG_BYTES = 16
        private const val FULL_BLOCK_HIBIT = 1L shl 24

        /**
         * Lectura little-endian de 4 bytes como Long **sin signo**.
         *
         * Importa que sea sin signo: si devolviera un Int con signo, el
         * `.toLong()` extendería con unos y el `ushr` posterior mezclaría esos
         * bits en el limb, sesgando el resultado de forma dependiente de los
         * datos.
         */
        private fun le32(b: ByteArray, off: Int): Long =
            (b[off].toLong() and 0xff) or
                ((b[off + 1].toLong() and 0xff) shl 8) or
                ((b[off + 2].toLong() and 0xff) shl 16) or
                ((b[off + 3].toLong() and 0xff) shl 24)

        private fun putLe32(b: ByteArray, off: Int, v: Long) {
            b[off] = v.toByte()
            b[off + 1] = (v ushr 8).toByte()
            b[off + 2] = (v ushr 16).toByte()
            b[off + 3] = (v ushr 24).toByte()
        }

        /**
         * Comparación en tiempo constante de dos tags: no sale antes el primer
         * byte distinto, así que no filtra información por temporización.
         */
        fun constantTimeEquals(a: ByteArray, aOff: Int, b: ByteArray, bOff: Int, len: Int): Boolean {
            var diff = 0
            for (i in 0 until len) diff = diff or (a[aOff + i].toInt() xor b[bOff + i].toInt())
            return diff == 0
        }
    }
}
