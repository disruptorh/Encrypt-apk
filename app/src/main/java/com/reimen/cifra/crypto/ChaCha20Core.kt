package com.reimen.cifra.crypto

/**
 * ChaCha20 (RFC 8439) como cifrador de flujo con estado reutilizable.
 *
 * Bouncy Castle solo ofrece una interfaz de un solo `processBytes` sobre el
 * array completo. Para cifrar por trozos sin reservar el mensaje entero, aquí se
 * expone el estado (clave, contador, nonce, bloque parcial) de forma explícita:
 * el llamante reutiliza los mismos buffers y el pico de memoria es constante
 * sea cual sea el tamaño del mensaje.
 *
 * ```
 * val core = ChaCha20Core(key, nonce, counter = 1)
 * core.process(chunk, 0, chunk.size, out, 0)   // out >= chunk.size
 * core.process(next, 0, next.size, out2, 0)    // continúa donde lo dejó
 * ```
 *
 * [counter] es el número de bloque de 64 bytes. El modo CTR de Poly1305 usa el
 * bloque 0 para la clave de la MAC, así que el texto se cifra desde el 1.
 */
class ChaCha20Core(
    key: ByteArray,
    nonce: ByteArray,
    counter: Int,
    private val rounds: Int = DEFAULT_ROUNDS
) {
    init {
        require(key.size == KEY_BYTES) { "ChaCha20: la clave debe tener $KEY_BYTES bytes" }
        require(nonce.size == NONCE_BYTES) { "ChaCha20: el nonce debe tener $NONCE_BYTES bytes" }
        require(counter >= 0) { "ChaCha20: el contador no puede ser negativo" }
    }

    /**
     * Estado de entrada de la función de bloque: constantes || clave ||
     * contador || nonce. El contador (índice 12) se incrementa tras cada bloque,
     * de modo que aquí siempre es el del bloque que se va a generar.
     */
    private val base = IntArray(16).also { s ->
        s[0] = 0x61707865
        s[1] = 0x3320646e
        s[2] = 0x79622d32
        s[3] = 0x6b206574
        for (i in 0 until 8) s[4 + i] = le32(key, i * 4)
        s[12] = counter
        for (i in 0 until 3) s[13 + i] = le32(nonce, i * 4)
    }

    /** Copia de trabajo sobre la que se aplican las rondas. */
    private val work = IntArray(16)

    /** Flujo de clave del bloque actual. */
    private val keyStream = ByteArray(BLOCK_BYTES)

    /** Bytes de [keyStream] aún sin consumir; 0 = hay que generar el siguiente bloque. */
    private var available = 0

    private var wiped = false

    /**
     * Aplica el flujo de clave a [input] escribiendo en [out].
     *
     * @return el número de bytes escritos en [out], siempre igual a [len].
     * @throws IllegalStateException si el contador de 32 bits se desbrosa, es
     *         decir, si el mensaje supera los 256 GiB con un mismo nonce.
     */
    fun process(input: ByteArray, inOff: Int, len: Int, out: ByteArray, outOff: Int): Int {
        if (len <= 0) return 0
        check(!wiped) { "ChaCha20: el motor ya fue limpiado" }
        var i = inOff
        val end = inOff + len
        var o = outOff

        while (i < end) {
            if (available == 0) refill()
            val take = minOf(end - i, available)
            for (k in 0 until take) {
                out[o + k] = (input[i + k].toInt() xor keyStream[BLOCK_BYTES - available + k].toInt()).toByte()
            }
            available -= take
            i += take
            o += take
        }
        return o - outOff
    }

    /**
     * Genera el flujo de clave del bloque [base]12 y lo descompone en
     * [keyStream]. Es exactamente la función de bloque del RFC 8439 §2.3: 20
     * rondas y suma del estado de entrada palabra a palabra.
     */
    private fun refill() {
        check(base[12] != Int.MAX_VALUE) {
            "ChaCha20: el mensaje excede los 256 GiB con un solo nonce"
        }
        System.arraycopy(base, 0, work, 0, 16)
        for (i in 0 until rounds / 2) doubleRound()
        for (i in 0 until 16) {
            val v = work[i] + base[i]
            keyStream[i * 4] = (v and 0xff).toByte()
            keyStream[i * 4 + 1] = ((v ushr 8) and 0xff).toByte()
            keyStream[i * 4 + 2] = ((v ushr 16) and 0xff).toByte()
            keyStream[i * 4 + 3] = ((v ushr 24) and 0xff).toByte()
        }
        base[12]++
        available = BLOCK_BYTES
    }

    /** Media vuelta de Cuadrícula: dos QR por diagonal y dos por anti-diagonal. */
    private fun doubleRound() {
        quarterRound(0, 4, 8, 12)
        quarterRound(1, 5, 9, 13)
        quarterRound(2, 6, 10, 14)
        quarterRound(3, 7, 11, 15)
        quarterRound(0, 5, 10, 15)
        quarterRound(1, 6, 11, 12)
        quarterRound(2, 7, 8, 13)
        quarterRound(3, 4, 9, 14)
    }

    private fun quarterRound(a: Int, b: Int, c: Int, d: Int) {
        work[a] += work[b]; work[d] = work[d] xor work[a]; work[d] = rotl(work[d], 16)
        work[c] += work[d]; work[b] = work[b] xor work[c]; work[b] = rotl(work[b], 12)
        work[a] += work[b]; work[d] = work[d] xor work[a]; work[d] = rotl(work[d], 8)
        work[c] += work[d]; work[b] = work[b] xor work[c]; work[b] = rotl(work[b], 7)
    }

    private fun rotl(v: Int, n: Int): Int = (v shl n) or (v ushr (32 - n))

    /** Sobrescribe clave, nonce, estado y flujo de clave retenidos. */
    fun wipe() {
        java.util.Arrays.fill(keyStream, 0.toByte())
        java.util.Arrays.fill(work, 0)
        java.util.Arrays.fill(base, 0)
        available = 0
        wiped = true
    }

    companion object {
        const val KEY_BYTES = 32
        const val NONCE_BYTES = 12
        const val BLOCK_BYTES = 64
        const val DEFAULT_ROUNDS = 20

        /**
         * Bloque de flujo de clave (64 bytes) para [counter], sin XOR: es lo que
         * Poly1305 usa como clave de la MAC (RFC 8439 §2.6).
         */
        fun keyStreamBlock(key: ByteArray, nonce: ByteArray, counter: Int): ByteArray {
            val core = ChaCha20Core(key, nonce, counter)
            core.refill()
            val out = core.keyStream.copyOf()
            core.wipe()
            return out
        }

        private fun le32(b: ByteArray, off: Int): Int =
            (b[off].toInt() and 0xff) or
                ((b[off + 1].toInt() and 0xff) shl 8) or
                ((b[off + 2].toInt() and 0xff) shl 16) or
                ((b[off + 3].toInt() and 0xff) shl 24)
    }
}
