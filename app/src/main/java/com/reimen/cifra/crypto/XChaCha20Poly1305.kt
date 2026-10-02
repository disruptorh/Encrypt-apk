package com.reimen.cifra.crypto

/** El tag de XChaCha20-Poly1305 no verificó (datos/clave/nonce incorrectos). */
class AeadAuthException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * XChaCha20-Poly1305 (IETF), byte-a-byte compatible con libsodium
 * `crypto_aead_xchacha20poly1305_ietf` (lo que usa el lado C++):
 *
 *   subkey = HChaCha20(key, nonce[0..16])
 *   nonce2 = 0x00000000 || nonce[16..24]     (nonce IETF de 96 bits)
 *   ChaCha20-Poly1305 RFC 8439 con key = subkey, nonce = nonce2 y el AAD dado.
 *
 * El tag (16 bytes) viaja al final del ciphertext.
 *
 * ## Por qué no se usa el AEAD de Bouncy Castle
 *
 * `ChaCha20Poly1305` de BC solo acepta el mensaje entero en un array y, al
 * descifrar, lo retiene en memoria hasta comprobar el tag: para un archivo de
 * varios GiB eso significa reservar el plaintext completo y además una copia.
 * Aquí [ChaCha20Core] y [Poly1305] son incrementales, así que el cifrado y el
 * descifrado van troce a troce con memoria constante.
 *
 * La contrapartida es que hay que ser explícito en el orden de las operaciones:
 * el plaintext de [Decryptor.update] sale **sin autenticar** y solo debe
 * confirmarse cuando [Decryptor.finish] termina sin lanzar. Para no exponer
 * datos sin verificar, escríbelos en un temporal y consérvalo solo al final; o
 * usa [decryptToVerified], que retiene la cola hasta verificar.
 */
object XChaCha20Poly1305 {

    const val NONCE_BYTES = 24
    const val TAG_BYTES = 16
    const val KEY_BYTES = 32
    private const val SUBKEY_INPUT_BYTES = 16

    /**
     * Tamaño de troceo recomendado para [Encryptor.update] y
     * [Decryptor.update]. Cualquier valor sirve; este mantiene los buffers
     * internos en la L2 sin castigar el número de llamadas.
     */
    const val CHUNK_BYTES = 64 * 1024

    /** HChaCha20 (libsodium `crypto_core_hchacha20`): key de 32 bytes, input de 16 → 32 bytes. */
    fun hChaCha20(key: ByteArray, input: ByteArray): ByteArray {
        require(key.size == KEY_BYTES) { "hChaCha20: la clave debe tener 32 bytes" }
        require(input.size == SUBKEY_INPUT_BYTES) { "hChaCha20: input debe tener 16 bytes" }
        val x = IntArray(16)
        x[0] = 0x61707865
        x[1] = 0x3320646e
        x[2] = 0x79622d32
        x[3] = 0x6b206574
        for (i in 0 until 8) x[4 + i] = le32(key, i * 4)
        for (i in 0 until 4) x[12 + i] = le32(input, i * 4)
        for (i in 0 until 10) {
            qr(x, 0, 4, 8, 12)
            qr(x, 1, 5, 9, 13)
            qr(x, 2, 6, 10, 14)
            qr(x, 3, 7, 11, 15)
            qr(x, 0, 5, 10, 15)
            qr(x, 1, 6, 11, 12)
            qr(x, 2, 7, 8, 13)
            qr(x, 3, 4, 9, 14)
        }
        val out = ByteArray(32)
        for (i in 0 until 4) putLe32(out, i * 4, x[i])
        for (i in 0 until 4) putLe32(out, 16 + i * 4, x[12 + i])
        return out
    }

    /** Clave derivada: HChaCha20 sobre los primeros 16 bytes del nonce. */
    fun deriveSubkey(key: ByteArray, nonce: ByteArray): ByteArray {
        require(key.size == KEY_BYTES) { "la clave debe tener $KEY_BYTES bytes" }
        require(nonce.size == NONCE_BYTES) { "el nonce debe tener $NONCE_BYTES bytes" }
        return hChaCha20(key, nonce.copyOfRange(0, SUBKEY_INPUT_BYTES))
    }

    /** Nonce IETF de 96 bits: 4 bytes a cero + los últimos 8 del nonce de 24. */
    fun deriveNonce(nonce: ByteArray): ByteArray {
        require(nonce.size == NONCE_BYTES) { "el nonce debe tener $NONCE_BYTES bytes" }
        return ByteArray(12).also { System.arraycopy(nonce, SUBKEY_INPUT_BYTES, it, 4, 8) }
    }

    /**
     * Cifrado en streaming. El plaintext nunca ocupa más que el troceo que se
     * le pase, así que el pico de memoria no depende del tamaño del mensaje.
     *
     * ```
     * val enc = XChaCha20Poly1305.Encryptor(key, nonce, aad)
     * for (chunk in chunks) enc.update(chunk, out)
     * enc.finish(out)              // escribe los 16 bytes del tag
     * ```
     */
    class Encryptor(key: ByteArray, nonce: ByteArray, aad: ByteArray) : AutoCloseable {

        private val acc = AeadCore(key, nonce, aad)
        private var closed = false

        /**
         * Cifra [len] bytes de [input] en [out].
         *
         * @return el número de bytes escritos, siempre [len].
         */
        fun update(input: ByteArray, inOff: Int, len: Int, out: ByteArray, outOff: Int): Int {
            check(!closed) { "Encryptor: ya se emitió el tag" }
            require(inOff >= 0 && len >= 0 && inOff + len <= input.size) { "Encryptor.update: rango de entrada inválido" }
            require(outOff >= 0 && out.size - outOff >= len) { "Encryptor.update: out no tiene sitio para $len bytes" }
            if (len == 0) return 0
            // La MAC cubre el CIPHERTEXT, no el plaintext: se absorbe de [out]
            // después de cifrar. Si se absorbiera antes, el tag dependería del
            // texto claro y no se podría verificar al descifrar.
            val n = acc.cipher.process(input, inOff, len, out, outOff)
            acc.absorbCiphertext(out, outOff, n)
            return n
        }

        /** Atajo de [update] sobre el array completo. */
        fun update(input: ByteArray, out: ByteArray, outOff: Int = 0): Int =
            update(input, 0, input.size, out, outOff)

        /**
         * Escribe el tag de 16 bytes en [out].
         *
         * @return [TAG_BYTES].
         * @throws IllegalStateException si ya se había emitido.
         */
        fun finish(out: ByteArray, outOff: Int = 0): Int {
            check(!closed) { "Encryptor: el tag ya fue emitido" }
            closed = true
            val n = acc.tag(out, outOff)
            wipe()
            return n
        }

        /** Cifra [input] entero y añade el tag; útil para mensajes pequeños. */
        fun encryptTo(input: ByteArray, out: ByteArray, outOff: Int = 0): Int {
            val n = update(input, 0, input.size, out, outOff)
            return n + finish(out, outOff + n)
        }

        override fun close() = wipe()

        private fun wipe() = acc.wipe()
    }

    /**
     * Descifrado en streaming.
     *
     * **El plaintext que devuelve [update] no está autenticado todavía.** Es
     * inevitable si se quiere memoria constante: el tag solo se puede comprobar
     * al haber leído todo el ciphertext. Si los datos van a un destino que
     * sobreviva a un fallo (un archivo, una base de datos), escríbelos en un
     * temporal y consérvalo únicamente si [finish] no lanza; o usa
     * [decryptToVerified], que retiene la cola hasta verificar.
     */
    class Decryptor(key: ByteArray, nonce: ByteArray, aad: ByteArray) : AutoCloseable {

        private val acc = AeadCore(key, nonce, aad)
        private var closed = false

        /**
         * Descifra [len] bytes de [input] en [out]. Lo escrito aquí todavía no
         * está autenticado (ver la nota de la clase).
         *
         * @return el número de bytes escritos, siempre [len].
         */
        fun update(input: ByteArray, inOff: Int, len: Int, out: ByteArray, outOff: Int): Int {
            check(!closed) { "Decryptor: ya se emitió el veredicto" }
            require(inOff >= 0 && len >= 0 && inOff + len <= input.size) { "Decryptor.update: rango de entrada inválido" }
            require(outOff >= 0 && out.size - outOff >= len) { "Decryptor.update: out no tiene sitio para $len bytes" }
            if (len == 0) return 0
            acc.absorbCiphertext(input, inOff, len)
            return acc.cipher.process(input, inOff, len, out, outOff)
        }

        /** Atajo de [update] sobre el array completo. */
        fun update(input: ByteArray, out: ByteArray, outOff: Int = 0): Int =
            update(input, 0, input.size, out, outOff)

        /**
         * Calcula el tag y lo compara con los [TAG_BYTES] que empiezan en
         * [expectedTag] + [tagOff].
         *
         * @return [TAG_BYTES].
         * @throws AeadAuthException si no coincide.
         */
        fun finish(expectedTag: ByteArray, tagOff: Int = 0): Int {
            check(!closed) { "Decryptor: el veredicto ya fue emitido" }
            require(tagOff >= 0 && expectedTag.size - tagOff >= TAG_BYTES) { "Decryptor.finish: el tag esperado no cabe" }
            closed = true
            val computed = ByteArray(TAG_BYTES)
            acc.tag(computed, 0)
            val ok = Poly1305.constantTimeEquals(computed, 0, expectedTag, tagOff, TAG_BYTES)
            java.util.Arrays.fill(computed, 0.toByte())
            wipe()
            if (!ok) throw AeadAuthException("Fallo de autenticación: datos no autenticados")
            return TAG_BYTES
        }

        override fun close() = wipe()

        private fun wipe() = acc.wipe()
    }

    /**
     * Estado compartido por [Encryptor] y [Decryptor]: flujo de clave, MAC y
     * el padding por secciones que exige el RFC 8439 §2.8.
     *
     * La MAC ve `AAD || pad16(AAD) || C || pad16(C) || le64(len AAD) ||
     * le64(len C)`, así que el relleno entre secciones hay que insertarlo a
     * mano: [Poly1305] por su cuenta solo añade el `0x01` del último bloque.
     */
    private class AeadCore(key: ByteArray, nonce: ByteArray, aad: ByteArray) {
        val cipher: ChaCha20Core
        private val mac: Poly1305
        private val aadLength = aad.size.toLong()
        private var ciphertextLength = 0L
        private val zeros = ByteArray(PAD_MAX)

        init {
            val subkey = deriveSubkey(key, nonce)
            val nonce2 = deriveNonce(nonce)
            // El bloque 0 del flujo de clave es la clave de la MAC; el texto
            // empieza en el bloque 1 (RFC 8439 §2.6). De los 64 bytes del
            // bloque solo se usan los primeros 32 como clave de Poly1305.
            cipher = ChaCha20Core(subkey, nonce2, 1)
            mac = Poly1305(
                ChaCha20Core.keyStreamBlock(subkey, nonce2, 0).copyOf(Poly1305.KEY_BYTES)
            )
            mac.feed(aad, 0, aad.size)
            padTo16(aadLength)
        }

        fun absorbCiphertext(b: ByteArray, off: Int, len: Int) {
            mac.feed(b, off, len)
            ciphertextLength += len
        }

        /** Escribe el tag de 16 bytes en [out] y limpia el estado. */
        fun tag(out: ByteArray, outOff: Int): Int {
            padTo16(ciphertextLength)
            val lens = ByteArray(16)
            putLe64(lens, 0, aadLength)
            putLe64(lens, 8, ciphertextLength)
            mac.feed(lens, 0, lens.size)
            return mac.finish(out, outOff)
        }

        /** Rellena con ceros hasta el siguiente múltiplo de 16. */
        private fun padTo16(length: Long) {
            val rem = (length % Poly1305.BLOCK_BYTES).toInt()
            if (rem != 0) mac.feed(zeros, 0, Poly1305.BLOCK_BYTES - rem)
        }

        fun wipe() {
            cipher.wipe()
            mac.wipe()
            java.util.Arrays.fill(zeros, 0.toByte())
            ciphertextLength = 0
        }

        private fun putLe64(b: ByteArray, off: Int, v: Long) {
            for (i in 0 until 8) b[off + i] = (v ushr (8 * i)).toByte()
        }
    }

    /**
     * @param key        clave de 32 bytes.
     * @param nonce      nonce de 24 bytes (se genera nuevo en cada cifrado).
     * @param aad        datos adicionales autenticados (parámetros del sobre).
     * @param plaintext  mensaje.
     * @return ciphertext con el tag de 16 bytes al final.
     */
    fun encrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        require(key.size == KEY_BYTES) { "clave debe tener $KEY_BYTES bytes" }
        require(nonce.size == NONCE_BYTES) { "nonce debe tener $NONCE_BYTES bytes" }
        val out = ByteArray(plaintext.size + TAG_BYTES)
        val enc = Encryptor(key, nonce, aad)
        val n = enc.encryptTo(plaintext, out)
        enc.close()
        check(n == out.size) { "XChaCha20Poly1305: tamaño inesperado ($n != ${out.size})" }
        return out
    }

    /**
     * @throws AeadAuthException si el tag no verifica (clave, nonce, AAD o
     *         ciphertext incorrectos).
     */
    fun decrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        require(key.size == KEY_BYTES) { "clave debe tener $KEY_BYTES bytes" }
        require(nonce.size == NONCE_BYTES) { "nonce debe tener $NONCE_BYTES bytes" }
        if (ciphertext.size < TAG_BYTES) throw AeadAuthException("ciphertext demasiado corto (falta tag)")
        val out = ByteArray(ciphertext.size - TAG_BYTES)
        decryptToVerified(key, nonce, aad, ciphertext, 0, ciphertext.size, out, 0)
        return out
    }

    /**
     * Descifrado de un bloque que cabe en memoria, sin exponer plaintext sin
     * verificar: retiene los últimos [TAG_BYTES] del plaintext y solo los
     * escribe cuando el tag ha pasado.
     *
     * @return el número de bytes escritos en [out], siempre [len].
     * @throws AeadAuthException si el tag no verifica; en ese caso [out] queda
     *         con los primeros `len - TAG_BYTES` bytes sin autenticar, así que
     *         el llamante debe descartarlo.
     */
    fun decryptToVerified(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertext: ByteArray,
        inOff: Int,
        len: Int,
        out: ByteArray,
        outOff: Int
    ): Int {
        require(key.size == KEY_BYTES) { "clave debe tener $KEY_BYTES bytes" }
        require(nonce.size == NONCE_BYTES) { "nonce debe tener $NONCE_BYTES bytes" }
        if (len < TAG_BYTES) throw AeadAuthException("ciphertext demasiado corto (falta tag)")
        val bodyLen = len - TAG_BYTES
        require(outOff >= 0 && out.size - outOff >= bodyLen) { "out no tiene sitio para $bodyLen bytes" }

        // Los últimos TAG_BYTES del plaintext solo se emiten tras verificar, así
        // que se descifran aparte y se escriben al final. El troceo final de la
        // MAC debe acabar justo en bodyLen: el tag va DESPUÉS y no se absorbe.
        val tailStart = maxOf(0, bodyLen - TAG_BYTES)
        val tailLen = bodyLen - tailStart
        Decryptor(key, nonce, aad).use { dec ->
            dec.update(ciphertext, inOff, tailStart, out, outOff)
            val tail = ByteArray(tailLen)
            dec.update(ciphertext, inOff + tailStart, tailLen, tail, 0)
            dec.finish(ciphertext, inOff + bodyLen)
            System.arraycopy(tail, 0, out, outOff + tailStart, tailLen)
            java.util.Arrays.fill(tail, 0.toByte())
        }
        return bodyLen
    }

    private fun qr(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[a] += x[b]
        x[d] = x[d] xor x[a]
        x[d] = (x[d] shl 16) or (x[d] ushr 16)
        x[c] += x[d]
        x[b] = x[b] xor x[c]
        x[b] = (x[b] shl 12) or (x[b] ushr 20)
        x[a] += x[b]
        x[d] = x[d] xor x[a]
        x[d] = (x[d] shl 8) or (x[d] ushr 24)
        x[c] += x[d]
        x[b] = x[b] xor x[c]
        x[b] = (x[b] shl 7) or (x[b] ushr 25)
    }

    private fun le32(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xff) or
            ((b[off + 1].toInt() and 0xff) shl 8) or
            ((b[off + 2].toInt() and 0xff) shl 16) or
            ((b[off + 3].toInt() and 0xff) shl 24)

    private fun putLe32(b: ByteArray, off: Int, v: Int) {
        b[off] = (v and 0xff).toByte()
        b[off + 1] = ((v ushr 8) and 0xff).toByte()
        b[off + 2] = ((v ushr 16) and 0xff).toByte()
        b[off + 3] = ((v ushr 24) and 0xff).toByte()
    }

    private const val PAD_MAX = Poly1305.BLOCK_BYTES - 1
}