package com.reimen.cifra.crypto

import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.modes.AEADCipher
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

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
 * El tag (16 bytes) viaja al final del ciphertext. La implementación del modo
 * AEAD la aporta Bouncy Castle (`ChaCha20Poly1305`); HChaCha20 se implementa
 * aquí porque BC no lo expone.
 */
object XChaCha20Poly1305 {

    const val NONCE_BYTES = 24
    const val TAG_BYTES = 16
    private const val KEY_BYTES = 32
    private const val SUBKEY_INPUT_BYTES = 16

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

    /**
     * @param key        clave de 32 bytes.
     * @param nonce      nonce de 24 bytes (se genera nuevo en cada cifrado).
     * @param aad        datos adicionales autenticados (parámetros del sobre).
     * @param plaintext  mensaje.
     * @return ciphertext con el tag de 16 bytes al final.
     */
    fun encrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        require(key.size == KEY_BYTES) { "clave debe tener 32 bytes" }
        require(nonce.size == NONCE_BYTES) { "nonce debe tener 24 bytes" }
        val (subkey, nonce2) = deriveSubkey(key, nonce)
        return runAead(subkey, nonce2, aad, plaintext, forEncryption = true)
    }

    /**
     * @throws AeadAuthException si el tag no verifica (clave, nonce, AAD o
     *         ciphertext incorrectos).
     */
    fun decrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        require(key.size == KEY_BYTES) { "clave debe tener 32 bytes" }
        require(nonce.size == NONCE_BYTES) { "nonce debe tener 24 bytes" }
        if (ciphertext.size < TAG_BYTES) {
            throw AeadAuthException("ciphertext demasiado corto (falta tag)")
        }
        val (subkey, nonce2) = deriveSubkey(key, nonce)
        return runAead(subkey, nonce2, aad, ciphertext, forEncryption = false)
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

    private fun deriveSubkey(key: ByteArray, nonce: ByteArray): Pair<ByteArray, ByteArray> {
        val subkey = hChaCha20(key, nonce.copyOfRange(0, SUBKEY_INPUT_BYTES))
        val nonce2 = ByteArray(12).also { System.arraycopy(nonce, SUBKEY_INPUT_BYTES, it, 4, 8) }
        return subkey to nonce2
    }

    private fun runAead(
        subkey: ByteArray,
        nonce2: ByteArray,
        aad: ByteArray,
        input: ByteArray,
        forEncryption: Boolean
    ): ByteArray {
        val cipher: AEADCipher = ChaCha20Poly1305()
        cipher.init(forEncryption, ParametersWithIV(KeyParameter(subkey), nonce2))
        cipher.processAADBytes(aad, 0, aad.size)
        val out = ByteArray(cipher.getOutputSize(input.size))
        var len = cipher.processBytes(input, 0, input.size, out, 0)
        len += try {
            cipher.doFinal(out, len)
        } catch (e: InvalidCipherTextException) {
            throw AeadAuthException("Fallo de autenticación: datos no autenticados", e)
        }
        return out.copyOf(len)
    }
}
