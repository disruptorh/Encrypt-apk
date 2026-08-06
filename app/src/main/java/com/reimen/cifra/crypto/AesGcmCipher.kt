package com.reimen.cifra.crypto

import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-256-GCM autenticado. El tag (16 bytes) se incluye al final del ciphertext.
 */
object AesGcmCipher {

    private const val GCM_TAG_BITS = 128
    const val NONCE_BYTES = 12

    fun aesGcmEncrypt(key: ByteArray, plaintext: ByteArray): Pair<ByteArray, ByteArray> {
        val nonce = ByteArray(NONCE_BYTES).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
        val ciphertext = cipher.doFinal(plaintext)
        return nonce to ciphertext
    }

    /**
     * @throws AEADBadTagException si la clave, nonce o el contenido no coinciden
     *         (contraseña/pepper incorrectos, o ciphertext manipulado).
     */
    fun aesGcmDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
        return cipher.doFinal(ciphertext)
    }
}
