package com.reimen.cifra.crypto

import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.params.KeyParameter

/**
 * Referencia de la MAC con Bouncy Castle, usada solo en los tests para
 * contrastar la implementación propia con streaming.
 *
 * No se aporta referencia de ChaCha20 porque la API ligera de BC no expone el
 * layout del RFC 8439 (contador de 32 bits + nonce de 96 bits): su
 * `ChaChaEngine` es la variante original de 64 bits de nonce. ChaCha20 queda
 * anclado por los vectores del RFC 8439 y, en la capa AEAD, por el vector
 * generado con libsodium de `XChaCha20Poly1305Test`.
 */
internal fun referencePoly1305(key: ByteArray, input: ByteArray): ByteArray {
    val mac = Poly1305()
    mac.init(KeyParameter(key))
    mac.update(input, 0, input.size)
    val out = ByteArray(16)
    mac.doFinal(out, 0)
    return out
}
