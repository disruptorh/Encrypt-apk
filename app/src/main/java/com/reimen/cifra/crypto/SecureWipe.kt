package com.reimen.cifra.crypto

import java.util.Arrays

/**
 * Utilidades para sobrescribir datos sensibles antes de soltar la referencia.
 * Un ByteArray/CharArray nunca debe reciclarse en el heap sin limpiarse antes.
 */
object SecureWipe {

    fun wipe(array: ByteArray?) {
        array?.let { Arrays.fill(it, 0) }
    }

    fun wipe(array: CharArray?) {
        array?.let { Arrays.fill(it, '\u0000') }
    }

    /** Convierte CharArray a ByteArray UTF-8 sin pasar por un String inmutable. */
    fun toUtf8Bytes(chars: CharArray): ByteArray {
        val encoder = java.nio.charset.StandardCharsets.UTF_8.newEncoder()
        val buffer = encoder.encode(java.nio.CharBuffer.wrap(chars))
        val out = ByteArray(buffer.remaining())
        buffer.get(out)
        return out
    }

    /** Sobre-escribe y descarta el buffer (para limpiar la copia UTF-8 de la clave). */
    fun wipeAndDiscard(bytes: ByteArray?) {
        wipe(bytes)
    }
}
