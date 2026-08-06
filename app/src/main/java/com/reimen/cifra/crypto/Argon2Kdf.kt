package com.reimen.cifra.crypto

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

/**
 * Derivación de clave con Argon2id (RFC 9106) usando Bouncy Castle.
 *
 * El "pepper" (campo secreto adicional del usuario) se pasa como `secret` de
 * Argon2: nunca se serializa en el sobre ni se persiste en ningún sitio.
 */
object Argon2Kdf {

    const val KEY_LENGTH_BYTES = 32 // AES-256

    fun deriveKey(
        password: CharArray,
        salt: ByteArray,
        pepper: ByteArray?, // null o vacío si el usuario no aportó campo extra
        memKib: Int,
        iterations: Int,
        parallelism: Int,
        additional: ByteArray? = null // solo para validar vectores RFC 9106 en tests
    ): ByteArray {
        require(memKib in 1..262144) { "memKib fuera de rango" }
        require(iterations in 1..16) { "iterations fuera de rango" }
        require(parallelism in 1..32) { "parallelism fuera de rango" }

        val builder = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(memKib)
            .withIterations(iterations)
            .withParallelism(parallelism)
            .withSalt(salt)

        if (pepper != null && pepper.isNotEmpty()) {
            builder.withSecret(pepper)
        }
        if (additional != null && additional.isNotEmpty()) {
            builder.withAdditional(additional)
        }

        val params = builder.build()
        try {
            val generator = Argon2BytesGenerator().apply { init(params) }
            val key = ByteArray(KEY_LENGTH_BYTES)
            // generateBytes(char[], byte[]) convierte internamente con CharToByteConverter UTF-8
            generator.generateBytes(password, key)
            return key
        } finally {
            params.clear()
        }
    }
}
