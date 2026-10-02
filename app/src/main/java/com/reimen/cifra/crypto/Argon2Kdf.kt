package com.reimen.cifra.crypto

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

/**
 * Derivación de clave con Argon2id (RFC 9106) usando Bouncy Castle.
 *
 * Formato idéntico al lado C++ (libsodium):
 *
 *   argon_key = Argon2id(password, salt, t_cost, m_cost, p = 1)
 *
 * El "pepper" (campo secreto adicional del usuario) NO se pasa como secret de
 * Argon2 (libsodium no lo soporta): se enlaza después con una cadena BLAKE2b,
 * la misma que usa `crypto_generichash` en C++:
 *
 *   pepper_key = BLAKE2b-256(pepper)
 *   final_key  = BLAKE2b-256(clave = pepper_key, mensaje = argon_key)
 *
 * Si pepper es null o vacío se devuelve argon_key tal cual.
 * El pepper nunca se serializa en el sobre ni se persiste en ningún sitio.
 */
object Argon2Kdf {

    const val KEY_LENGTH_BYTES = 32 // 256 bits

    fun deriveKey(
        password: CharArray,
        salt: ByteArray,
        pepper: ByteArray?, // null o vacío si el usuario no aportó campo extra
        memKib: Int,
        iterations: Int,
        parallelism: Int // debe ser 1 para interoperar con libsodium
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

        val params = builder.build()
        val argonKey: ByteArray
        try {
            val generator = Argon2BytesGenerator().apply { init(params) }
            argonKey = ByteArray(KEY_LENGTH_BYTES)
            // generateBytes(char[], byte[]) convierte internamente con CharToByteConverter UTF-8
            generator.generateBytes(password, argonKey)
        } finally {
            params.clear()
        }

        if (pepper == null || pepper.isEmpty()) return argonKey

        // Binding de pepper con BLAKE2b keyed (paridad con libsodium). Los dos
        // intermedios son secretos derivados y se borran: si no, quedan
        // alcanzables en el heap hasta que pase el GC.
        val pepperKey = Blake2b.hash(pepper)
        try {
            return Blake2b.hash(argonKey, key = pepperKey)
        } finally {
            SecureWipe.wipe(pepperKey)
            SecureWipe.wipe(argonKey)
        }
    }
}
