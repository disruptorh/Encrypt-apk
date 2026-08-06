package com.reimen.cifra.crypto

import java.security.SecureRandom
import javax.crypto.AEADBadTagException

/**
 * Única puerta de entrada de la criptografía de la app.
 *
 * Cifrar:   salt aleatorio → Argon2id(password, salt, pepper) → AES-256-GCM → sobre → Base64.
 * Descifrar: sobre → parámetros del sobre → misma derivación → GCM → texto plano.
 *
 * La capa crypto no conoce Android: solo usa JCA, Bouncy Castle y java.util.
 */
object CryptoEngine {

    /** Perfil de fuerza del KDF. Los valores se serializan en el sobre. */
    data class KdfProfile(
        val memKib: Int,
        val iterations: Int,
        val parallelism: Int,
        val label: String
    ) {
        companion object {
            val STANDARD = KdfProfile(65536, 3, 4, "Estándar")
            val MAXIMUM = KdfProfile(262144, 6, 4, "Máxima")
            val ALL = listOf(STANDARD, MAXIMUM)
        }
    }

    class CryptoException(message: String, cause: Throwable? = null) : Exception(message, cause)

    // Presupuesto de memoria conservador para evitar OutOfMemoryError.
    // El pico estimado ≈ memoria del KDF + 10× el texto (copias en bytes, UTF-16,
    // Base64, JSON y sobre) + la base de la propia app/UI.
    private const val BASELINE_MEMORY_BYTES = 48L * 1024 * 1024
    private const val TEXT_OVERHEAD_FACTOR = 10L
    private const val BUDGET_FRACTION = 0.9

    private const val MEMORY_ERROR_MESSAGE =
        "Memoria insuficiente para procesar este contenido. Reduce el tamaño o usa el perfil Estándar."

    /**
     * ¿Cabe [plaintextBytes] con un KDF de [kdfMemKib] KiB dentro del heap disponible?
     * Evita que un bloque gigante o un perfil máximo lancen OutOfMemoryError.
     */
    fun checkSizeBudget(kdfMemKib: Int, plaintextBytes: Long): Boolean {
        val maxHeap = Runtime.getRuntime().maxMemory()
        if (maxHeap <= 0) return true
        // Tamaños absurdos → seguro que no caben (y evita desbordar Long).
        if (plaintextBytes > (Long.MAX_VALUE - BASELINE_MEMORY_BYTES) / TEXT_OVERHEAD_FACTOR) return false
        val estimated = BASELINE_MEMORY_BYTES +
            kdfMemKib.toLong() * 1024L +
            plaintextBytes * TEXT_OVERHEAD_FACTOR
        return estimated < maxHeap * BUDGET_FRACTION
    }

    private fun sizeMb(bytes: Long): String = String.format("%.1f", bytes / (1024.0 * 1024.0))

    /**
     * @param plaintext  texto a cifrar (UTF-8 del usuario).
     * @param password   contraseña obligatoria (CharArray; no se modifica aquí).
     * @param pepper     campo secreto opcional (CharArray) o null.
     * @param profile    fuerza del KDF.
     * @return blob Base64 URL-safe del sobre.
     */
    fun encrypt(
        plaintext: ByteArray,
        password: CharArray,
        pepper: CharArray?,
        profile: KdfProfile
    ): String {
        if (password.isEmpty()) throw CryptoException("La contraseña es obligatoria")
        if (!checkSizeBudget(profile.memKib, plaintext.size.toLong())) {
            throw CryptoException(
                "El texto de ${sizeMb(plaintext.size.toLong())} MB es demasiado grande para el perfil " +
                    "${profile.label} (${profile.memKib / 1024} MiB de memoria). " +
                    "Usa el perfil Estándar o reduce el texto."
            )
        }

        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val pepperBytes = pepper?.let { p -> if (p.isEmpty()) null else SecureWipe.toUtf8Bytes(p) }
        var key: ByteArray? = null
        try {
            key = Argon2Kdf.deriveKey(
                password = password,
                salt = salt,
                pepper = pepperBytes,
                memKib = profile.memKib,
                iterations = profile.iterations,
                parallelism = profile.parallelism
            )
            // Los bloques de memoria de Argon2 ya no son alcanzables: dale al GC la
            // oportunidad de liberarlos ANTES de reservar ciphertext/sobre, para no
            // sumar ambos picos de memoria.
            Runtime.getRuntime().gc()
            val (nonce, ciphertext) = AesGcmCipher.aesGcmEncrypt(key, plaintext)
            val envelope = Envelope(
                version = Envelope.CURRENT_VERSION,
                kdf = Envelope.KDF_NAME,
                memKib = profile.memKib,
                iterations = profile.iterations,
                parallelism = profile.parallelism,
                salt = salt,
                nonce = nonce,
                ciphertext = ciphertext
            )
            return Envelope.toBase64(envelope)
        } catch (e: OutOfMemoryError) {
            throw CryptoException(MEMORY_ERROR_MESSAGE, e)
        } finally {
            SecureWipe.wipe(pepperBytes)
            SecureWipe.wipe(key)
        }
    }

    /**
     * @param blob      sobre Base64.
     * @param password  contraseña (CharArray; no se modifica aquí).
     * @param pepper    campo secreto opcional (CharArray) o null.
     * @return texto plano en UTF-8.
     * @throws CryptoException si el sobre es inválido, la contraseña/pepper son
     *         incorrectos o el ciphertext fue manipulado (nunca un crash sin manejar).
     */
    fun decrypt(
        blob: String,
        password: CharArray,
        pepper: CharArray?
    ): ByteArray {
        if (blob.isBlank()) throw CryptoException("No hay sobre que descifrar")
        if (password.isEmpty()) throw CryptoException("La contraseña es obligatoria")

        val envelope = try {
            Envelope.fromBase64(blob)
        } catch (e: EnvelopeException) {
            throw CryptoException("Sobre inválido: ${e.message}", e)
        }

        // El sobre es Base64 (~4/3 del texto original): estima el tamaño en claro
        // para aplicar el mismo presupuesto que en el cifrado.
        val estimatedPlaintext = blob.length.toLong() * 3L / 4L
        if (!checkSizeBudget(envelope.memKib, estimatedPlaintext)) {
            throw CryptoException(
                "Este sobre requiere ${envelope.memKib / 1024} MiB de memoria (perfil del sobre). " +
                    "Memoria insuficiente en este dispositivo para descifrarlo."
            )
        }

        val pepperBytes = pepper?.let { p -> if (p.isEmpty()) null else SecureWipe.toUtf8Bytes(p) }
        var key: ByteArray? = null
        try {
            key = Argon2Kdf.deriveKey(
                password = password,
                salt = envelope.salt,
                pepper = pepperBytes,
                memKib = envelope.memKib,
                iterations = envelope.iterations,
                parallelism = envelope.parallelism
            )
            Runtime.getRuntime().gc()
            return AesGcmCipher.aesGcmDecrypt(key, envelope.nonce, envelope.ciphertext)
        } catch (e: AEADBadTagException) {
            throw CryptoException(
                "Fallo de autenticación: contraseña o campo secreto incorrectos, o datos manipulados", e
            )
        } catch (e: OutOfMemoryError) {
            throw CryptoException(MEMORY_ERROR_MESSAGE, e)
        } catch (e: CryptoException) {
            throw e
        } catch (e: Exception) {
            throw CryptoException("Error al descifrar: ${e.message}", e)
        } finally {
            SecureWipe.wipe(pepperBytes)
            SecureWipe.wipe(key)
        }
    }
}
