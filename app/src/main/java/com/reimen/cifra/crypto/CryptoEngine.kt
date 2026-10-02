package com.reimen.cifra.crypto

import java.security.SecureRandom
import java.util.Locale

/**
 * Única puerta de entrada de la criptografía de la app.
 *
 * Cifrar:   salt aleatorio → Argon2id(password, salt, pepper, p=1) → clave →
 *           XChaCha20-Poly1305(plaintext, AAD = parámetros del sobre) → sobre → Base64.
 * Descifrar: sobre → parámetros del sobre → misma derivación → AEAD → texto plano.
 *
 * El esquema criptográfico es byte-a-byte compatible con el lado C++
 * (Encrypt-C++): mismo KDF (Argon2id con p=1 y binding de pepper por BLAKE2b),
 * mismo AEAD (XChaCha20-Poly1305 de libsodium), mismo sobre JSON/Base64 y el
 * AAD autentica los parámetros del KDF dentro del tag.
 *
 * La capa crypto no conoce Android: solo usa JCA, Bouncy Castle y java.util.
 */
object CryptoEngine {

    /** Perfil de fuerza del KDF. Los valores se serializan en el sobre. */
    data class KdfProfile(
        val memKib: Int,
        val iterations: Int,
        val label: String
    ) {
        companion object {
            val STANDARD = KdfProfile(65536, 3, "Estándar")
            val MAXIMUM = KdfProfile(262144, 6, "Máxima")
            val ALL = listOf(STANDARD, MAXIMUM)
        }
    }

    class CryptoException(message: String, cause: Throwable? = null) : Exception(message, cause)

    // libsodium (lado C++) deriva con p=1 hardcodeado: no se serializa en el
    // sobre porque nunca cambia.
    private const val KDF_PARALLELISM = 1

    // Presupuesto de memoria conservador para evitar OutOfMemoryError.
    //
    // El coste depende de si el mensaje llega entero en memoria o a trozos, y la
    // diferencia no es un detalle: ver [ContentCost].
    private const val BASELINE_MEMORY_BYTES = 48L * 1024 * 1024
    private const val TEXT_OVERHEAD_FACTOR = 10L
    private const val BUDGET_FRACTION = 0.9

    private const val MEMORY_ERROR_MESSAGE =
        "Memoria insuficiente para procesar este contenido. Reduce el tamaño o usa el perfil Estándar."

    private const val AUTH_ERROR_MESSAGE =
        "Fallo de autenticación: contraseña o campo secreto incorrectos, o datos manipulados"

    /**
     * De dónde viene el contenido y, por tanto, cómo se comporta la memoria.
     *
     * Es la diferencia entre "la app puede cifrar un archivo de 40 GB" y "la app
     * se niega a cifrar un archivo de 40 MB", así que no es un detalle interno.
     */
    enum class ContentCost {
        /** El mensaje está entero en un `ByteArray` o un `String`. */
        IN_MEMORY,

        /**
         * El mensaje entra y sale por trozos ([startEncrypting] /
         * [startDecrypting]). El pico de memoria es el búfer de trabajo, no el
         * tamaño del archivo, así que el archivo puede ser arbitrariamente
         * grande.
         */
        STREAMED
    }

    /**
     * ¿Cabe [plaintextBytes] con un KDF de [kdfMemKib] KiB dentro del heap disponible?
     * Evita que un bloque gigante o un perfil máximo lancen OutOfMemoryError.
     *
     * Con [ContentCost.IN_MEMORY] el pico escala con el mensaje (el sobre son dos
     * capas de Base64, más el JSON y las copias intermedias: [TEXT_OVERHEAD_FACTOR]
     * es deliberadamente pesimista). Con [ContentCost.STREAMED] el pico no depende
     * del tamaño, porque nada se materializa entero.
     */
    fun checkSizeBudget(kdfMemKib: Int, plaintextBytes: Long, cost: ContentCost = ContentCost.IN_MEMORY): Boolean {
        val maxHeap = Runtime.getRuntime().maxMemory()
        if (maxHeap <= 0) return true
        // Tamaños absurdos → seguro que no caben (y evita desbordar Long).
        if (plaintextBytes > (Long.MAX_VALUE - BASELINE_MEMORY_BYTES) / TEXT_OVERHEAD_FACTOR) return false
        val contentBytes =
            if (cost == ContentCost.STREAMED) 0L else plaintextBytes * TEXT_OVERHEAD_FACTOR
        val estimated = BASELINE_MEMORY_BYTES + kdfMemKib.toLong() * 1024L + contentBytes
        return estimated < maxHeap * BUDGET_FRACTION
    }

    private fun sizeMb(bytes: Long): String = String.format(Locale.ROOT, "%.1f", bytes / (1024.0 * 1024.0))

    // =======================================================================
    // API en streaming
    // =======================================================================
    //
    // Lo de abajo es el camino que usa la app de verdad. Las funciones
    // [encrypt]/[decrypt] de una sola pasada se quedan para mensajes pequeños y
    // para los tests, pero no para el grueso: aquí el pico de memoria es el del
    // KDF más unos pocos búferes, así que no depende del tamaño del texto.

    /** Tamaño de búfer de las copias intermedias del pipeline en streaming. */
    const val CHUNK_BYTES = 64 * 1024

    /** Nombra los tramos del cifrado para la interfaz. */
    enum class Stage { PREPARANDO, CIFRANDO, DESCIFRANDO, TERMINANDO }

    /** Datos de progreso, pensados para que la UI los use tal cual. */
    data class Progress(
        val stage: Stage,
        /** Bytes de texto ya procesados. */
        val doneBytes: Long,
        /** Total esperado, o -1 si aún no se sabe. */
        val totalBytes: Long
    ) {
        /** 0.0..1.0, o null si el total aún no se conoce. */
        val fraction: Float?
            get() = if (totalBytes <= 0) null else (doneBytes.toDouble() / totalBytes).coerceIn(0.0, 1.0).toFloat()
    }

    /** Llave ya derivada y lista para cifrar o descifrar, que se cierra sola. */
    class KeyHandle internal constructor(
        internal val key: ByteArray,
        internal val header: EnvelopeHeader
    ) : AutoCloseable {
        override fun close() = SecureWipe.wipe(key)
    }

    /**
     * Prepara el cifrado: deriva la clave y monta el sobre en [out].
     *
     * A partir de aquí el llamante va entregando trozos de texto con
     * [write] y cierra con [Encryption.close]. El sobre va saliendo por [out] a
     * medida que se cifra, así que nada depende de que el mensaje quepa entero.
     *
     * @param plaintextBytes tamaño esperado del texto, solo para el presupuesto
     *        y el progreso: si no se sabe, -1.
     */
    fun startEncrypting(
        password: CharArray,
        pepper: CharArray?,
        profile: KdfProfile,
        plaintextBytes: Long,
        out: java.io.OutputStream
    ): Encryption {
        if (password.isEmpty()) throw CryptoException("La contraseña es obligatoria")
        // `STREAMED`: el texto entra a trozos y el sobre sale por `out`, así que
        // su tamaño no limita nada. Lo único que tiene que caber es el KDF.
        if (plaintextBytes >= 0 && !checkSizeBudget(profile.memKib, plaintextBytes, ContentCost.STREAMED)) {
            throw CryptoException(tooBigMessage(profile))
        }
        val salt = ByteArray(Envelope.SALT_BYTES).also { SecureRandom().nextBytes(it) }
        val nonce = ByteArray(XChaCha20Poly1305.NONCE_BYTES).also { SecureRandom().nextBytes(it) }
        val key = derive(password, salt, pepper, profile)
        val writer = try {
            EnvelopeWriter.new(out, profile.iterations, profile.memKib, salt, nonce)
        } catch (e: Throwable) {
            SecureWipe.wipe(key)
            throw e
        }
        return Encryption(
            XChaCha20Poly1305.Encryptor(key, nonce, aadOf(Envelope.CURRENT_VERSION, profile)),
            writer, key, plaintextBytes, salt, nonce, profile
        )
    }

    /** Cifrado en curso. Hay que cerrarlo siempre, también al abortar. */
    class Encryption internal constructor(
        private val enc: XChaCha20Poly1305.Encryptor,
        private val writer: EnvelopeWriter,
        private val key: ByteArray,
        private val plaintextBytes: Long,
        private val salt: ByteArray,
        private val nonce: ByteArray,
        private val profile: KdfProfile
    ) : AutoCloseable {
        private val buffer = ByteArray(CHUNK_BYTES)
        private var plaintextSeen = 0L
        private var closed = false

        /** Bytes de plaintext escritos hasta ahora. */
        val bytesWritten: Long get() = plaintextSeen

        fun write(input: ByteArray, off: Int, len: Int) {
            check(!closed) { "El cifrado ya está cerrado" }
            if (len <= 0) return
            var p = off
            val end = off + len
            while (p < end) {
                val n = minOf(CHUNK_BYTES, end - p)
                val produced = enc.update(input, p, n, buffer, 0)
                writer.write(buffer, 0, produced)
                p += n
                plaintextSeen += n
            }
        }

        fun write(input: ByteArray) = write(input, 0, input.size)

        /** Escribe el tag, cierra el campo y el Base64 exterior. */
        fun finish(): Long {
            check(!closed) { "El cifrado ya está cerrado" }
            val n = enc.finish(buffer, 0)
            writer.write(buffer, 0, n)
            writer.finish()
            closed = true
            return plaintextSeen
        }

        override fun close() {
            if (closed) return
            closed = true
            writer.close()
            enc.close()
            SecureWipe.wipe(key)
            SecureWipe.wipe(salt)
            SecureWipe.wipe(nonce)
        }
    }

    /**
     * Prepara el descifrado de un sobre de [blobBytes] bytes.
     *
     * [open] **debe devolver una lectura nueva desde el principio cada vez que se
     * llame**: la cabecera se lee en una pasada y el ciphertext en otra, así que
     * se invoca dos veces. Pasar la misma instancia ya consumida —`{ unFlujo }` en
     * vez de `{ abrirFlujo() }`— no da un error claro, falla más tarde con un
     * `IOException: Stream Closed` desde dentro del lector, que no dice nada de
     * la causa real. Es la razón de que
     * [EnvelopeReader.readHeader] insista en lo mismo.
     *
     * @param blobBytes tamaño del blob, o `<= 0` si no se conoce. Un tamaño
     *        desconocido está permitido y no impide descifrar.
     * @param open      abre una lectura nueva del blob, desde el principio.
     */
    fun startDecrypting(
        blobBytes: Long,
        open: () -> java.io.InputStream,
        password: CharArray,
        pepper: CharArray?
    ): Decryption {
        if (password.isEmpty()) throw CryptoException("La contraseña es obligatoria")
        val header = try {
            EnvelopeReader.readHeader(blobBytes, open)
        } catch (e: EnvelopeException) {
            throw CryptoException("Sobre inválido: ${e.message}", e)
        }
        if (!checkSizeBudget(header.memKib, header.plaintextBytes, ContentCost.STREAMED)) {
            throw CryptoException(
                "Este sobre requiere ${header.memKib / 1024} MiB de memoria (perfil del sobre). " +
                    "Memoria insuficiente en este dispositivo para descifrarlo."
            )
        }
        val key = derive(password, header.salt, pepper, profileOf(header))
        val dec = try {
            XChaCha20Poly1305.Decryptor(key, header.nonce, header.aad())
        } catch (e: Throwable) {
            SecureWipe.wipe(key)
            throw e
        }
        return Decryption(header, key, dec, blobBytes, open)
    }

    /**
     * Descifrado en curso.
     *
     * El tag solo puede comprobarse cuando ha pasado todo el ciphertext, así
     * que los últimos 16 bytes se retienen: [decrypt] entrega a [emit] el texto
     * ya descifrado pero **sin verificar**. Si el tag no cuadra, lo entregado
     * queda sin validar y es del llamante decidir si lo tira; por eso la app lo
     * escribe siempre en un temporal y solo lo publica al final.
     */
    class Decryption internal constructor(
        private val header: EnvelopeHeader,
        private val key: ByteArray,
        private val dec: XChaCha20Poly1305.Decryptor,
        private val blobBytes: Long,
        private val open: () -> java.io.InputStream
    ) : AutoCloseable {

        /** Bytes de plaintext que van a salir (aproximado si el blob traía relleno). */
        val expectedPlaintextBytes: Long get() = header.plaintextBytes

        // `stage` guarda el ciphertext aún sin descifrar; los últimos TAG_BYTES
        // quedan siempre reservados al final para no tocarlos hasta el cierre.
        private val stage = ByteArray(CHUNK_BYTES + XChaCha20Poly1305.TAG_BYTES)
        private val out = ByteArray(CHUNK_BYTES)
        private var staged = 0
        private var ciphertextSeen = 0L
        private var plaintextEmitted = 0L
        private var closed = false

        /** Bytes de plaintext ya entregados. */
        val bytesEmitted: Long get() = plaintextEmitted

        /**
         * Descifra el sobre entero y entrega el texto a [emit], en orden y sin
         * el tag.
         *
         * @param emit recibe los trozos de texto plano.
         * @throws CryptoException si el sobre está malformado o el tag no cuadra.
         */
        fun decrypt(emit: (ByteArray, Int, Int) -> Unit) {
            try {
                EnvelopeReader.streamCiphertext(header, blobBytes, open) { bytes, off, len ->
                    stage(bytes, off, len, emit)
                }
                if (staged < XChaCha20Poly1305.TAG_BYTES) {
                    throw EnvelopeException("Sobre inválido: el ciphertext no incluye el tag")
                }
                try {
                    dec.finish(stage, 0)
                } catch (e: AeadAuthException) {
                    throw CryptoException(AUTH_ERROR_MESSAGE, e)
                }
            } catch (e: EnvelopeException) {
                throw CryptoException("Sobre inválido: ${e.message}", e)
            } catch (e: OutOfMemoryError) {
                throw CryptoException(MEMORY_ERROR_MESSAGE, e)
            } finally {
                SecureWipe.wipe(stage)
                SecureWipe.wipe(out)
                closed = true
            }
        }

        /**
         * Apila el ciphertext que llega y descifra en cuanto hay un trozo que no
         * puede contener el tag.
         */
        private fun stage(bytes: ByteArray, off: Int, len: Int, emit: (ByteArray, Int, Int) -> Unit) {
            if (len <= 0) return
            ciphertextSeen += len
            if (ciphertextSeen > header.ciphertextBytes) {
                throw EnvelopeException("Sobre malformado: más ciphertext del declarado")
            }
            var p = off
            var remaining = len
            while (remaining > 0) {
                val space = stage.size - XChaCha20Poly1305.TAG_BYTES - staged
                val take = minOf(remaining.toLong(), space.toLong()).toInt()
                System.arraycopy(bytes, p, stage, staged, take)
                staged += take
                p += take
                remaining -= take

                // Todo lo apilado salvo los últimos TAG_BYTES ya está fuera de
                // peligro: se descifra y se entrega.
                val safe = staged - XChaCha20Poly1305.TAG_BYTES
                if (safe > 0) {
                    val n = dec.update(stage, 0, safe, out, 0)
                    plaintextEmitted += n
                    emit(out, 0, n)
                    // El tag sigue al final del buffer: se compacta al principio.
                    System.arraycopy(stage, safe, stage, 0, XChaCha20Poly1305.TAG_BYTES)
                    staged = XChaCha20Poly1305.TAG_BYTES
                }
            }
        }

        override fun close() {
            if (closed) return
            closed = true
            SecureWipe.wipe(stage)
            SecureWipe.wipe(out)
            dec.close()
            SecureWipe.wipe(key)
        }
    }

    private fun aadOf(version: Int, profile: KdfProfile): ByteArray =
        buildAad(version, Envelope.AEAD_NAME, Envelope.KDF_NAME, profile.iterations, profile.memKib)

    private fun profileOf(header: EnvelopeHeader): KdfProfile =
        KdfProfile(header.memKib, header.ops, labelOf(header))

    private fun labelOf(header: EnvelopeHeader): String =
        if (header.memKib == KdfProfile.MAXIMUM.memKib) KdfProfile.MAXIMUM.label else KdfProfile.STANDARD.label

    private fun derive(
        password: CharArray,
        salt: ByteArray,
        pepper: CharArray?,
        profile: KdfProfile
    ): ByteArray {
        val pepperBytes = pepper?.let { p -> if (p.isEmpty()) null else SecureWipe.toUtf8Bytes(p) }
        try {
            return Argon2Kdf.deriveKey(
                password = password,
                salt = salt,
                pepper = pepperBytes,
                memKib = profile.memKib,
                iterations = profile.iterations,
                parallelism = KDF_PARALLELISM
            )
        } finally {
            SecureWipe.wipe(pepperBytes)
        }
    }

    /**
     * Solo llega aquí si el perfil del KDF no cabe en el heap. El tamaño del
     * archivo no tiene nada que ver (va a trozos), así que el mensaje no culpa al
     * archivo: sería advice inútil, y el más grave, "reduce el texto", no lleva
     * a ninguna parte.
     */
    private fun tooBigMessage(profile: KdfProfile): String =
        if (profile == KdfProfile.STANDARD) {
            "El perfil ${profile.label} (${profile.memKib / 1024} MiB de memoria para el KDF) " +
                "no cabe en la memoria disponible en este dispositivo."
        } else {
            "El perfil ${profile.label} (${profile.memKib / 1024} MiB de memoria para el KDF) " +
                "no cabe en la memoria disponible. Usa el perfil Estándar (64 MiB)."
        }

    /**
     * AAD estable y desacoplado: "v|aead|kdf|ops|mem_kib" (misma cadena que
     * `envelope::build_aad` del lado C++). Autentica los parámetros del KDF
     * DENTRO del tag del AEAD: manipular "mem_kib"/"ops" en el JSON sin
     * re-cifrar provoca fallo de autenticación.
     */
    private fun buildAad(version: Int, aeadName: String, kdfName: String, ops: Int, memKib: Int): ByteArray =
        "$version|$aeadName|$kdfName|$ops|$memKib".toByteArray(Charsets.US_ASCII)

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
                parallelism = KDF_PARALLELISM
            )
            // Los bloques de memoria de Argon2 ya no son alcanzables: dale al GC la
            // oportunidad de liberarlos ANTES de reservar ciphertext/sobre, para no
            // sumar ambos picos de memoria.
            Runtime.getRuntime().gc()
            val nonce = ByteArray(XChaCha20Poly1305.NONCE_BYTES).also { SecureRandom().nextBytes(it) }
            val aad = buildAad(
                Envelope.CURRENT_VERSION, Envelope.AEAD_NAME, Envelope.KDF_NAME,
                profile.iterations, profile.memKib
            )
            val ciphertext = XChaCha20Poly1305.encrypt(key, nonce, aad, plaintext)
            val envelope = Envelope(
                version = Envelope.CURRENT_VERSION,
                aead = Envelope.AEAD_NAME,
                kdf = Envelope.KDF_NAME,
                ops = profile.iterations,
                memKib = profile.memKib,
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
                iterations = envelope.ops,
                parallelism = KDF_PARALLELISM
            )
            Runtime.getRuntime().gc()
            val aad = buildAad(envelope.version, envelope.aead, envelope.kdf, envelope.ops, envelope.memKib)
            return XChaCha20Poly1305.decrypt(key, envelope.nonce, aad, envelope.ciphertext)
        } catch (e: AeadAuthException) {
            throw CryptoException(AUTH_ERROR_MESSAGE, e)
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
