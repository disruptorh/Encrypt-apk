package com.reimen.cifra.crypto

import org.json.JSONException
import org.json.JSONObject
import java.util.Base64

/**
 * Sobre cifrado: serialización/deserialización del blob que viaja entre cifrar y
 * descifrar. Formato JSON → Base64 URL-safe sin padding.
 *
 * Los parámetros del KDF van DENTRO del sobre (no hardcodeados), de modo que
 * subir la fuerza en el futuro no rompe compatibilidad con textos antiguos.
 * El pepper NUNCA aparece aquí.
 */
data class Envelope(
    val version: Int,
    val kdf: String,
    val memKib: Int,
    val iterations: Int,
    val parallelism: Int,
    val salt: ByteArray,
    val nonce: ByteArray,
    val ciphertext: ByteArray
) {
    companion object {
        const val CURRENT_VERSION = 1
        const val KDF_NAME = "argon2id"
        private const val SALT_BYTES = 16
        private const val NONCE_BYTES = 12

        private fun b64encode(bytes: ByteArray): String =
            Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        private fun b64decode(s: String): ByteArray {
            require(s.isNotEmpty()) { "campo base64 vacío" }
            return Base64.getUrlDecoder().decode(s)
        }

        fun toBase64(envelope: Envelope): String {
            // Serialización a mano con StringBuilder: evita las copias internas de
            // JSONObject y el doble String que produciría en textos de decenas de MB.
            // Los únicos valores string son Base64 URL-safe (alfabeto [A-Za-z0-9_-]),
            // que no necesita ningún escaping en JSON, así que es seguro y mucho más
            // ligero en memoria.
            val saltB64 = b64encode(envelope.salt)
            val nonceB64 = b64encode(envelope.nonce)
            val cipherB64 = b64encode(envelope.ciphertext)
            val sb = StringBuilder(
                64 + saltB64.length + nonceB64.length + cipherB64.length
            )
            sb.append("{\"v\":").append(envelope.version)
            sb.append(",\"kdf\":\"").append(envelope.kdf).append('"')
            sb.append(",\"mem_kib\":").append(envelope.memKib)
            sb.append(",\"iters\":").append(envelope.iterations)
            sb.append(",\"parallelism\":").append(envelope.parallelism)
            sb.append(",\"salt\":\"").append(saltB64).append('"')
            sb.append(",\"nonce\":\"").append(nonceB64).append('"')
            sb.append(",\"ciphertext\":\"").append(cipherB64).append('"')
            sb.append('}')
            return b64encode(sb.toString().toByteArray(Charsets.UTF_8))
        }

        /**
         * @throws EnvelopeException si el blob está malformado o fuera de rango
         *         (JSON inválido, Base64 inválido, parámetros imposibles...).
         */
        fun fromBase64(blob: String): Envelope {
            val decoded: ByteArray
            try {
                decoded = b64decode(blob)
            } catch (e: IllegalArgumentException) {
                throw EnvelopeException("Base64 inválido", e)
            }

            val json: JSONObject
            try {
                json = JSONObject(String(decoded, Charsets.UTF_8))
            } catch (e: JSONException) {
                throw EnvelopeException("JSON malformado", e)
            }

            return try {
                val v = json.getInt("v")
                val kdf = json.getString("kdf")
                val memKib = json.getInt("mem_kib")
                val iters = json.getInt("iters")
                val parallelism = json.getInt("parallelism")
                val salt = b64decode(json.getString("salt"))
                val nonce = b64decode(json.getString("nonce"))
                val ciphertext = b64decode(json.getString("ciphertext"))

                if (v != CURRENT_VERSION) throw EnvelopeException("Versión no soportada: $v")
                if (kdf != KDF_NAME) throw EnvelopeException("KDF desconocido: $kdf")
                if (memKib !in 1..262144) throw EnvelopeException("mem_kib fuera de rango: $memKib")
                if (iters !in 1..16) throw EnvelopeException("iters fuera de rango: $iters")
                if (parallelism !in 1..32) throw EnvelopeException("parallelism fuera de rango: $parallelism")
                if (salt.size != SALT_BYTES) throw EnvelopeException("salt debe tener $SALT_BYTES bytes, tiene ${salt.size}")
                if (nonce.size != NONCE_BYTES) throw EnvelopeException("nonce debe tener $NONCE_BYTES bytes, tiene ${nonce.size}")
                if (ciphertext.isEmpty()) throw EnvelopeException("ciphertext vacío")
                if (ciphertext.size < 16) throw EnvelopeException("ciphertext demasiado corto (falta tag GCM)")

                Envelope(v, kdf, memKib, iters, parallelism, salt, nonce, ciphertext)
            } catch (e: EnvelopeException) {
                throw e
            } catch (e: JSONException) {
                throw EnvelopeException("Campo del sobre inválido", e)
            } catch (e: IllegalArgumentException) {
                throw EnvelopeException("Campo base64 del sobre inválido", e)
            }
        }
    }
}

class EnvelopeException(message: String, cause: Throwable? = null) : Exception(message, cause)
