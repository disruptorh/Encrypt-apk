package com.reimen.cifra.crypto

import org.json.JSONException
import org.json.JSONObject
import java.util.Base64

/**
 * Sobre cifrado: serialización/deserialización del blob que viaja entre cifrar y
 * descifrar. Formato JSON → Base64 URL-safe sin padding.
 *
 * El esquema es idéntico al lado C++ (Encrypt-C++):
 *
 *   {"v":1,"aead":"xchacha20poly1305_ietf","kdf":"argon2id","ops":N,
 *    "mem_kib":N,"salt":"<b64>","nonce":"<b64>","ciphertext":"<b64>"}
 *
 * Los parámetros del KDF van DENTRO del sobre (no hardcodeados), de modo que
 * subir la fuerza en el futuro no rompe compatibilidad con textos antiguos.
 * El pepper NUNCA aparece aquí.
 */
data class Envelope(
    val version: Int,
    val aead: String,
    val kdf: String,
    val ops: Int,
    val memKib: Int,
    val salt: ByteArray,
    val nonce: ByteArray,
    val ciphertext: ByteArray
) {
    companion object {
        const val CURRENT_VERSION = 1
        const val AEAD_NAME = "xchacha20poly1305_ietf"
        const val KDF_NAME = "argon2id"
        private const val SALT_BYTES = 16
        private const val NONCE_BYTES = 24
        private const val TAG_BYTES = 16
        private const val OPS_MAX = 16
        private const val MEM_KIB_MAX = 262144

        private val ALLOWED_FIELDS = setOf("v", "aead", "kdf", "ops", "mem_kib", "salt", "nonce", "ciphertext")

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
            sb.append(",\"aead\":\"").append(envelope.aead).append('"')
            sb.append(",\"kdf\":\"").append(envelope.kdf).append('"')
            sb.append(",\"ops\":").append(envelope.ops)
            sb.append(",\"mem_kib\":").append(envelope.memKib)
            sb.append(",\"salt\":\"").append(saltB64).append('"')
            sb.append(",\"nonce\":\"").append(nonceB64).append('"')
            sb.append(",\"ciphertext\":\"").append(cipherB64).append('"')
            sb.append('}')
            return b64encode(sb.toString().toByteArray(Charsets.UTF_8))
        }

        /**
         * @throws EnvelopeException si el blob está malformado o fuera de rango
         *         (JSON inválido, Base64 inválido, campos desconocidos, parámetros
         *         imposibles...). Misma estrictez que el parser C++.
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
                // Strict: rechaza campos desconocidos (paridad con C++).
                val keys = json.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    if (k !in ALLOWED_FIELDS) throw EnvelopeException("Campo desconocido: $k")
                }

                val v = json.getInt("v")
                val aead = json.getString("aead")
                val kdf = json.getString("kdf")
                val ops = json.getInt("ops")
                val memKib = json.getInt("mem_kib")
                val salt = b64decode(json.getString("salt"))
                val nonce = b64decode(json.getString("nonce"))
                val ciphertext = b64decode(json.getString("ciphertext"))

                if (v != CURRENT_VERSION) throw EnvelopeException("Versión no soportada: $v")
                if (aead != AEAD_NAME) throw EnvelopeException("Algoritmo AEAD desconocido: $aead")
                if (kdf != KDF_NAME) throw EnvelopeException("KDF desconocido: $kdf")
                if (ops !in 1..OPS_MAX) throw EnvelopeException("ops fuera de rango: $ops")
                if (memKib !in 1..MEM_KIB_MAX) throw EnvelopeException("mem_kib fuera de rango: $memKib")
                if (salt.size != SALT_BYTES) throw EnvelopeException("salt debe tener $SALT_BYTES bytes, tiene ${salt.size}")
                if (nonce.size != NONCE_BYTES) throw EnvelopeException("nonce debe tener $NONCE_BYTES bytes, tiene ${nonce.size}")
                if (ciphertext.isEmpty()) throw EnvelopeException("ciphertext vacío")
                if (ciphertext.size < TAG_BYTES) throw EnvelopeException("ciphertext demasiado corto (falta tag)")

                Envelope(v, aead, kdf, ops, memKib, salt, nonce, ciphertext)
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
