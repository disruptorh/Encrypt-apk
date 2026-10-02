package com.reimen.cifra.crypto

import java.io.ByteArrayOutputStream
import java.io.OutputStream

/**
 * Base64 URL-safe **por trozos** (RFC 4648 §5, sin padding).
 *
 * `java.util.Base64` solo sabe de bloques enteros: obliga a materializar el
 * mensaje completo tres veces (bytes → cadena → bytes) antes de poder escribir
 * nada. Con textos de decenas de MB eso es la diferencia entre funcionar y
 * reventar el heap. Aquí el codificador y el decodificador son máquinas de
 * estado que se alimentan trozo a trozo, así que el pico de memoria es
 * constante (~64 KiB) sea cual sea el tamaño del mensaje.
 *
 * La salida es byte a byte idéntica a `java.util.Base64.getUrlEncoder()
 * .withoutPadding()`: los grupos de tres bytes se emiten igual y el resto
 * final se completa igual, de modo que el formato del sobre no cambia ni un
 * bit y la interoperabilidad con el lado C++ se mantiene.
 *
 * El decodificador es deliberadamente **tolerante** con lo que llega de
 * copiar y pegar, algo que la app no controla:
 *  - espacios, tabuladores y saltos de línea en cualquier posición,
 *  - relleno `=` al final (lo que emite el Base64 estándar),
 *  - alfabeto estándar (`+`, `/`) además del URL-safe (`-`, `_`).
 * Cualquier otro carácter sigue siendo un error, para no aceptar basura.
 */
object Base64Url {

    /** Tamaño de trozo por defecto. 48 KiB es múltiplo de 3: codifica sin arrastre. */
    const val DEFAULT_CHUNK = 48 * 1024

    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    private val DECODE_TABLE = IntArray(128) { -1 }.also { table ->
        ALPHABET.forEachIndexed { i, c -> table[c.code] = i }
        table['+'.code] = 62
        table['/'.code] = 63
    }

    /**
     * Longitud exacta de la salida para [byteCount] bytes de entrada.
     *
     * Sin relleno, como emite este codificador: los restos de 1 y 2 bytes dan
     * 2 y 3 caracteres, no 4. Reservar con la cuenta con relleno sobraba
     * caracteres de_capacity, y en un mensaje grande esa sobre-reserva era
     * justo de la que quería prescindir.
     */
    fun encodedLength(byteCount: Long): Long {
        val rem = byteCount % 3
        return byteCount / 3 * 4 + when (rem) {
            0L -> 0L
            1L -> 2L
            else -> 3L
        }
    }

    /**
     * Bytes que representa un Base64 de [charCount] caracteres **sin relleno**,
     * de forma exacta.
     *
     * Ojo con [decodedLength]: esa redondea hacia arriba a propósito, porque se
     * usa para reservar capacidad. Aquí la cifra exacta importa, porque de ella
     * depende dónde termina el campo `ciphertext` del sobre.
     */
    fun exactDecodedLength(charCount: Long): Long {
        val whole = charCount / 4
        return when (val rem = charCount % 4) {
            0L -> whole * 3
            2L -> whole * 3 + 1
            3L -> whole * 3 + 2
            else -> throw Base64Exception("Base64 inválido: longitud imposible ($charCount caracteres)")
        }
    }

    /** Bytes de carga útil que representa un Base64 de [charCount] caracteres. */
    fun decodedLength(charCount: Long): Long = (charCount + 3L) / 4L * 3L

    /** Codifica [input] escribiendo los trozos directamente en [out] (no se cierra). */
    fun encode(input: ByteArray, out: OutputStream) {
        val enc = Encoder(out)
        enc.update(input, 0, input.size)
        enc.finish()
    }

    /** Codifica a Base64 URL-safe sin padding en una sola llamada. */
    fun encode(input: ByteArray): String {
        val out = AsciiStringOutputStream(encodedLength(input.size.toLong()))
        encode(input, out)
        return out.toAsciiString()
    }

    /**
     * Decodifica [input] tolerando espacios, relleno y ambos alfabetos.
     * @throws Base64Exception si hay caracteres no permitidos o la longitud no
     *         puede corresponder a datos Base64 válidos.
     */
    fun decode(input: CharSequence): ByteArray {
        val capacity = try {
            exactDecodedLength(input.length.toLong()).toInt()
        } catch (e: Base64Exception) {
            0
        }
        val out = ByteArrayOutputStream(capacity.coerceAtLeast(16))
        val dec = Decoder { bytes, off, len -> out.write(bytes, off, len) }
        dec.update(input, 0, input.length)
        dec.finish()
        return out.toByteArray()
    }

    /**
     * Codificador incremental. Arrastra 0-2 bytes entre trozos, así que el
     * resultado no depende de cómo se corte la entrada.
     */
    class Encoder(out: OutputStream) : OutputStream() {

        private val out = out
        // Tres bytes, no dos: con dos bytes de arrastre ya queda lleno, y el
        // byte que completa el grupo no cabe. Con 1 se quedaba corto.
        private val carry = ByteArray(3)
        private var carryLen = 0
        private val group = ByteArray(4)

        /** Como [OutputStream], para poder encadenar codificadores sin adaptadores. */
        override fun write(b: Int) = update(byteArrayOf(b.toByte()), 0, 1)

        override fun write(b: ByteArray, off: Int, len: Int) = update(b, off, len)

        override fun close() {
            finish()
            out.close()
        }

        fun update(input: ByteArray, off: Int, len: Int) {
            if (len <= 0) return
            var i = off
            val end = off + len

            // Completa el grupo pendiente antes de emitir los grupos completos.
            if (carryLen > 0) {
                val need = 3 - carryLen
                val take = minOf(need, end - i)
                System.arraycopy(input, i, carry, carryLen, take)
                i += take
                carryLen += take
                if (carryLen < 3) return
                emit(carry, 0, 3)
                carryLen = 0
            }

            val whole = ((end - i) / 3) * 3
            var p = i
            val limit = i + whole
            while (p < limit) {
                emit(input, p, 3)
                p += 3
            }
            if (p < end) {
                carryLen = end - p
                System.arraycopy(input, p, carry, 0, carryLen)
            }
        }

        fun finish() {
            when (carryLen) {
                0 -> return
                1 -> {
                    val b0 = carry[0].toInt() and 0xFF
                    group[0] = ALPHABET[b0 shr 2].code.toByte()
                    group[1] = ALPHABET[(b0 shl 4) and 0x3F].code.toByte()
                    out.write(group, 0, 2)
                }
                else -> {
                    val b0 = carry[0].toInt() and 0xFF
                    val b1 = carry[1].toInt() and 0xFF
                    group[0] = ALPHABET[b0 shr 2].code.toByte()
                    group[1] = ALPHABET[((b0 shl 4) or (b1 shr 4)) and 0x3F].code.toByte()
                    group[2] = ALPHABET[(b1 shl 2) and 0x3F].code.toByte()
                    out.write(group, 0, 3)
                }
            }
            carryLen = 0
        }

        private fun emit(src: ByteArray, off: Int, count: Int) {
            val b0 = src[off].toInt() and 0xFF
            val b1 = src[off + 1].toInt() and 0xFF
            val b2 = src[off + 2].toInt() and 0xFF
            group[0] = ALPHABET[b0 shr 2].code.toByte()
            group[1] = ALPHABET[((b0 shl 4) or (b1 shr 4)) and 0x3F].code.toByte()
            group[2] = ALPHABET[((b1 shl 2) or (b2 shr 6)) and 0x3F].code.toByte()
            group[3] = ALPHABET[b2 and 0x3F].code.toByte()
            out.write(group, 0, 4)
        }
    }

    /**
     * Decodificador incremental. Reúne un grupo de cuatro sextetos cada vez y
     * arrastra el grupo a medio entre trozos, así que un Base64 partido en
     * trozos arbitrarios decodifica igual que uno entero.
     */
    class Decoder(private val sink: (ByteArray, Int, Int) -> Unit) {

        private val triple = ByteArray(3)
        private var quad = 0
        private var quadLen = 0
        private var sawPadding = false

        fun update(input: CharSequence, off: Int, len: Int) {
            val end = off + len
            for (i in off until end) feed(input[i])
        }

        /**
         * Variante sobre bytes, para decodificar sin materializar un String
         * intermedio: el contenido del sobre ya son bytes UTF-8/ASCII y
         * multiplicarlos por dos al convertirlos es justo lo que se quiere
         * evitar.
         *
         * Cada byte se interpreta como su equivalente Latin-1, que es lo mismo
         * que habría dado la cadena.
         */
        fun update(bytes: ByteArray, off: Int, len: Int) {
            val end = off + len
            for (i in off until end) feed((bytes[i].toInt() and 0xff).toChar())
        }

        private fun feed(c: Char) {
            if (c == '\n' || c == '\r' || c == ' ' || c == '\t' || c == '\u000B' || c == '\u000C') return
            if (c == '=') {
                sawPadding = true
                return
            }
            if (sawPadding) throw Base64Exception("Base64 inválido: carácter '$c' después del relleno")
            val v = if (c.code < DECODE_TABLE.size) DECODE_TABLE[c.code] else -1
            if (v < 0) throw Base64Exception("Base64 inválido: carácter no permitido '$c'")
            quad = (quad shl 6) or v
            quadLen++
            if (quadLen == 4) {
                triple[0] = (quad ushr 16).toByte()
                triple[1] = (quad ushr 8).toByte()
                triple[2] = quad.toByte()
                sink(triple, 0, 3)
                quad = 0
                quadLen = 0
            }
        }

        fun finish() {
            when (quadLen) {
                0 -> return
                1 -> throw Base64Exception("Base64 inválido: sobra un carácter suelto")
                2 -> {
                    // 12 bits: 8 del primer byte y 4 de sobra, que se descartan.
                    triple[0] = (quad ushr 4).toByte()
                    sink(triple, 0, 1)
                }
                else -> {
                    // 18 bits: 8 + 8 y 2 de relleno. El segundo byte sale del
                    // sexteto alto que queda tras quitar los 2 bits de relleno,
                    // no de los bits bajos: `quad.toByte()` aquí devolvía basura
                    // y corrompía el último byte de cada Base64 sin padding cuyo
                    // tamaño no fuese múltiplo de 3.
                    triple[0] = (quad ushr 10).toByte()
                    triple[1] = (quad ushr 2).toByte()
                    sink(triple, 0, 2)
                }
            }
            quad = 0
            quadLen = 0
        }
    }
}

/** Base64 malformado: carácter inesperado o longitud imposible. */
class Base64Exception(message: String) : Exception(message)

/**
 * `ByteArrayOutputStream` que sabe convertirse a cadena sin pasar por la
 * decodificación con juego de caracteres: el Base64 es ASCII puro, así que
 * basta con ensanchar los bytes LATIN-1 y convertir.
 */
internal class AsciiStringOutputStream(expectedSize: Long) : ByteArrayOutputStream(
    if (expectedSize in 1..MAX_INITIAL) expectedSize.toInt() else DEFAULT_INITIAL
) {
    fun toAsciiString(): String = String(toByteArray(), 0, size(), Charsets.US_ASCII)

    private companion object {
        const val MAX_INITIAL = 32L * 1024 * 1024
        const val DEFAULT_INITIAL = 1024
    }
}
