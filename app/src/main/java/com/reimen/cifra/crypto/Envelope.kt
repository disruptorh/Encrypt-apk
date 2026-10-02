package com.reimen.cifra.crypto

import java.io.OutputStream

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
 *
 * ## Por qué hay una API en streaming
 *
 * El ciphertext es el 99 % del sobre y además queda codificado dos veces (una
 * dentro del JSON, otra el sobre entero en Base64). Con las APIs de array
 * completo eso son cuatro o cinco copias del texto claro en vuelo a la vez: el
 * pico crece ~14× y la operación muere con OutOfMemoryError aunque el heap
 * tuviera sitio de sobra.
 *
 * [EnvelopeWriter] y [EnvelopeReader] hacen lo mismo con memoria constante:
 *
 *  - [EnvelopeWriter] escribe el prefijo del JSON, va codificando el ciphertext
 *    a medida que se cifra y cierra el sobre. No hay ningún Base64 completo en
 *    memoria.
 *  - [EnvelopeReader.readHeader] recorre el blob, reconoce la cabecera (unos 200
 *    bytes) y anota dónde empieza el ciphertext y cuánto ocupa. Con eso ya se
 *    puede derivar la clave y saber cuánto plaintext habrá.
 *  - [EnvelopeReader.streamCiphertext] vuelve a abrir el blob, se salta la
 *    cabecera y entrega el ciphertext por trozos.
 *
 * El formato no cambia ni un bit: los sobres siguen siendo legibles por
 * `envelope_from_base64` del lado C++ y al revés.
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
    // El equals que genera una `data class` compara los ByteArray por
    // referencia, no por contenido: dos sobres con los mismos bytes darían
    // "distintos". Aquí la comparación es por contenido, que es lo que espera
    // cualquiera que use la clase.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Envelope) return false
        return version == other.version &&
            aead == other.aead &&
            kdf == other.kdf &&
            ops == other.ops &&
            memKib == other.memKib &&
            salt.contentEquals(other.salt) &&
            nonce.contentEquals(other.nonce) &&
            ciphertext.contentEquals(other.ciphertext)
    }

    override fun hashCode(): Int {
        var r = version
        r = 31 * r + aead.hashCode()
        r = 31 * r + kdf.hashCode()
        r = 31 * r + ops
        r = 31 * r + memKib
        r = 31 * r + salt.contentHashCode()
        r = 31 * r + nonce.contentHashCode()
        r = 31 * r + ciphertext.contentHashCode()
        return r
    }

    /** Sin esto, el toString de un `data class` vuelca el ciphertext entero. */
    override fun toString(): String =
        "Envelope(version=$version, aead=$aead, kdf=$kdf, ops=$ops, memKib=$memKib, " +
            "salt=${salt.size}B, nonce=${nonce.size}B, ciphertext=${ciphertext.size}B)"

    companion object {
        const val CURRENT_VERSION = 1
        const val AEAD_NAME = "xchacha20poly1305_ietf"
        const val KDF_NAME = "argon2id"
        const val SALT_BYTES = 16
        const val NONCE_BYTES = 24
        const val TAG_BYTES = 16
        const val OPS_MAX = 16
        const val MEM_KIB_MAX = 262144

        /**
         * Serializa el sobre completo. Cómodo para mensajes pequeños; para
         * textos grandes usa [EnvelopeWriter], que produce exactamente los
         * mismos bytes sin materializar nada.
         */
        fun toBase64(envelope: Envelope): String {
            val innerLength = Base64Url.encodedLength(envelope.ciphertext.size.toLong())
            val out = AsciiStringOutputStream(
                Base64Url.encodedLength(innerLength + 256),
            )
            val writer = EnvelopeWriter.new(
                out, ops = envelope.ops, memKib = envelope.memKib,
                salt = envelope.salt, nonce = envelope.nonce,
                version = envelope.version, aead = envelope.aead, kdf = envelope.kdf,
            )
            writer.write(envelope.ciphertext, 0, envelope.ciphertext.size)
            writer.finish()
            return out.toAsciiString()
        }

        /**
         * @throws EnvelopeException si el blob está malformado o fuera de rango
         *         (JSON inválido, Base64 inválido, campos desconocidos o
         *         duplicados, parámetros imposibles...). Misma estrictez que el
         *         parser C++, que también rechaza duplicados.
         */
        fun fromBase64(blob: String): Envelope {
            val json = try {
                Base64Url.decode(blob)
            } catch (e: Base64Exception) {
                throw EnvelopeException("Base64 inválido", e)
            }
            val header = EnvelopeReader.parseHeader(json)
            val ciphertext = ByteArray(header.ciphertextBytes.toInt())
            var written = 0L
            EnvelopeReader.streamCiphertextInMemory(json, header) { b, off, len ->
                System.arraycopy(b, off, ciphertext, written.toInt(), len)
                written += len
            }
            if (written != header.ciphertextBytes) {
                throw EnvelopeException("Sobre truncado: el ciphertext no está completo")
            }
            return header.toEnvelope(ciphertext)
        }

        /**
         * Valida los parámetros de cabecera. Se llama tanto al escribir como al
         * leer, para que no se pueda construir un sobre con parámetros que luego
         * nadie sabría descifrar.
         */
        fun validate(
            version: Int,
            aeadName: String,
            kdfName: String,
            ops: Int,
            memKib: Int,
            salt: ByteArray,
            nonce: ByteArray
        ) {
            if (version != CURRENT_VERSION) throw EnvelopeException("Versión no soportada: $version")
            if (aeadName != AEAD_NAME) throw EnvelopeException("Algoritmo AEAD desconocido: $aeadName")
            if (kdfName != KDF_NAME) throw EnvelopeException("KDF desconocido: $kdfName")
            if (ops !in 1..OPS_MAX) throw EnvelopeException("ops fuera de rango: $ops")
            if (memKib !in 1..MEM_KIB_MAX) throw EnvelopeException("mem_kib fuera de rango: $memKib")
            if (salt.size != SALT_BYTES) throw EnvelopeException("salt debe tener $SALT_BYTES bytes, tiene ${salt.size}")
            if (nonce.size != NONCE_BYTES) throw EnvelopeException("nonce debe tener $NONCE_BYTES bytes, tiene ${nonce.size}")
        }
    }
}

/** El sobre no se puede construir, analizar ni serializar. */
class EnvelopeException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Cabecera del sobre: todo lo necesario para derivar la clave y saber cuánto
 * plaintext va a salir, sin mirar el ciphertext.
 */
data class EnvelopeHeader(
    val version: Int,
    val aead: String,
    val kdf: String,
    val ops: Int,
    val memKib: Int,
    val salt: ByteArray,
    val nonce: ByteArray,
    /** Offset, dentro del JSON decodificado, del primer carácter Base64 del ciphertext. */
    val ciphertextStartInJson: Long,
    /** Caracteres Base64 del campo "ciphertext". */
    val ciphertextChars: Long
) {
    companion object {
        /**
         * Valor de [ciphertextChars] cuando la longitud del blob se desconoce.
         *
         * Hay proveedores de SAF que no declaran el tamaño de un documento hasta
         * que se lee, así que el total no puede deducirse por aritmética. En vez
         * de inventar una cifra, se deja constancia de que el límite no existe:
         * [EnvelopeReader.streamCiphertext] encuentra el final real del campo
         * por sus propios delimitadores, así que el resultado sigue siendo
         * exacto. Cualquier consumidor que use la longitud como *cota* para
         * planning debe tratar este valor como "sin límite".
         */
        const val UNKNOWN_CHARS: Long = Long.MAX_VALUE
    }
    /**
     * Bytes de ciphertext que habrá que descifrar (incluye el tag).
     *
     * [ciphertextChars] es exacto cuando la cabecera viene de [parseHeader] y
     * una cota superior —con un margen de un par de bytes— cuando viene de
     * [EnvelopeReader.readHeader], que solo conoce la longitud del blob. Para
     * planning (progreso, presupuesto) da igual; el ajuste exacto lo hace
     * [EnvelopeReader.streamCiphertext] al recorrer el campo.
     */
    val ciphertextBytes: Long
        get() {
            // Un resto de 1 no puede salir de un Base64 real: cuando la longitud
            // viene de [EnvelopeReader.readHeader] solo es una cota y puede quedar
            // desalineada por uno, porque el Base64 puede llevar relleno o
            // espacios que el conteo no puede ver. Se descarta ese carácter suelta
            // en vez de fallar, porque aquí la cifra solo sirve para planning; el
            // ajuste real lo hace [EnvelopeReader.streamCiphertext] al recorrer
            // el campo.
            val c = if (ciphertextChars % 4 == 1L) ciphertextChars - 1 else ciphertextChars
            return c / 4 * 3 + when (c % 4) {
                0L -> 0L
                2L -> 1L
                else -> 2L
            }
        }

    /**
     * Bytes de plaintext esperados: el ciphertext menos el tag.
     *
     * Con [UNKNOWN_CHARS] sale una cifra enorme, no un número real: es
     * deliberado, porque lo que se quiere transmitir es "no lo sé, no prometas
     * nada", y eso hace que la interfaz saque el destino a un archivo en vez de
     * intentar pintarlo en pantalla.
     */
    val plaintextBytes: Long get() = ciphertextBytes - Envelope.TAG_BYTES

    /**
     * AAD estable y desacoplado: `v|aead|kdf|ops|mem_kib` (la misma cadena que
     * devuelve `build_aad` del lado C++). Autentica los parámetros del KDF
     * DENTRO del tag del AEAD: cambiar "mem_kib"/"ops" en el JSON sin re-cifrar
     * provoca fallo de autenticación.
     */
    fun aad(): ByteArray = "$version|$aead|$kdf|$ops|$memKib".toByteArray(Charsets.US_ASCII)

    fun toEnvelope(ciphertext: ByteArray): Envelope =
        Envelope(version, aead, kdf, ops, memKib, salt, nonce, ciphertext)
}

/**
 * Escribe un sobre sin materializar ni el ciphertext ni su Base64.
 *
 * ```
 * val w = EnvelopeWriter.new(out, ops = 3, memKib = 65536, salt = salt, nonce = nonce)
 * // ... cifra un trozo y escríbelo:
 * w.update(chunk, 0, n)
 * w.finish()
 * ```
 *
 * Hereda de [OutputStream] para poder enchufarse tal cual detrás de un troceo
 * cifrado sin montar un buffer intermedio.
 */
class EnvelopeWriter private constructor(
    out: OutputStream,
    version: Int,
    aead: String,
    kdf: String,
    ops: Int,
    memKib: Int,
    salt: ByteArray,
    nonce: ByteArray
) : OutputStream() {

    /**
     * El JSON del sobre alimenta el codificador exterior. Entre las dos capas
     * hay un búfer porque los codificadores de Base64 escriben de cuatro en
     * cuatro caracteres: sin agrupar, el escritor de destino recibiría cientos
     * de millones de llamadas diminutas.
     */
    private val outerEncoder = Base64Url.Encoder(out)
    private val jsonToBase64 = ChunkBuffer(outerEncoder)
    private val ciphertextToJson = Base64Url.Encoder(jsonToBase64)

    /** Bytes de ciphertext escritos hasta ahora, para el progreso y el presupuesto. */
    var bytesWritten: Long = 0
        private set

    private var closed = false

    init {
        writeAscii(
            buildString {
                append("{\"v\":").append(version)
                append(",\"aead\":\"").append(aead).append('"')
                append(",\"kdf\":\"").append(kdf).append('"')
                append(",\"ops\":").append(ops)
                append(",\"mem_kib\":").append(memKib)
                append(",\"salt\":\"").append(Base64Url.encode(salt)).append('"')
                append(",\"nonce\":\"").append(Base64Url.encode(nonce)).append('"')
                append(",\"ciphertext\":\"")
            }
        )
    }

    override fun write(b: Int) {
        checkOpen()
        ciphertextToJson.write(b)
        bytesWritten++
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        checkOpen()
        if (len <= 0) return
        ciphertextToJson.write(b, off, len)
        bytesWritten += len
    }

    /** Alias de [write] con el mismo nombre que los troceadores del AEAD. */
    fun update(b: ByteArray, off: Int, len: Int) = write(b, off, len)

    /** Cierra el campo, el objeto JSON y el Base64 exterior. */
    fun finish() {
        checkOpen()
        // Orden obligatorio: primero se completa el Base64 del ciphertext, luego
        // se añade el cierre del JSON, y solo entonces se vacía el Base64
        // exterior, que arrastra hasta dos caracteres del último grupo.
        ciphertextToJson.finish()
        jsonToBase64.write(QUOTE_AND_BRACE, 0, 2)
        jsonToBase64.drain()
        outerEncoder.finish()
        closed = true
    }

    override fun close() {
        if (!closed) finish()
    }

    override fun flush() = jsonToBase64.flush()

    private fun writeAscii(s: String) {
        val n = s.length
        val tmp = ByteArray(n)
        for (i in 0 until n) tmp[i] = s[i].code.toByte()
        jsonToBase64.write(tmp, 0, n)
    }

    private fun checkOpen() = check(!closed) { "EnvelopeWriter: el sobre ya está cerrado" }

    companion object {
        private val QUOTE_AND_BRACE = byteArrayOf('"'.code.toByte(), '}'.code.toByte())

        /**
         * @throws EnvelopeException si los parámetros están fuera de rango o las
         *         longitudes de salt/nonce no son las del formato.
         */
        fun new(
            out: OutputStream,
            ops: Int,
            memKib: Int,
            salt: ByteArray,
            nonce: ByteArray,
            version: Int = Envelope.CURRENT_VERSION,
            aead: String = Envelope.AEAD_NAME,
            kdf: String = Envelope.KDF_NAME
        ): EnvelopeWriter {
            Envelope.validate(version, aead, kdf, ops, memKib, salt, nonce)
            return EnvelopeWriter(out, version, aead, kdf, ops, memKib, salt, nonce)
        }
    }
}

/**
 * Lectura del sobre por partes, con memoria que no depende del ciphertext.
 *
 * [readHeader] es la pieza clave: recorre el blob desde el principio, reconoce la
 * cabecera y anota en qué offset del JSON empieza el ciphertext y cuántos
 * caracteres ocupa. Con esos dos números, [streamCiphertext] puede reenvolver el
 * Base64 exterior y entregar solo bytes de ciphertext.
 */
object EnvelopeReader {

    /**
     * Analiza la cabecera de un sobre que ya está en memoria.
     *
     * @throws EnvelopeException con la misma estrictez que el parser C++.
     */
    fun parseHeader(json: ByteArray): EnvelopeHeader {
        val scan = try {
            HeaderScanner(json).scanToCiphertext()
        } catch (e: NeedMoreData) {
            throw EnvelopeException("Sobre truncado: falta el campo ciphertext")
        } catch (e: HeaderSyntaxException) {
            throw EnvelopeException(e.message ?: "JSON malformado")
        }
        return headerFrom(scan, json.size.toLong())
    }

    /**
     * Lee solo la cabecera de un blob guardado en un origen re-abrible, sin
     * recorrer el ciphertext más que un cuarto de KB.
     *
     * [open] debe devolver una lectura nueva desde el principio del blob cada vez
     * que se invoque: la cabecera se lee en una pasada y [streamCiphertext] vuelve
     * a abrir para el grueso.
     *
     * @param blobBytes longitud del blob en bytes, o un valor `<= 0` si el
     *   proveedor no la declara. Un tamaño desconocido no invalida el sobre: solo
     *   deja de poderse acotar la longitud del campo "ciphertext", y eso se
     *   registra como [EnvelopeHeader.UNKNOWN_CHARS].
     * @param open      abre una lectura nueva del blob.
     * @throws EnvelopeException si el blob está malformado.
     */
    fun readHeader(blobBytes: Long, open: () -> java.io.InputStream): EnvelopeHeader {
        val declared = blobBytes > 0
        if (declared) {
            if (Base64Url.decodedLength(blobBytes) < MIN_JSON_BYTES) {
                throw EnvelopeException("Sobre demasiado corto")
            }
        }

        val buf = ByteArrayBuilder(HEADER_SCAN_LIMIT)
        var scan: HeaderScan? = null

        open().use { raw ->
            // Lecturas cortas a propósito: el Base64 entrega los bytes de tres en
            // tres, así que un búfer grande llenaría el tope del acumulador antes
            // de que la cabecera tuviera ocasión de reconocerse.
            val chunk = ByteArray(HEADER_READ)
            val outer = Base64Url.Decoder { bytes, off, len ->
                if (scan == null) {
                    if (buf.size + len > HEADER_SCAN_LIMIT) {
                        throw EnvelopeException("Cabecera del sobre demasiado grande")
                    }
                    buf.append(bytes, off, len)
                }
            }
            while (scan == null) {
                val n = raw.read(chunk)
                if (n < 0) break
                outer.update(chunk, 0, n)
                // En cuanto entra la comilla que abre el valor de "ciphertext" la
                // cabecera está completa y no hace falta leer más: el campo es
                // el 99 % del sobre.
                try {
                    scan = HeaderScanner(buf.toByteArray()).scanToCiphertext()
                } catch (e: NeedMoreData) {
                    // Todavía no: se sigue trayendo bytes.
                } catch (e: HeaderSyntaxException) {
                    // Invariante del scanner: un búfer a medio llenar solo puede
                    // dar NeedMoreData, nunca un error de sintaxis. Si aparece,
                    // el sobre está roto de verdad.
                    throw EnvelopeException(e.message ?: "JSON malformado")
                }
            }
            if (scan == null) {
                // Se llegó al final sin reconocer la cabecera: soltar el resto
                // del Base64 destapa un carácter inválido que de otro modo
                // passaría desapercibido.
                try {
                    outer.finish()
                } catch (e: Base64Exception) {
                    throw EnvelopeException("Base64 inválido", e)
                }
            }
        }

        val found = scan ?: throw EnvelopeException("Sobre truncado: falta el campo ciphertext")
        return headerFrom(found, if (declared) Base64Url.decodedLength(blobBytes) else EnvelopeHeader.UNKNOWN_CHARS)
    }

    /**
     * Entrega el ciphertext del blob por trozos, ya des-codificado: lo que sale
     * es exactamente el valor del campo "ciphertext".
     *
     * Reenvuelve el Base64 exterior, se salta la cabecera en [open] bytes del
     * JSON y pasa el resto al decodificador interior. El final del campo se
     * localiza aquí y no se da por supuesto a partir de la longitud, así que el
     * cierre `"}` y la ausencia de basura posterior se comprueban de verdad.
     *
     * @param sink recibe trozos en orden y sin huecos.
     * @throws EnvelopeException si el blob no termina donde debe, lo que delata
     *         un sobre manipulado o con espacios en blanco insertados.
     */
    fun streamCiphertext(
        header: EnvelopeHeader,
        blobBytes: Long,
        open: () -> java.io.InputStream,
        sink: (ByteArray, Int, Int) -> Unit
    ) {
        val skip = header.ciphertextStartInJson
        var seen = 0L
        var routed = 0L
        var closing = CLOSING_IN_FIELD
        val inner = Base64Url.Decoder(sink)

        try {
            open().use { raw ->
                val chunk = ByteArray(READ_BUFFER)
                val outer = Base64Url.Decoder { bytes, off, len ->
                    var i = off
                    var rem = len
                    while (rem > 0) {
                        // Fase 1: descartar la cabecera, que ya se validó.
                        if (seen < skip) {
                            val n = minOf(rem.toLong(), skip - seen).toInt()
                            i += n
                            rem -= n
                            seen += n
                            continue
                        }
                        if (closing == CLOSING_DONE) {
                            throw EnvelopeException("Sobre malformado: hay datos tras el cierre del sobre")
                        }
                        if (closing == CLOSING_AFTER_QUOTE) {
                            if ((bytes[i].toInt() and 0xff) != BRACE) {
                                throw EnvelopeException("Sobre malformado: se esperaba '}' tras el ciphertext")
                            }
                            i++
                            rem--
                            seen++
                            closing = CLOSING_DONE
                            continue
                        }
                        // Fase 2: dentro del campo. Ni '"' ni '}' son caracteres
                        // Base64 válidos, así que el primero que aparece marca el
                        // fin, y hasta entonces todo es ciphertext.
                        var j = i
                        while (j < i + rem) {
                            val b = bytes[j].toInt() and 0xff
                            if (b == QUOTE || b == BRACE) break
                            j++
                        }
                        val bulk = j - i
                        if (bulk > 0) {
                            val room = header.ciphertextChars - routed
                            if (room <= 0) {
                                throw EnvelopeException("Sobre malformado: el campo ciphertext es más largo de lo declarado")
                            }
                            val take = minOf(bulk.toLong(), room).toInt()
                            inner.update(bytes, i, take)
                            routed += take
                            i += take
                            rem -= take
                            seen += take
                            if (take < bulk) {
                                throw EnvelopeException("Sobre malformado: el campo ciphertext es más largo de lo declarado")
                            }
                            continue
                        }
                        if ((bytes[i].toInt() and 0xff) != QUOTE) {
                            throw EnvelopeException("Sobre malformado: el campo ciphertext no cierra con comilla")
                        }
                        i++
                        rem--
                        seen++
                        closing = CLOSING_AFTER_QUOTE
                    }
                }
                while (true) {
                    val n = raw.read(chunk)
                    if (n < 0) break
                    outer.update(chunk, 0, n)
                }
                outer.finish()
            }
        } catch (e: Base64Exception) {
            throw EnvelopeException("Base64 inválido", e)
        }

        if (closing != CLOSING_DONE) {
            throw EnvelopeException("Sobre truncado: el campo ciphertext no cierra el objeto")
        }
        if (routed == 0L) {
            throw EnvelopeException("ciphertext vacío")
        }
        try {
            inner.finish()
        } catch (e: Base64Exception) {
            throw EnvelopeException("Base64 inválido", e)
        }
    }

    private const val QUOTE = 0x22
    private const val BRACE = 0x7D
    private const val CLOSING_IN_FIELD = 0
    private const val CLOSING_AFTER_QUOTE = 1
    private const val CLOSING_DONE = 2

    /** Atajo de [streamCiphertext] para un sobre que ya está en memoria. */
    fun streamCiphertextInMemory(
        json: ByteArray,
        header: EnvelopeHeader,
        sink: (ByteArray, Int, Int) -> Unit
    ) {
        val start = header.ciphertextStartInJson.toInt()
        val end = start + header.ciphertextChars.toInt()
        if (end + 2 != json.size ||
            json[end] != '"'.code.toByte() ||
            json[end + 1] != '}'.code.toByte()
        ) {
            throw EnvelopeException("Sobre malformado: el campo ciphertext no cierra el objeto")
        }
        val inner = Base64Url.Decoder(sink)
        inner.update(json, start, header.ciphertextChars.toInt())
        inner.finish()
    }

    private const val READ_BUFFER = 32 * 1024

    /** Techo de la cabecera: si no se reconoce en 4 KiB, algo va muy mal. */
    private const val HEADER_SCAN_LIMIT = 4096

    /** Bytes de Base64 leídos por golpe al reconocer la cabecera. */
    private const val HEADER_READ = 1024

    /** Un sobre completo ocupa más de 64 bytes de JSON, incluso vacío. */
    private const val MIN_JSON_BYTES = 40

    private fun headerFrom(scan: HeaderScan, decodedTotal: Long): EnvelopeHeader {
        // Tras la comilla de apertura del ciphertext solo puede venir su Base64
        // y el cierre `"}`; por eso la longitud se deduce del total en vez de
        // tener que recorrerlo. [streamCiphertext] verifica después que el
        // cálculo cuadre con lo que realmente hay.
        //
        // Con la longitud del blob desconocida no hay total contra el que restar,
        // y las dos comprobaciones de abajo no se pueden hacer: no hay nada que
        // afirmar todavía sobre el tamaño del campo. No es un agujero, porque
        // [streamCiphertext] exige encontrar los delimitadores de cierre y
        // rechaza un ciphertext vacío (o demasiado corto para el tag) cuando los
        // recorre. Lo que se pierde es poder avisar antes de empezar.
        val bounded = decodedTotal != EnvelopeHeader.UNKNOWN_CHARS
        val ciphertextChars = if (bounded) decodedTotal - scan.consumed - 2 else EnvelopeHeader.UNKNOWN_CHARS
        if (bounded && ciphertextChars <= 0) throw EnvelopeException("ciphertext vacío")
        val header = EnvelopeHeader(
            scan.version, scan.aead, scan.kdf, scan.ops, scan.memKib,
            scan.salt, scan.nonce, scan.consumed, ciphertextChars,
        )
        if (bounded && header.ciphertextBytes < Envelope.TAG_BYTES) {
            throw EnvelopeException("ciphertext demasiado corto (falta tag)")
        }
        Envelope.validate(
            header.version, header.aead, header.kdf, header.ops, header.memKib,
            header.salt, header.nonce,
        )
        return header
    }
}

// ---------------------------------------------------------------------------
// Parser incremental de la cabecera
// ---------------------------------------------------------------------------

/** Lo que se sabe del sobre tras recorrer el JSON hasta el valor de "ciphertext". */
internal class HeaderScan(
    val version: Int,
    val aead: String,
    val kdf: String,
    val ops: Int,
    val memKib: Int,
    val salt: ByteArray,
    val nonce: ByteArray,
    /** Bytes del JSON consumidos, incluido el `:` y la comilla de apertura. */
    val consumed: Long
)

/** Se acabó el búfer y el JSON sigue: hay que traer más bytes. */
internal class NeedMoreData : RuntimeException(null, null, false, false)

internal class HeaderSyntaxException(message: String) : RuntimeException(message)

private val ALLOWED_FIELDS = setOf(
    "v", "aead", "kdf", "ops", "mem_kib", "salt", "nonce", "ciphertext",
)

/**
 * Recorre el objeto JSON campo a campo hasta la comilla que abre el valor de
 * `"ciphertext"`, que es donde el sobre deja de ser pequeño.
 *
 * Antes de ese punto solo hay enteros y Base64 de 16 y 24 bytes, así que el
 * recorrido encaja en un búfer diminuto. Cuando llegan más bytes se vuelve a
 * intentar desde el principio en vez de mantener una máquina de estados
 * particulada: el búfer está acotado a 4 KiB, el coste de reintentar es
 * despreciable y el código queda sin estados que sincronizar.
 *
 * Tolera el espacio en blanco insignificant igual que cualquier parser JSON y
 * que el lado C++. Rechaza lo mismo: campos desconocidos, campos duplicados,
 * valores con tipo equivocado y bytes sobrantes tras el objeto.
 */
internal class HeaderScanner(private val json: ByteArray) {

    private var p = 0

    /** @throws NeedMoreData si el JSON no ha terminado. */
    fun scanToCiphertext(): HeaderScan {
        var version = -1
        var aead: String? = null
        var kdf: String? = null
        var ops = -1
        var memKib = -1
        var salt: ByteArray? = null
        var nonce: ByteArray? = null
        val seen = HashSet<String>(8)

        expect('{')
        while (true) {
            when (peekSkippingSpace()) {
                CLOSE_BRACE -> fail("Sobre malformado: falta el campo ciphertext")
                -1 -> throw NeedMoreData()
            }
            expect('"')
            val name = readString()
            if (!seen.add(name)) fail("Campo duplicado: $name")
            if (name !in ALLOWED_FIELDS) fail("Campo desconocido: $name")
            expect(':')

            when (name) {
                "v" -> version = readIntValue()
                "aead" -> aead = readStringValue()
                "kdf" -> kdf = readStringValue()
                "ops" -> ops = readIntValue()
                "mem_kib" -> memKib = readIntValue()
                "salt" -> salt = readSmallBase64("salt")
                "nonce" -> nonce = readSmallBase64("nonce")
                "ciphertext" -> {
                    skipSpace()
                    if (p >= json.size) throw NeedMoreData()
                    if (next() != QUOTE) fail("Sobre malformado: ciphertext no es una cadena")
                    val v = version; val a = aead; val k = kdf
                    val s = salt; val n = nonce
                    if (v < 0 || a == null || k == null || ops < 0 || memKib < 0 || s == null || n == null) {
                        fail("Sobre malformado: faltan campos obligatorios")
                    }
                    return HeaderScan(v, a, k, ops, memKib, s, n, p.toLong())
                }
            }

            when (peekSkippingSpace()) {
                COMMA -> { p++ }
                CLOSE_BRACE -> fail("Sobre malformado: falta el campo ciphertext")
                -1 -> throw NeedMoreData()
                else -> fail("JSON malformado: se esperaba ',' o '}'")
            }
        }
    }

    private fun peek(): Int = if (p < json.size) json[p].toInt() and 0xff else -1

    private fun next(): Int = if (p < json.size) (json[p++].toInt() and 0xff) else -1

    /**
     * Salta el espacio en blanco insignificant entre tokens, como cualquier
     * parser JSON y como el lado C++. El sobre que produce esta app es compacto,
     * pero el que llega de fuera puede venir formateado.
     */
    private fun skipSpace() {
        while (p < json.size) {
            when (json[p].toInt() and 0xff) {
                SPACE, TAB, CR, LF -> p++
                else -> return
            }
        }
    }

    private fun peekSkippingSpace(): Int {
        skipSpace()
        return peek()
    }

    private fun expect(c: Char) {
        skipSpace()
        // next() no avanza al final del búfer, así que quedarse sin datos hay
        // que detectarlo antes: si no, un búfer a medio llenar se confundiría con
        // un JSON sintácticamente roto y se rechazaría un sobre válido.
        if (p >= json.size) throw NeedMoreData()
        if (next() != c.code) fail("JSON malformado: se esperaba '$c'")
    }

    /** Valor de cadena: abre comilla y lee el contenido. */
    private fun readStringValue(): String {
        skipSpace()
        if (p >= json.size) throw NeedMoreData()
        if (next() != QUOTE) fail("JSON malformado: se esperaba una cadena")
        return readString()
    }

    private fun readIntValue(): Int {
        skipSpace()
        return readInt()
    }

    /**
     * Cadena JSON sin escapes. El sobre solo lleva nombres de campo y Base64, y
     * un `\` ahí no puede ser legítimo: se rechaza en vez de interpretarlo, que
     * es más estricto que el parser C++ y no deja pasar nada que él no pase.
     */
    private fun readString(): String {
        val start = p
        while (true) {
            val c = next()
            when {
                c == QUOTE -> break
                c == BACKSLASH -> fail("JSON malformado: escapes no admitidos")
                c == -1 -> {
                    p = json.size
                    throw NeedMoreData()
                }
            }
        }
        return String(json, start, p - start - 1, Charsets.US_ASCII)
    }

    /** Entero JSON sin signo, sin ceros a la izquierda y sin `+`, como en C++. */
    private fun readInt(): Int {
        val start = p
        if (peek() == '0'.code) {
            p++
            if (peek() in '0'.code..'9'.code) fail("JSON malformado: cero con dígitos iniciales")
            if (p >= json.size) throw NeedMoreData()
            return 0
        }
        while (peek() in '0'.code..'9'.code) {
            if (p - start >= 10) fail("JSON malformado: entero desbordado")
            p++
        }
        if (p == start) {
            if (peek() < 0) throw NeedMoreData()
            fail("JSON malformado: se esperaba un entero")
        }
        // El búfer se ha agotado justo detrás de los dígitos: pueden venir más.
        if (p >= json.size) throw NeedMoreData()
        return String(json, start, p - start, Charsets.US_ASCII).toInt()
    }

    private fun readSmallBase64(name: String): ByteArray {
        val s = readStringValue()
        return try {
            Base64Url.decode(s)
        } catch (e: Base64Exception) {
            fail("Campo base64 del sobre inválido: $name")
        }
    }

    private fun fail(message: String): Nothing = throw HeaderSyntaxException(message)

    private companion object {
        const val QUOTE = '"'.code
        const val BACKSLASH = '\\'.code
        const val COMMA = ','.code
        const val CLOSE_BRACE = '}'.code
        const val SPACE = 0x20
        const val TAB = 0x09
        const val CR = 0x0D
        const val LF = 0x0A
    }
}

// ---------------------------------------------------------------------------
// Utilidades de bajo nivel
// ---------------------------------------------------------------------------

/**
 * `OutputStream` que agrupa lo que le llega en bloques antes de pasarlo aguas
 * abajo. Los codificadores de Base64 escriben cuatro caracteres por llamada; sin
 * agrupar, un archivo de 100 MB serían cientos de millones de llamadas diminutas
 * en el escritor de destino.
 */
internal class ChunkBuffer(
    private val down: OutputStream,
    private val capacity: Int = 64 * 1024
) : OutputStream() {

    private val buf = ByteArray(capacity)
    private var n = 0

    override fun write(b: Int) {
        if (n == capacity) drain()
        buf[n++] = b.toByte()
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (len <= 0) return
        if (len >= capacity) {
            drain()
            down.write(b, off, len)
            return
        }
        if (n + len > capacity) drain()
        System.arraycopy(b, off, buf, n, len)
        n += len
    }

    fun drain() {
        if (n > 0) {
            down.write(buf, 0, n)
            n = 0
        }
    }

    override fun flush() {
        drain()
        down.flush()
    }
}

/** Búfer debytes para acumular la cabecera del JSON mientras se reconoce. */
internal class ByteArrayBuilder(initial: Int) {
    private var buf = ByteArray(initial.coerceAtLeast(64))
    var size: Int = 0
        private set

    fun append(b: ByteArray, off: Int, len: Int) {
        if (size + len > buf.size) {
            var cap = buf.size
            while (cap < size + len) cap *= 2
            buf = buf.copyOf(cap)
        }
        System.arraycopy(b, off, buf, size, len)
        size += len
    }

    fun toByteArray(): ByteArray = buf.copyOf(size)
}