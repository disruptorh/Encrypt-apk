package com.reimen.cifra.ui

import android.app.Application
import android.net.Uri
import android.os.Looper
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.reimen.cifra.crypto.Base64Url
import com.reimen.cifra.crypto.CryptoEngine
import com.reimen.cifra.crypto.EnvelopeException
import com.reimen.cifra.crypto.EnvelopeReader
import com.reimen.cifra.crypto.SecureWipe
import com.reimen.cifra.data.Sources
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction

/**
 * Estado y lógica de la pantalla.
 *
 * El ViewModel es quien decide dónde va cada resultado. Con un texto corto o un
 * sobre corto, el resultado se queda en memoria y se muestra en pantalla. Con
 * algo grande, va a un [Uri] que elige el usuario: la app nunca copia el
 * contenido de un archivo ajeno al disco, solo lo lee y escribe donde le digan.
 *
 * La contraseña y el campo secreto NO se guardan en `SavedStateHandle` a
 * propósito: ese estado acaba escrito en disco cuando Android mata el proceso,
 * y una contraseña no debería poder acabar ahí. Se pierden al rotar, que es el
 * precio justo por no guardarlas.
 */
class CryptoViewModel(app: Application) : AndroidViewModel(app) {

    enum class Mode { ENCRYPT, DECRYPT }

    /** De dónde sale lo que se cifra o se descifra. */
    sealed interface Content {
        data object None : Content
        data class Text(val value: String) : Content
        data class File(val uri: Uri, val name: String, val size: Long) : Content
    }

    /** Qué ha quedado al terminar. */
    sealed interface Outcome {
        data object None : Outcome
        /** Sobre cifrado, bastante pequeño para verse en pantalla. */
        data class Blob(val value: String, val bytes: Long) : Outcome
        /** Texto descifrado, bastante pequeño para verse en pantalla. */
        data class Plain(val value: String, val bytes: Long) : Outcome
        /** Resultado escrito en un archivo. `verified` dice si pasó el tag. */
        data class Saved(val uri: Uri, val name: String, val bytes: Long, val verified: Boolean) : Outcome
    }

    /** En qué punto está la operación. */
    sealed interface Phase {
        data object Idle : Phase
        data class Running(val label: String, val doneBytes: Long, val totalBytes: Long) : Phase {
            /** 0.0..1.0, o null si aún no se sabe el total. */
            val fraction: Float?
                get() = if (totalBytes <= 0) null else (doneBytes.toDouble() / totalBytes).coerceIn(0.0, 1.0).toFloat()
        }
        data class Ok(val message: String) : Phase
        data class Failed(val message: String) : Phase
        data object Cancelled : Phase
    }

    data class UiState(
        val mode: Mode = Mode.ENCRYPT,
        val password: String = "",
        val pepper: String = "",
        val pepperVisible: Boolean = false,
        val profile: CryptoEngine.KdfProfile = CryptoEngine.KdfProfile.STANDARD,
        val input: Content = Content.None,
        val inputNote: String = "",
        /** Bytes que habrá al terminar, para decidir entre memoria y archivo. */
        val expectedOutputBytes: Long = -1,
        val outcome: Outcome = Outcome.None,
        val phase: Phase = Phase.Idle
    ) {
        val busy: Boolean get() = phase is Phase.Running

        /**
         * ¿El resultado es demasiado grande —o demasiado grande *a conocidos*—
         * para ponerlo en un `Text`? La decisión, y su porqué, están en
         * [Plan.needsFile].
         */
        val outputNeedsFile: Boolean
            get() = Plan.needsFile(expectedOutputBytes, Sources.INLINE_LIMIT_BYTES)

        val canRun: Boolean
            get() = password.isNotEmpty() && !busy && when (input) {
                is Content.Text -> input.value.isNotBlank()
                is Content.File -> true
                Content.None -> false
            }
    }

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    private var running: Job? = null

    private fun update(f: (UiState) -> UiState) {
        // Los callbacks de cifrado y descifrado corren en un hilo de fondo, así
        // que el progreso también se escribe desde ahí. Escribir en el `StateFlow`
        // es seguro desde cualquier hilo, pero la interfaz se entera por un collector
        // y el salto de hilo en mitad de una recomposición es justo lo que rompe
        // cuando el entorno aplica los cambios en el hilo que escribe. En el hilo
        // principal se aplica ya; desde un hilo de fondo, se encola.
        if (Looper.myLooper() == Looper.getMainLooper()) {
            _state.value = f(_state.value)
        } else {
            viewModelScope.launch { _state.value = f(_state.value) }
        }
    }

    // --- acciones de la interfaz -------------------------------------------

    fun setMode(mode: Mode) = update {
        it.copy(mode = mode, outcome = Outcome.None, phase = Phase.Idle, inputNote = "", expectedOutputBytes = -1)
    }

    fun setPassword(value: String) = update { it.copy(password = value, phase = Phase.Idle) }

    fun setPepper(value: String) = update { it.copy(pepper = value, phase = Phase.Idle) }

    fun togglePepper() = update { it.copy(pepperVisible = !it.pepperVisible) }

    fun setProfile(profile: CryptoEngine.KdfProfile) = update { it.copy(profile = profile, phase = Phase.Idle) }

    fun setInputText(value: String) {
        val content = Content.Text(value)
        update {
            it.copy(
                input = content,
                inputNote = describeInput(content),
                outcome = Outcome.None,
                phase = Phase.Idle,
                expectedOutputBytes = if (it.mode == Mode.ENCRYPT) upperBoundFor(content) else -1
            )
        }
        inspectBlob()
    }

    fun setInputFile(uri: Uri) {
        val context = getApplication<Application>()
        val content = Content.File(uri, Sources.nameOf(context, uri), Sources.sizeOf(context, uri))
        update {
            it.copy(
                input = content,
                inputNote = describeInput(content),
                outcome = Outcome.None,
                phase = Phase.Idle,
                expectedOutputBytes = if (it.mode == Mode.ENCRYPT) upperBoundFor(content) else -1
            )
        }
        inspectBlob()
    }

    fun clearInput() = update {
        it.copy(input = Content.None, inputNote = "", outcome = Outcome.None, phase = Phase.Idle, expectedOutputBytes = -1)
    }

    fun dismissPhase() = update { it.copy(phase = Phase.Idle) }

    fun cancel() {
        running?.cancel()
        running = null
        update { it.copy(phase = Phase.Cancelled) }
    }

    /**
     * Cifra dejando el resultado en memoria.
     *
     * La interfaz solo llama a esto cuando sabe que el sobre va a caber; si no,
     * pide un destino con [encryptTo].
     */
    fun encrypt() = launch("Cifrando") { encryptImpl(null) }

    fun encryptTo(destination: Uri?) = launch("Cifrando") { encryptImpl(destination) }

    fun decrypt() = launch("Descifrando") { decryptImpl(null) }

    fun decryptTo(destination: Uri?) = launch("Descifrando") { decryptImpl(destination) }

    /**
     * El camino en memoria solo vale para lo que la interfaz ha decidido que cabe
     * en pantalla. Se vuelve a comprobar aquí, en el sitio que de verdad decide,
     * para que un `expectedOutputBytes` desconocido (un sobre largo pegado, del
     * que no se ha leído la cabecera) no acabe llenando un `ByteArrayOutputStream`
     * con el resultado entero.
     */
    private fun refuseIfTooBigInMemory(s: UiState) {
        if (s.outputNeedsFile) {
            throw CryptoEngine.CryptoException(
                "Es demasiado grande para mostrarlo aquí: elige un archivo de salida"
            )
        }
    }

    // --- trabajo ------------------------------------------------------------

    private fun launch(label: String, block: suspend () -> Outcome) {
        val s = _state.value
        if (s.busy) return
        if (s.password.isEmpty()) {
            update { it.copy(phase = Phase.Failed("La contraseña es obligatoria")) }
            return
        }
        if (!hasContent(s.input)) {
            update {
                it.copy(phase = Phase.Failed(if (s.mode == Mode.ENCRYPT) "No hay nada que cifrar" else "No hay sobre que descifrar"))
            }
            return
        }
        update { it.copy(phase = Phase.Running(label, 0, s.expectedOutputBytes), outcome = Outcome.None) }
        running = viewModelScope.launch {
            try {
                val outcome = withContext(Dispatchers.IO) { block() }
                update { it.copy(phase = Phase.Ok(doneMessage(outcome)), outcome = outcome) }
            } catch (e: CancellationException) {
                update { it.copy(phase = Phase.Cancelled, outcome = Outcome.None) }
                throw e
            } catch (e: CryptoEngine.CryptoException) {
                update { it.copy(phase = Phase.Failed(e.message ?: "Error"), outcome = Outcome.None) }
            } catch (e: EnvelopeException) {
                update { it.copy(phase = Phase.Failed("Sobre inválido: ${e.message}"), outcome = Outcome.None) }
            } catch (e: OutOfMemoryError) {
                update { it.copy(phase = Phase.Failed("Memoria insuficiente para procesar este contenido"), outcome = Outcome.None) }
            } catch (e: Exception) {
                update { it.copy(phase = Phase.Failed(e.message ?: "Error inesperado"), outcome = Outcome.None) }
            } finally {
                running = null
            }
        }
    }

    private suspend fun encryptImpl(destination: Uri?): Outcome {
        val s = _state.value
        val password = s.password.toCharArray()
        val pepper = s.pepper.takeIf { it.isNotEmpty() }?.toCharArray()
        try {
            if (destination != null) {
                try {
                    Sources.openOutput(getApplication(), destination).use { out ->
                        encryptInto(out, s.input, password, pepper, s.profile)
                    }
                } catch (e: Throwable) {
                    // Un sobre a medias es peor que no tener nada: parece
                    // cifrable y no lo es. Como el documento lo creó esta misma
                    // app, se puede borrar.
                    discardQuietly(destination)
                    throw e
                }
                return Outcome.Saved(
                    destination,
                    Sources.nameOf(getApplication(), destination),
                    Sources.sizeOf(getApplication(), destination),
                    verified = true
                )
            }
            refuseIfTooBigInMemory(s)
            val out = ByteArrayOutputStream()
            encryptInto(out, s.input, password, pepper, s.profile)
            val blob = out.toString(Charsets.US_ASCII.name())
            return Outcome.Blob(blob, blob.length.toLong())
        } finally {
            SecureWipe.wipe(password)
            SecureWipe.wipe(pepper)
        }
    }

    /** Cifra [input] hacia [out] sin que nada dependa del tamaño del contenido. */
    private suspend fun encryptInto(
        out: OutputStream,
        input: Content,
        password: CharArray,
        pepper: CharArray?,
        profile: CryptoEngine.KdfProfile
    ) {
        // El contexto se captura aquí para poder comprobar la cancelación
        // dentro de los callbacks, que no son `suspend` y por tanto no pueden
        // llamar a `currentCoroutineContext()`.
        val context = currentCoroutineContext()
        // Lo que se pasa como total del progreso es el **texto plano**, no el
        // tamaño del sobre: el contador `done` también cuenta texto plano, y
        // mezclar las dos unidades hacía que la barra se parara en 9/16 = 56 %
        // sin llegar nunca al final. El tamaño del sobre sigue decidiendo si el
        // resultado va a memoria o a archivo, pero eso es [outputNeedsFile] y
        //Para el texto se cuenta el UTF-8 exacto porque `done` lo
        // cuenta en bytes y no en caracteres.
        val plaintextSize = when (input) {
            is Content.Text -> Plan.utf8Length(input.value)
            is Content.File -> if (input.size > 0) input.size else -1L
            Content.None -> -1L
        }
        CryptoEngine.startEncrypting(password, pepper, profile, plaintextSize, out).use { enc ->
            var done = 0L
            when (input) {
                is Content.Text -> Utf8Writer(input.value).use { utf8 ->
                    utf8.forEachChunk { buf, off, len ->
                        enc.write(buf, off, len)
                        done += len
                        progress("Cifrando", done)
                    }
                }
                is Content.File -> Sources.openInput(getApplication(), input.uri).use { raw ->
                    readInto(context, raw) { buf, off, len ->
                        enc.write(buf, off, len)
                        done += len
                        progress("Cifrando", done)
                    }
                }
                Content.None -> throw CryptoEngine.CryptoException("No hay nada que cifrar")
            }
            enc.finish()
        }
    }

    private suspend fun decryptImpl(destination: Uri?): Outcome {
        val s = _state.value
        val password = s.password.toCharArray()
        val pepper = s.pepper.takeIf { it.isNotEmpty() }?.toCharArray()
        try {
            if (destination != null) {
                // Se descifra antes a un temporal: el texto sale del AEAD sin
                // verificar hasta el final, y no se escribe en el archivo del
                // usuario algo que después resulte no ser auténtico.
                val temp = Sources.tempFile(getApplication(), ".plain")
                try {
                    var done = 0L
                    temp.outputStream().buffered(CryptoEngine.CHUNK_BYTES).use { sink ->
                        decrypt(s.input, password, pepper) { b, off, len ->
                            sink.write(b, off, len)
                            done += len
                            progress("Descifrando", done)
                        }
                    }
                    val bytes = temp.length()
                    Sources.publish(temp, getApplication(), destination)
                    return Outcome.Saved(
                        destination,
                        Sources.nameOf(getApplication(), destination),
                        bytes,
                        verified = true
                    )
                } catch (e: Throwable) {
                    temp.delete()
                    throw e
                }
            }

            refuseIfTooBigInMemory(s)
            // Solo se llega aquí cuando el resultado cabe en memoria (lo decide
            // la interfaz mirando el tamaño), así que recoger los bytes y
            // decodificarlos de golpe es lo más simple que funciona. `String`
            // sustituye por U+FFFD lo que no sea UTF-8 válido, que es justo lo
            // que se quiere con texto cifrado que resultara no ser UTF-8.
            val context = currentCoroutineContext()
            val plain = ByteArrayOutputStream()
            var done = 0L
            decrypt(s.input, password, pepper) { b, off, len ->
                context.ensureActive()
                plain.write(b, off, len)
                done += len
                progress("Descifrando", done)
            }
            val bytes = plain.toByteArray()
            val text = String(bytes, Charsets.UTF_8)
            SecureWipe.wipe(bytes)
            return Outcome.Plain(text, done)
        } finally {
            SecureWipe.wipe(password)
            SecureWipe.wipe(pepper)
        }
    }

    private suspend fun decrypt(
        input: Content,
        password: CharArray,
        pepper: CharArray?,
        emit: (ByteArray, Int, Int) -> Unit
    ) {
        when (input) {
            is Content.Text -> {
                // El sobre pegado llega como `String`, y copiarlo entero era el
                // problema: `trim()` hacía una copia y `toByteArray()` otra, así
                // que un pegado de 10 MB reservaba unos 20 MB de golpe (40 con la
                // cadena) antes de descifrar nada. Con un pegado mayor el proceso
                // moría por memoria. Aquí se decodifica en streaming, con un
                // buffer fijo, y los límites se calculan sin copiar.
                val text = input.value
                val size = AsciiTextStream.of(text).length.toLong()
                // Se crea un flujo nuevo por cada `open`, que es lo que exige
                // [CryptoEngine.startDecrypting].
                CryptoEngine.startDecrypting(size, { AsciiTextStream.of(text) }, password, pepper)
                    .use { it.decrypt(emit) }
            }
            is Content.File -> CryptoEngine
                .startDecrypting(input.size, { Sources.openInput(getApplication(), input.uri) }, password, pepper)
                .use { it.decrypt(emit) }
            Content.None -> throw CryptoEngine.CryptoException("No hay sobre que descifrar")
        }
    }

    // --- utilidades ---------------------------------------------------------

    private fun progress(label: String, done: Long) {
        update { it.copy(phase = Phase.Running(label, done, it.expectedOutputBytes)) }
    }

    /**
     * Intenta borrar un documento creado por la app. Si el proveedor no lo
     * permite, no hay nada que hacer: es mejor fallar en silencio que tapar el
     * error real con otro.
     */
    private fun discardQuietly(uri: Uri) {
        runCatching { getApplication<Application>().contentResolver.delete(uri, null, null) }
    }

    private fun hasContent(content: Content): Boolean = when (content) {
        is Content.Text -> content.value.isNotBlank()
        is Content.File -> true
        Content.None -> false
    }

    /**
     * Cota superior de lo que ocupará el resultado: para decidir y para la
     * barra de progreso, no un número exacto. El cálculo está en [Plan] para que
     * se pueda probar; aquí solo se traduce de [Content] a números.
     */
    private fun upperBoundFor(content: Content): Long = when (content) {
        is Content.File ->
            if (content.size > 0) Plan.upperBoundForPlaintext(content.size) else -1L
        is Content.Text -> Plan.upperBoundForText(content.value.length)
        Content.None -> -1L
    }

    private fun describeInput(content: Content): String = when (content) {
        is Content.Text -> "${content.value.length} caracteres"
        is Content.File ->
            if (content.size > 0) "${content.name} · ${Sources.formatBytes(content.size)}"
            else "${content.name} · tamaño desconocido"
        Content.None -> ""
    }

    private fun doneMessage(outcome: Outcome): String = when (outcome) {
        is Outcome.Blob -> "Cifrado correcto · ${Sources.formatBytes(outcome.bytes)} de sobre"
        is Outcome.Plain -> "Descifrado correcto · ${Sources.formatBytes(outcome.bytes)}"
        is Outcome.Saved -> "Guardado en ${outcome.name}"
        Outcome.None -> "Listo"
    }

    /**
     * Lee solo la cabecera del sobre para saber cuánto texto va a salir. Cuesta
     * un kilobyte de lectura y es lo que permite avisar antes de empezar de que
     * el resultado no va a caber en pantalla.
     */
    private fun inspectBlob() {
        val s = _state.value
        if (s.mode != Mode.DECRYPT) return
        val input = s.input
        if (input is Content.None) return
        // Leer la cabecera de un texto exige decodificarlo entero, porque el
        // campo `ciphertext` del JSON es justamente lo que hay que medir. Con un
        // sobre de varios megabytes eso son unos miles de bytes por pulsación:
        // la app se quedaba temblando al pegar y el recolector no daba abasto,
        // así que el proceso acababa muriéndose. Por encima del tope no se
        // intenta, y se deja el tamaño como desconocido.
        //
        // No se pierde nada: un sobre tan largo descifra a un tamaño que de todos
        // modos va a un archivo, que es justo lo que decide el tamaño desconocido.
        if (input is Content.Text && input.value.length > INSPECT_LIMIT) return
        inspectJob?.cancel()
        inspectJob = viewModelScope.launch {
            val plain = withContext(Dispatchers.IO) {
                runCatching {
                    when (input) {
                        is Content.Text -> EnvelopeReader.parseHeader(Base64Url.decode(input.value.trim())).plaintextBytes
                        is Content.File -> EnvelopeReader.readHeader(input.size, { Sources.openInput(getApplication(), input.uri) })
                            .plaintextBytes
                        Content.None -> -1L
                    }
                }.getOrDefault(-1L)
            }
            if (plain > 0) {
                update { current ->
                    // Entre el lanzamiento y aquí el usuario puede haber cambiado
                    // la entrada; el dato viejo no vale para la nueva.
                    if (current.input == input) current.copy(expectedOutputBytes = plain) else current
                }
            }
        }
    }

    private var inspectJob: Job? = null

    private companion object {
        /**
         * Tope de caracteres de un sobre pegado al que se le lee la cabecera.
         *
         * Está muy por encima de lo que cabe en pantalla, para no perder el
         * tamaño exacto en los casos en que el resultado sí se muestra en el
         * texto, y muy por debajo de un megabyte para que peekar sea barato.
         */
        const val INSPECT_LIMIT = 64 * 1024
    }
}

/** Lee [raw] a trozos, respetando la cancelación de la corrutina. */
private suspend fun readInto(
    context: kotlin.coroutines.CoroutineContext,
    raw: InputStream,
    consume: (ByteArray, Int, Int) -> Unit
) {
    val buf = ByteArray(CryptoEngine.CHUNK_BYTES)
    while (true) {
        context.ensureActive()
        val n = raw.read(buf)
        if (n < 0) return
        consume(buf, 0, n)
    }
}

/**
 * UTF-8 sobre trozos, para cifrar un texto pegado sin copiarlo entero.
 *
 * El detalle que importa: un par surrogata partido entre dos trozos. Si se
 * codifica trozo a trozo sin mirar eso, un emoji en el límite de un búfer se
 * convierte en dos signos de interrogación en vez de un emoji. [Utf8Writer]
 * deja el carácter a medias en el codificador y lo resuelve en el trozo
 * siguiente.
 *
 * Los archivos no pasan por aquí: van byte a byte tal cual, que es lo que hay
 * que hacer con contenido arbitrario.
 */
private class Utf8Writer(private val chars: CharSequence) : AutoCloseable {

    private val encoder = Charsets.UTF_8.newEncoder()
        .onMalformedInput(CodingErrorAction.REPLACE)
        .onUnmappableCharacter(CodingErrorAction.REPLACE)
    private val inBuf = CharBuffer.allocate(CHUNK_CHARS)
    private val outBuf = ByteBuffer.allocate(CHUNK_CHARS * 3)

    suspend fun forEachChunk(consume: (ByteArray, Int, Int) -> Unit) {
        val context = currentCoroutineContext()
        var p = 0
        while (p < chars.length) {
            context.ensureActive()
            val n = minOf(CHUNK_CHARS, chars.length - p)
            inBuf.clear()
            for (c in chars.subSequence(p, p + n)) inBuf.put(c)
            inBuf.flip()
            encoder.encode(inBuf, outBuf, false)
            outBuf.flip()
            consume(outBuf.array(), 0, outBuf.remaining())
            outBuf.clear()
            p += n
        }
        // Vaciado final: aquí es donde un surrogata sin pareja se sustituye.
        encoder.encode(CharBuffer.allocate(0), outBuf, true)
        encoder.flush(outBuf)
        outBuf.flip()
        if (outBuf.hasRemaining()) consume(outBuf.array(), 0, outBuf.remaining())
        outBuf.clear()
    }

    override fun close() {
        SecureWipe.wipe(outBuf.array())
    }

    companion object {
        private const val CHUNK_CHARS = 32 * 1024

    }
}
/**
 * Un [InputStream] que entrega un texto como bytes ASCII a trozos, sin copiarlo
 * entero ni una sola vez.
 *
 * Existe por el caso de pegar un sobre grande en el campo de texto. Copiarlo con
 * `trim()` y `toByteArray()` costaba una copia del tamaño del texto, y a partir
 * de unos pocos megabytes la app se quedaba sin memoria. Este flujo solo tiene
 * un buffer fijo, así que el pico no depende de lo que se haya pegado.
 */
internal class AsciiTextStream private constructor(
    private val text: CharSequence,
    private val start: Int,
    private val end: Int
) : InputStream() {
    /** Cuántos bytes entregará en total, sin materializar nada. */
    val length: Int get() = end - start

    private val buffer = ByteArray(CHUNK_CHARS)
    private var pos = 0
    private var limit = 0
    private var index = start

    override fun read(): Int {
        if (!fill()) return -1
        return buffer[pos++].toInt() and 0xFF
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        if (!fill()) return -1
        val n = minOf(len, limit - pos)
        buffer.copyInto(b, off, pos, pos + n)
        pos += n
        return n
    }

    override fun available(): Int = limit - pos

    /** Rellena [buffer] si está vacío. @return false si ya no queda nada. */
    private fun fill(): Boolean {
        while (pos >= limit) {
            if (index >= end) return false
            val n = minOf(CHUNK_CHARS, end - index)
            for (i in 0 until n) {
                val c = text[index + i]
                if (c.code > 0x7F) {
                    // Base64url es ASCII. Un carácter de más wide es un error de
                    // formato, no algo que se pueda "limpiar" como un espacio.
                    throw EnvelopeException("El sobre debe ser texto ASCII")
                }
                buffer[i] = c.code.toByte()
            }
            index += n
            pos = 0
            limit = n
        }
        return true
    }

    companion object {
        private const val CHUNK_CHARS = 32 * 1024

        /**
         * Envuelve [text] ignorando los espacios de los dos extremos, igual que
         * haría `trim()`, pero sin crear la copia.
         *
         * @throws EnvelopeException si solo hay espacios.
         */
        fun of(text: CharSequence): AsciiTextStream {
            var start = 0
            while (start < text.length && text[start].isWhitespace()) start++
            var end = text.length
            while (end > start && text[end - 1].isWhitespace()) end--
            if (end == start) throw EnvelopeException("No hay sobre que descifrar")
            return AsciiTextStream(text, start, end)
        }
    }
}
