package com.reimen.cifra.data

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.documentfile.provider.DocumentFile
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.util.Locale

/**
 * Acceso a contenido (SAF) y a archivos, con las cuentas que la app necesita.
 *
 * Todo el trabajo pesado va por [InputStream]/[OutputStream] y nunca por
 * `readBytes()`/`writeBytes()`: un archivo de 500 MB no puede pasar por un
 * array. Las únicas cosas que se cargan enteras son las pequeñas, y siempre con
 * un tope explícito.
 */
object Sources {

    /** Tope para mostrar algo en pantalla. Por encima, va a archivo. */
    const val INLINE_LIMIT_BYTES = 256L * 1024

    private const val STREAM_BUFFER = 64 * 1024

    fun openInput(context: Context, uri: Uri): InputStream =
        BufferedInputStream(context.contentResolver.openInputStream(uri) ?: error("No se puede leer el archivo"), STREAM_BUFFER)

    /**
     * Abre el destino para escribir **desde cero** (`wt`, truncar y escribir).
     *
     * `CreateDocument` puede devolver un documento que ya existe: abrirlo en
     * modo `append` dejaría el sobre nuevo detrás del anterior y el resultado
     * sería un archivo corrupto que parece cifrado.
     */
    fun openOutput(context: Context, uri: Uri): OutputStream =
        BufferedOutputStream(
            context.contentResolver.openOutputStream(uri, "wt") ?: error("No se puede escribir el archivo"),
            STREAM_BUFFER
        )

    /**
     * Tamaño en bytes, o -1 si el proveedor no lo dice (algunos URI de
     * streaming no lo declaran hasta que se lee).
     */
    fun sizeOf(context: Context, uri: Uri): Long {
        runCatching {
            context.contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use { c ->
                if (c.moveToFirst() && !c.isNull(0)) return c.getLong(0)
            }
        }
        runCatching { DocumentFile.fromSingleUri(context, uri)?.length()?.takeIf { it > 0 }?.let { return it } }
        return -1
    }

    /** Nombre visible del documento, para mostrarlo junto a su tamaño. */
    fun nameOf(context: Context, uri: Uri): String {
        runCatching {
            context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst() && !c.isNull(0)) return c.getString(0)
            }
        }
        return uri.lastPathSegment?.substringAfterLast('/') ?: "archivo"
    }

    /**
     * Lee el contenido en memoria solo si cabe en [limit]. Si no cabe, devuelve
     * null: la decisión de pasarlo a archivo es de quien llama, no de aquí.
     */
    fun readIfSmall(context: Context, uri: Uri, limit: Long = INLINE_LIMIT_BYTES): ByteArray? {
        val size = sizeOf(context, uri)
        if (size in 0..limit) {
            runCatching { return openInput(context, uri).use { it.readBytes() } }
        }
        // Sin tamaño conocido: se lee a la tentativa y se corta en cuanto se pasa.
        return runCatching {
            openInput(context, uri).use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buf = ByteArray(STREAM_BUFFER)
                var total = 0L
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    total += n
                    if (total > limit) return null
                    out.write(buf, 0, n)
                }
                out.toByteArray()
            }
        }.getOrNull()
    }

    /**
     * Copia de un origen a otro sin cargarlo entero, a trozos.
     *
     * Sin callback de progreso a propósito: el progreso lo lleva
     * `CryptoEngine`, que ya sabe cuántos bytes ha procesado y no necesita que
     * nadie le account dos veces. Un `onBytes` aquí además era ambiguo —si
     * informaba del total acumulado o del incremento— y el primer test que
     * escribió contra él lo interpretó como incremento y falló.
     */
    fun copy(src: InputStream, dst: OutputStream) {
        val buf = ByteArray(STREAM_BUFFER)
        while (true) {
            val n = src.read(buf)
            if (n < 0) break
            dst.write(buf, 0, n)
        }
        dst.flush()
    }

    /** Archivo temporal en el caché, que se borra con [publish] o con el `delete` del llamante. */
    fun tempFile(context: Context, suffix: String): File =
        File.createTempFile("cifra", suffix, context.cacheDir)

    /**
     * Publica un temporal ya verificado en el destino que eligió el usuario.
     * Se copia y no se renombra porque el destino puede estar en otro volumen:
     * un `renameTo` entre volúmenes falla en silencio y perdería el resultado.
     */
    fun publish(temp: File, context: Context, destination: Uri) {
        openOutput(context, destination).use { dst ->
            temp.inputStream().buffered(STREAM_BUFFER).use { src -> copy(src, dst) }
        }
        temp.delete()
    }

    /** Formatea un tamaño en bytes como lo escribiría una persona. */
    fun formatBytes(bytes: Long): String {
        if (bytes < 0) return "tamaño desconocido"
        if (bytes < 1024) return "$bytes B"
        val units = arrayOf("KiB", "MiB", "GiB", "TiB")
        var value = bytes.toDouble() / 1024
        var i = 0
        while (value >= 1024 && i < units.size - 1) {
            value /= 1024
            i++
        }
        return String.format(Locale.ROOT, "%.1f %s", value, units[i])
    }
}
