package com.reimen.cifra.data

import android.content.ContentProvider
import android.os.ParcelFileDescriptor
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.provider.OpenableColumns
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowContentResolver
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.Locale

/**
 * La capa que habla con `ContentResolver`, probada de verdad.
 *
 * Todo lo demás del proyecto se prueba sin Android; esta clase es la excepción
 * porque no hay forma honesta de hacerlo de otro modo: `Uri`, `ContentResolver` y
 * los proveedores de SAF son tipos de la plataforma. Robolectric levanta un
 * `Context` real, así que lo que se prueba aquí es el mismo código que corre en el
 * teléfono.
 *
 * Los documentos los sirve [DocumentsProviderFalso], un `ContentProvider` de
 * verdad, y no los registros a mano de `ShadowContentResolver`. La diferencia
 * importa: un `ShadowContentResolver.registerCursor` devuelve siempre las mismas
 * columnas y se salta el modo de apertura, y un proveedor real hace las dos
 * cosas. Probar contra el atajo habría dado por bueno un `Sources` que leyera
 * `SIZE` de la columna equivocada y otro que escribiera en modo `append`.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SourcesTest {

    private lateinit var context: Context
    private lateinit var provider: DocumentsProviderFalso

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        provider = DocumentsProviderFalso()
        // Sin esto el `authority` del provider es null y el `Transport` de Android
        // rechaza cada llamada; en una app real lo pone el manifiesto.
        provider.attachInfo(
            context,
            android.content.pm.ProviderInfo().apply { authority = DocumentsProviderFalso.AUTHORITY }
        )
        ShadowContentResolver.registerProviderInternal(DocumentsProviderFalso.AUTHORITY, provider)
    }

    private fun document(
        name: String,
        bytes: ByteArray,
        declaredSize: Long? = bytes.size.toLong(),
        visibleName: String? = name
    ): Uri = provider.put(name, visibleName, bytes, declaredSize)

    // --- openInput --------------------------------------------------------

    @Test
    fun `abre un documento de entrada y lee exactamente lo publicado`() {
        val contenido = "contenido del documento".toByteArray()
        val uri = document("entrada", contenido)

        val leido = Sources.openInput(context, uri).use { it.readBytes() }
        assertArrayEquals(contenido, leido)
    }

    @Test
    fun `un uri sin documento falla en vez de devolver un flujo vacío`() {
        // El fallo tiene que ser ruidoso: si `openInput` devolviera un flujo
        // vacío, la app cifraría un archivo vacío y diría que ha ido bien.
        val uri = Uri.parse("content://${DocumentsProviderFalso.AUTHORITY}/no-existe")
        val fallo = runCatching { Sources.openInput(context, uri).use { it.readBytes() } }
        assertTrue("esperaba un fallo; se leyó $fallo", fallo.isFailure)
    }

    @Test
    fun `cerrar el flujo de entrada deja el documento reabrible`() {
        val uri = document("cierre", ByteArray(50) { 7 })
        Sources.openInput(context, uri).use { it.read() }
        Sources.openInput(context, uri).use { assertEquals(50, it.readBytes().size) }
    }

    // --- openOutput -------------------------------------------------------

    @Test
    fun `escribe en el documento de destino`() {
        val uri = document("salida", ByteArray(0))
        Sources.openOutput(context, uri).use { it.write("datos de prueba".toByteArray()) }
        assertArrayEquals("datos de prueba".toByteArray(), provider.bytesOf(uri))
    }

    @Test
    fun `abre el destino en modo truncar y escribir`() {
        // El modo importa y no se puede comprobar mirando el resultado con un
        // `OutputStream` registrado a mano: el shadow se lo ignora. Aquí se ve en
        // el modo que le pide al proveedor.
        val uri = document("modo", ByteArray(0))
        Sources.openOutput(context, uri).use { it.write("x".toByteArray()) }
        assertEquals("wt", provider.lastWriteMode)
    }

    @Test
    fun `escribir dos veces en el mismo destino no deja el contenido anterior`() {
        // `CreateDocument` puede devolver un documento que ya existe. Si se
        // abriera en modo `append`, el segundo sobre quedaría detrás del primero
        // y el archivo sería un sobre corrupto disfrazado de válido.
        val uri = document("sobrescribe", ByteArray(0))
        Sources.openOutput(context, uri).use { it.write("primera".toByteArray()) }
        Sources.openOutput(context, uri).use { it.write("segunda".toByteArray()) }

        assertArrayEquals(
            "el segundo sobre debe reemplazar al primero",
            "segunda".toByteArray(),
            provider.bytesOf(uri)
        )
    }

    // --- sizeOf -----------------------------------------------------------

    @Test
    fun `devuelve el tamaño declarado por el proveedor`() {
        val uri = document("tamano", ByteArray(1234))
        assertEquals(1234L, Sources.sizeOf(context, uri))
    }

    @Test
    fun `lee la columna SIZE aunque se pidan varias columnas`() {
        // El proveedor devuelve las columnas que se le piden, en ese orden, y no
        // un mapa: `sizeOf` lee el índice 0, así que depende de que la petición
        // sea de una sola columna. Un cursor que devolviera siempre las columnas
        // completas escondería el error.
        val uri = document("orden", ByteArray(64))
        assertEquals(64L, Sources.sizeOf(context, uri))
    }

    @Test
    fun `un tamaño desconocido se reporta como desconocido y no como cero`() {
        // Importa: un 0 se leería como "archivo vacío" y haría decidir en contra
        // de escribir a disco. Lo desconocido tiene que ser -1.
        val uri = document("sin-tamano", ByteArray(10), declaredSize = null)
        assertEquals(-1L, Sources.sizeOf(context, uri))
    }

    @Test
    fun `un proveedor sin metadatos no tumba la pantalla`() {
        val uri = Uri.parse("content://${DocumentsProviderFalso.AUTHORITY}/fantasma")
        assertTrue(Sources.sizeOf(context, uri) < 0L)
    }

    @Test
    fun `un proveedor que lanza al preguntar el tamaño no tumba la pantalla`() {
        provider.throwOnQuery = true
        val uri = document("explota", ByteArray(10))
        // Aunque el proveedor reviente, `sizeOf` tiene que devolver algo
        // utilizable: la app no puede caerse por no saber cuánto mide un archivo.
        assertTrue(Sources.sizeOf(context, uri) < 0L)
    }

    // --- nameOf -----------------------------------------------------------

    @Test
    fun `devuelve el nombre visible del documento`() {
        val uri = document("informe.pdf", ByteArray(10))
        assertEquals("informe.pdf", Sources.nameOf(context, uri))
    }

    @Test
    fun `un nombre ausente cae a algo utilizable y no a una cadena vacía`() {
        val uri = document("sin-nombre", ByteArray(4), visibleName = null)
        val nombre = Sources.nameOf(context, uri)
        assertTrue("nombre=$nombre", nombre.isNotBlank())
    }

    @Test
    fun `un nombre con acentos llega intacto a la interfaz`() {
        val uri = document("año café.pdf", ByteArray(4))
        assertEquals("año café.pdf", Sources.nameOf(context, uri))
    }

    // --- readIfSmall ------------------------------------------------------

    @Test
    fun `lee en memoria lo que cabe en el limite`() {
        val contenido = ByteArray(1000) { it.toByte() }
        val uri = document("pequeno", contenido)
        assertArrayEquals(contenido, Sources.readIfSmall(context, uri))
    }

    @Test
    fun `devuelve null en vez de truncar lo que no cabe`() {
        // Un archivo recortado a la mitad y tratado como válido sería peor que no
        // leerlo: el usuario vería un texto descifrado que no es el suyo.
        val uri = document("grande", ByteArray(Sources.INLINE_LIMIT_BYTES.toInt() + 1))
        assertNull(Sources.readIfSmall(context, uri))
    }

    @Test
    fun `respeta un limite explicito`() {
        val contenido = ByteArray(500) { it.toByte() }
        val uri = document("limite", contenido)
        assertNull(Sources.readIfSmall(context, uri, limit = 100))
        assertArrayEquals(contenido, Sources.readIfSmall(context, uri, limit = 500))
    }

    @Test
    fun `sin tamaño declarado se lee a la tentativa y se corta al pasarse`() {
        // Un proveedor de streaming no siempre dice cuánto mide. El contenido es
        // de 1000 bytes y el límite son 500: tiene que devolver null, no los
        // primeros 500.
        val uri = document("a-ojos", ByteArray(1000) { it.toByte() }, declaredSize = null)
        assertNull(Sources.readIfSmall(context, uri, limit = 500))
    }

    @Test
    fun `sin tamaño declarado pero corto se lee igual`() {
        val contenido = ByteArray(100) { it.toByte() }
        val uri = document("a-ojos-corto", contenido, declaredSize = null)
        assertArrayEquals(contenido, Sources.readIfSmall(context, uri, limit = 500))
    }

    @Test
    fun `un documento que no existe devuelve null y no revienta`() {
        assertNull(Sources.readIfSmall(context, Uri.parse("content://${DocumentsProviderFalso.AUTHORITY}/nada")))
    }

    // --- copy -------------------------------------------------------------

    @Test
    fun `copy transfiere todo sin cargarlo entero`() {
        val origen = ByteArray(300_000) { (it % 251).toByte() }
        val destino = ByteArrayOutputStream()
        Sources.copy(ByteArrayInputStream(origen), destino)
        assertArrayEquals(origen, destino.toByteArray())
    }

    @Test
    fun `copy de un flujo vacío no escribe nada`() {
        val destino = ByteArrayOutputStream()
        Sources.copy(ByteArrayInputStream(ByteArray(0)), destino)
        assertEquals(0, destino.size())
    }

    // --- tempFile / publish ----------------------------------------------

    @Test
    fun `tempFile crea un archivo real, vacio y con el sufijo pedido`() {
        val temp = Sources.tempFile(context, ".cifra")
        try {
            assertTrue(temp.exists())
            assertEquals(0L, temp.length())
            assertTrue("nombre=${temp.name}", temp.name.endsWith(".cifra"))
        } finally {
            temp.delete()
        }
    }

    @Test
    fun `tempFile no repite nombres entre llamadas`() {
        val a = Sources.tempFile(context, ".t")
        val b = Sources.tempFile(context, ".t")
        try {
            assertTrue("dos temporales con la misma ruta", a.absolutePath != b.absolutePath)
        } finally {
            a.delete()
            b.delete()
        }
    }

    @Test
    fun `tempFile va al area privado de la app`() {
        // Si el temporal acabara en un directorio compartido, otro proceso con
        // permiso de lectura vería el texto descifrado antes de publicarlo.
        val temp = Sources.tempFile(context, ".priv")
        try {
            assertTrue(
                "ruta=${temp.absolutePath} cache=${context.cacheDir}",
                temp.absolutePath.startsWith(context.cacheDir.absolutePath)
            )
        } finally {
            temp.delete()
        }
    }

    @Test
    fun `publish deja el contenido del temporal en el destino`() {
        val uri = document("publicado", ByteArray(0))
        val temp = Sources.tempFile(context, ".tmp")
        try {
            val contenido = "lo que hay que publicar".toByteArray()
            temp.writeBytes(contenido)
            Sources.publish(temp, context, uri)
            assertArrayEquals(contenido, provider.bytesOf(uri))
        } finally {
            temp.delete()
        }
    }

    @Test
    fun `publish borra el temporal`() {
        // El temporal contiene texto descifrado en claro: si sobrevive a una
        // publicación correcta, se queda en el caché para siempre.
        val uri = document("publicado2", ByteArray(0))
        val temp = Sources.tempFile(context, ".tmp")
        temp.writeBytes(ByteArray(10))
        Sources.publish(temp, context, uri)
        assertFalse("el temporal debe borrarse tras publicar", temp.exists())
    }

    @Test
    fun `un temporal de 5 MiB se publica entero y en trozos`() {
        val uri = document("grande", ByteArray(0))
        val temp = Sources.tempFile(context, ".tmp")
        try {
            val contenido = ByteArray(5 * 1024 * 1024) { (it % 251).toByte() }
            temp.writeBytes(contenido)
            Sources.publish(temp, context, uri)
            assertArrayEquals(contenido, provider.bytesOf(uri))
        } finally {
            temp.delete()
        }
    }

    // --- formatBytes ------------------------------------------------------

    @Test
    fun `formatBytes usa unidades binarias`() {
        assertEquals("0 B", Sources.formatBytes(0))
        assertEquals("1 B", Sources.formatBytes(1))
        assertEquals("1023 B", Sources.formatBytes(1023))
        assertEquals("1.0 KiB", Sources.formatBytes(1024))
        assertEquals("1.0 MiB", Sources.formatBytes(1024L * 1024))
        assertEquals("1.0 GiB", Sources.formatBytes(1024L * 1024 * 1024))
    }

    @Test
    fun `formatBytes no usa coma decimal aunque el sistema la tenga`() {
        // Un `String.format` sin `Locale.ROOT` escribe "1,5 MiB" en alemán y en
        // español. El mismo código daría textos distintos según el idioma del
        // móvil, que es justo lo que no debe pasar con un tamaño de archivo.
        val original = Locale.getDefault()
        try {
            Locale.setDefault(Locale.GERMANY)
            assertEquals("1.5 MiB", Sources.formatBytes(1024L * 1024 * 3 / 2))
        } finally {
            Locale.setDefault(original)
        }
    }

    @Test
    fun `un tamaño negativo se dice que se desconoce`() {
        assertEquals("tamaño desconocido", Sources.formatBytes(-1))
    }
}

/**
 * Proveedor de documentos mínimo, pero con las dos cosas que importan y que
 * `ShadowContentResolver` no hace: devolver **solo** las columnas que se le
 * piden, y respetar el modo con el que se abre para escribir.
 */
private class DocumentsProviderFalso : ContentProvider() {

    companion object {
        const val AUTHORITY = "cifra.test.docs"
    }

    private class Doc(val name: String?, val declaredSize: Long?, val file: File)

    private val docs = mutableMapOf<String, Doc>()
    private val archivos = mutableListOf<File>()

    /** Último archivo creado al escribir en cada documento: su contenido actual. */
    private val escritos = mutableMapOf<String, File>()

    /** Lo último con lo que se abrió para escribir, para poder comprobarlo. */
    var lastWriteMode: String? = null
        private set

    /** Hace que `query` reviente, para probar que la app no se cae. */
    var throwOnQuery = false

    fun put(name: String, visibleName: String?, bytes: ByteArray, declaredSize: Long?): Uri {
        val file = File.createTempFile("cifra-doc", ".bin").apply { writeBytes(bytes) }
        archivos += file
        docs[name] = Doc(visibleName, declaredSize, file)
        return Uri.parse("content://$AUTHORITY/${Uri.encode(name)}")
    }

    fun bytesOf(uri: Uri): ByteArray? =
        (escritos[keyOf(uri)] ?: docs[keyOf(uri)]?.file)?.readBytes()

    private fun keyOf(uri: Uri): String = Uri.decode(uri.lastPathSegment ?: "")

    /**
     * `ContentResolver.openInputStream` acaba aquí, así que hacen falta
     * descriptores de archivo de verdad. El contenido vive en un archivo real, y
     * escribir crea uno nuevo: por eso el modo se puede comprobar de verdad.
     */
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor? {
        val clave = keyOf(uri)
        val esLectura = mode.startsWith("r")
        val destino = if (esLectura) {
            docs[clave]?.file ?: return null
        } else {
            lastWriteMode = mode
            File.createTempFile("cifra-doc", ".out").also {
                archivos += it
                escritos[clave] = it
            }
        }
        val flags = if (esLectura) {
            ParcelFileDescriptor.MODE_READ_ONLY
        } else {
            ParcelFileDescriptor.MODE_CREATE or
                ParcelFileDescriptor.MODE_READ_WRITE or
                ParcelFileDescriptor.MODE_TRUNCATE
        }
        return ParcelFileDescriptor.open(destino, flags)
    }

    override fun onCreate() = true

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?
    ): Cursor? {
        if (throwOnQuery) throw SecurityException("proveedor sin permiso")
        val doc = docs[keyOf(uri)] ?: return null
        // Como un proveedor real: solo las columnas pedidas, en ese orden.
        val columns = projection?.takeIf { it.isNotEmpty() }
            ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        val cursor = MatrixCursor(columns)
        cursor.addRow(columns.map { column ->
            when (column) {
                OpenableColumns.DISPLAY_NAME -> doc.name
                OpenableColumns.SIZE -> doc.declaredSize
                else -> null
            }
        })
        return cursor
    }

    override fun getType(uri: Uri): String = "application/octet-stream"

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?) = 0
    override fun update(
        uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?
    ) = 0
}