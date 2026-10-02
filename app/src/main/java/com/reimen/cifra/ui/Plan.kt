package com.reimen.cifra.ui

/**
 * Las decisiones de la pantalla, sin Android detrás.
 *
 * Todo lo que decide *qué hacer* —y no lo que ejecuta— vive aquí para poder
 * probarlo en la JVM normal. La regla que se sigue en el resto del proyecto es
 * que `crypto/` es Kotlin puro y se prueba sin emulador; esta clase mantiene esa
 * propiedad para la capa de UI, que si no solo se podía probar a mano.
 *
 * Estas funciones son deliberadamente conservadoras: cuando no se sabe un
 * tamaño, se estima de más, y cuando hay duda se elige el archivo. Un error en
 * este sentido cuesta un diálogo de más; el otro cuesta un `OutOfMemoryError`.
 */
object Plan {

    /**
     * Techo de bytes para un texto de [chars] unidades UTF-16.
     *
     * No es `chars.toByteArray().size` —eso reserva un array del tamaño del
     * texto, justo lo que se quiere evitar— ni `chars`, que es lo que se usó
     * antes y está mal: un emoji son 2 unidades UTF-16 y 4 bytes UTF-8, así que
     * contar unidades de código *subestima* el texto real. Con emojis el cálculo
     * anterior se quedaba en la mitad de su valor, la barra de progreso llegaba
     * al 100 % a la mitad del trabajo y un texto grande se podía enrutar a
     * memoria believing que cabía en memoria.
     *
     * El peor caso por unidad UTF-16 son 3 bytes (caracteres BMP), porque un par
     * suplente son 2 unidades para 4 bytes, o sea 2 por unidad. Con 3 por unidad
     * la cota es un óptimo para UTF-8: nunca se queda corta.
     */
    fun upperBoundForText(chars: Int): Long {
        if (chars < 0) return -1L
        // Un texto vacío sigue produciendo un sobre entero, así que el mínimo no
        // es 0 sino lo que ocupa la cabecera.
        return envelopeOverhead(chars.toLong() * 3L)
    }

    /**
     * Tamaño de un texto de [plaintextBytes] ya codificado, una vez dentro del
     * sobre.
     *
     * El sobre crece ~4/3 por el Base64 interior y ~4/3 más por el exterior,
     * más la cabecera JSON; 16/9 es 1.777… y sobra. Los 512 bytes de margen
     * cubren la cabecera y el redondeo de los dos Base64.
     *
     * `-1` (tamaño desconocido) se propaga como `-1`: quien llama tiene que
     * distinguir "pequeño" de "no lo sé", y confundirlos sería elegir destino
     * por un número inventado.
     */
    fun upperBoundForPlaintext(plaintextBytes: Long): Long {
        if (plaintextBytes < 0) return -1L
        return envelopeOverhead(plaintextBytes)
    }

    /** @param plaintextBytes tamaño en UTF-8, o `-1` si no se conoce. */
    private fun envelopeOverhead(plaintextBytes: Long): Long {
        // Saturar en vez de desbordar: un Long negativo ya significaría "no cabe".
        val headroom = Long.MAX_VALUE / 16 * 9
        if (plaintextBytes > headroom) return Long.MAX_VALUE
        return plaintextBytes * 16 / 9 + 512
    }

    /**
     * Bytes exactos que ocupa [text] codificado en UTF-8.
     *
     * Recorre los puntos de código sin reservar nada: `toByteArray(UTF_8)`
     * reservaría un array del tamaño del texto, que para un pegado grande es
     * justo lo que esta app evita. O(n) en tiempo, O(1) en memoria.
     *
     * Es exacto para texto bien formado. Un suplente suelto —una `String` con un
     * UTF-16 mal partido, que solo sale de bugs o de una entrada poco habitual—
     * cuenta 3 bytes donde el codificador de Java pone un `?` de 1, así que en ese
     * caso la cifra va de más, que es el lado correcto para no quedarse corto.
     */
    fun utf8Length(text: String): Long {
        var bytes = 0L
        var i = 0
        val n = text.length
        while (i < n) {
            val codePoint = text.codePointAt(i)
            bytes += when {
                codePoint < 0x80 -> 1L
                codePoint < 0x800 -> 2L
                codePoint < 0x10000 -> 3L
                else -> 4L
            }
            i += Character.charCount(codePoint)
        }
        return bytes
    }

    /**
     * ¿El resultado va a un archivo en vez de a la pantalla?
     *
     * Un tamaño desconocido cuenta como "sí, a archivo". Es la dirección segura:
     * si un proveedor de SAF no declara la longitud, se pide el destino antes de
     * empezar en lugar de descubrir a mitad de un archivo de 8 GB que no cabe en
     * memoria.
     */
    fun needsFile(expectedOutputBytes: Long, inlineLimitBytes: Long): Boolean =
        expectedOutputBytes < 0 || expectedOutputBytes > inlineLimitBytes

    /**
     * Nombre sugerido para el archivo de destino.
     *
     * [inputName] es el nombre del archivo de entrada, o `null` si la entrada es
     * un texto pegado. El tallo se recorta para que el resultado completo quepa
     * en [MAX_NAME_BYTES]: muchos proveedores de SAF rechazan el archivo si no,
     * y fallar al *crear* el destino —después de que el usuario haya escrito la
     * contraseña— es una forma muy cara de discovered un nombre demasiado largo.
     */
    fun outputName(inputName: String?, encrypting: Boolean): String {
        val extension = if (encrypting) "cifrado.txt" else "descifrado.txt"
        val stem = inputName?.substringBeforeLast('.')?.takeIf { it.isNotBlank() } ?: "cifra"
        val suffix = ".$extension"
        // Contar caracteres no es contar bytes: los nombres se limitan por bytes
        // en la mayoría de los sistemas de archivos, y aquí hay nombres con
        // acentos. Recortar por bytes UTF-8 es lo único que no miente.
        val budget = MAX_NAME_BYTES - suffix.toByteArray(Charsets.UTF_8).size
        if (budget <= 0) return extension
        return truncateToBytes(stem, budget) + suffix
    }

    /** Prefijo de [value] que cabe en [maxBytes] UTF-8, sin partir un carácter. */
    private fun truncateToBytes(value: String, maxBytes: Int): String {
        var bytes = 0
        var end = 0
        while (end < value.length) {
            val codePoint = value.codePointAt(end)
            val charCount = Character.charCount(codePoint)
            val charBytes = String(Character.toChars(codePoint)).toByteArray(Charsets.UTF_8).size
            if (bytes + charBytes > maxBytes) break
            bytes += charBytes
            end += charCount
        }
        return value.substring(0, end)
    }

    /** Los proveedores y el kernel de Linux recortan a 255 bytes por nombre. */
    const val MAX_NAME_BYTES = 255
}