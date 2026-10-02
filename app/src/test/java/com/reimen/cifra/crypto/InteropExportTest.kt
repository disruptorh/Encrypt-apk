package com.reimen.cifra.crypto

import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Escribe sobres con Kotlin para que `tools/interop/verify.sh` los pase por la
 * biblioteca de C++.
 *
 * No es un test en sí mismo: sin la propiedad de sistema `interopOut` no hace
 * nada y se salta. La razón de existir es que la compatibilidad con Encrypt-C++
 * solo vale si se comprueba en *los dos* sentidos, y la otra mitad necesita C++
 * para poder hablar. El sentido inverso (Kotlin descifra lo que escribe C++) está
 * cubierto para siempre por [InteropVectorsTest], que lleva los vectores de C++
 * como datos fijos y no depende de que el proyecto de escritorio compile.
 */
class InteropExportTest {

    @Test
    fun `export blobs for the C++ side to decrypt`() {
        val out = System.getProperty("interopOut")
        assumeTrue("sin -PinteropOut no hay nada que exportar", out != null)

        val dir = File(out!!).apply { mkdirs() }
        val password = "clave-kotlin"
        val texts = listOf(
            "texto Kotlin \uD83D\uDE00 ñ 漢\n".toByteArray(Charsets.UTF_8),
            ByteArray(0),
            // Suficiente para que el Base64 y el streaming crucen varios trozos.
            ByteArray(500_000) { (it * 31 + 7).toByte() }
        )

        texts.forEachIndexed { index, plaintext ->
            // Sin pepper y con pepper, y con los dos perfiles: las cuatro
            // combinaciones que el sobre tiene que saber describir.
            listOf(
                CryptoEngine.KdfProfile.STANDARD to null,
                CryptoEngine.KdfProfile.MAXIMUM to "pepper-kotlin"
            ).forEach { (profile, pepper) ->
                val blob = CryptoEngine.encrypt(
                    plaintext,
                    password.toCharArray(),
                    pepper?.toCharArray(),
                    profile
                )
                val stem = "$index-${profile.memKib}"
                File(dir, "$stem.blob").writeText(blob)
                File(dir, "$stem.plain").writeBytes(plaintext)
                File(dir, "$stem.meta").writeText("$password\n${pepper ?: ""}\n")
            }
        }
    }
}