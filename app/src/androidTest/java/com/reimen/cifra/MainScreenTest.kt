package com.reimen.cifra

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.reimen.cifra.ui.Tags
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Tests de la pantalla real, en un dispositivo real.
 *
 * No son un lujo: los dos bugs más molestos que aparecieron se encontraron a mano
 * en el móvil y **no los veía ningún test de JVM**. Los dos eran de la capa
 * Compose, que hasta ahora no tenía ni un test.
 *
 * Nota al escribir estos tests: la pantalla es una columna con scroll, así que
 * muchos nodos existen pero están fuera de la ventana. Por eso se usa
 * `assertExists()` para comprobar que algo se ha compuesto, y `performScrollTo()`
 * antes de interactuar con algo que puede estar más abajo.
 */
@RunWith(AndroidJUnit4::class)
class MainScreenTest {

    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    /**
     * La regresión del crash de arranque.
     *
     * Con lifecycle 2.8 y Compose 1.6 la app moría al abrirse con
     * `IllegalStateException: CompositionLocal LocalLifecycleOwner not present`.
     * Compilaba, el release se firmaba y los 188 tests de JVM pasaban; solo
     * montaba la ventana en un dispositivo y peta. Que estos nodos existan ya
     * demuestra que la composición llegó a completarse.
     */
    @Test
    fun laAppArrancaYMuestraLaPantalla() {
        rule.onNodeWithText("Cifrar").assertExists()
        rule.onNodeWithText("Descifrar").assertExists()
        rule.onNodeWithTag(Tags.PASTE).assertExists()
        rule.onNodeWithTag(Tags.RUN).assertExists()
        rule.onNodeWithTag(Tags.PASSWORD).assertExists()
    }

    /**
     * La regresión del camino de texto inalcanzable.
     *
     * El botón de pegar no existía, así que no había forma de meter texto a mano.
     * Y no era un detalle de interfaz: sin él la única entrada posible era elegir
     * un archivo, y `Content.Text` no se llegaba a dibujar nunca.
     *
     * Se prueba el recorrido entero —escribir el portapapeles y pulsar el botón—
     * porque eso es exactamente lo que faltaba.
     */
    @Test
    fun pegarTraeElTextoAlCampo() {
        val texto = "hola desde el portapapeles"
        portapapeles(texto)
        rule.onNodeWithTag(Tags.PASTE).performScrollTo().performClick()
        rule.waitForIdle()

        rule.onNodeWithTag(Tags.CONTENT).performScrollTo().assertIsDisplayed()
        assertTrue(leerCampo().contains(texto))
    }

    /**
     * El camino completo, sin tocar el SAF: cifrar un texto, leer el sobre y
     * descifrarlo. Es el recorrido que hace un usuario de la app.
     */
    @Test
    fun sePuedeCifrarYDescifrarUnTextoCorto() {
        val secreto = "esto es un secreto pequeño"
        val contraseña = "contraseña"

        portapapeles(secreto)
        rule.onNodeWithTag(Tags.PASTE).performScrollTo().performClick()
        rule.waitForIdle()
        rule.onNodeWithTag(Tags.PASSWORD).performScrollTo().performTextInput(contraseña)
        rule.onNodeWithTag(Tags.RUN).performScrollTo().performClick()

        val sobre = esperarResultado()
        assertTrue("el sobre debería parecer Base64, no: $sobre", sobre.startsWith("ey"))

        // Ahora al revés. Pegar de nuevo reemplaza el contenido, así que el
        // sobre no acaba pegado al texto en claro.
        rule.onNodeWithText("Descifrar").performScrollTo().performClick()
        rule.waitForIdle()
        portapapeles(sobre)
        rule.onNodeWithTag(Tags.PASTE).performScrollTo().performClick()
        rule.waitForIdle()
        // La contraseña NO se vuelve a escribir: cambiar de pestaña la conserva, y
        // teclearla otra vez la dejaría duplicada y el descifrado fallaría.
        rule.onNodeWithTag(Tags.RUN).performScrollTo().performClick()

        val recuperado = esperarResultado()
        assertTrue(
            "el secreto debería volver intacto, volvió: $recuperado",
            recuperado.contains(secreto)
        )
    }

    /**
     * Sin contraseña no se arranca nada. Se comprueba por el efecto observable —
     * que no aparezca ningún resultado— y no por el texto del aviso, que sale en
     * un Snackbar y se va solo: eso daría tests que fallan por tiempo.
     */
    @Test
    fun sinContrasenaNoSaleNada() {
        portapapeles("algo que solo")
        rule.onNodeWithTag(Tags.PASTE).performScrollTo().performClick()
        rule.waitForIdle()
        rule.onNodeWithTag(Tags.RUN).performScrollTo().performClick()
        rule.waitForIdle()

        assertEquals(0, rule.onAllNodesWithTag(Tags.RESULT).fetchSemanticsNodes().size)
    }

    /** Escribe en el portapapeles del sistema. */
    private fun portapapeles(texto: String) {
        val clipboard = InstrumentationRegistry.getInstrumentation().targetContext
            .getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("prueba", texto))
    }

    /** Argon2id no es instantáneo, así que el resultado no aparece de golpe. */
    private fun esperarResultado(): String {
        rule.waitUntil(timeoutMillis = 30_000) { leerResultadoOpcional().isNotBlank() }
        rule.onNodeWithTag(Tags.RESULT).performScrollTo().assertIsDisplayed()
        return leerResultado()
    }

    private fun leerResultado(): String =
        rule.onNodeWithTag(Tags.RESULT)
            .fetchSemanticsNode()
            .config[SemanticsProperties.Text]
            .joinToString("") { it.text }

    private fun leerResultadoOpcional(): String =
        rule.onAllNodesWithTag(Tags.RESULT).fetchSemanticsNodes()
            .firstOrNull()
            ?.config
            ?.get(SemanticsProperties.Text)
            ?.joinToString("") { it.text }
            ?: ""

    /** Un campo editable guarda su texto en [SemanticsProperties.EditableText]. */
    private fun leerCampo(): String =
        rule.onNodeWithTag(Tags.CONTENT)
            .fetchSemanticsNode()
            .config[SemanticsProperties.EditableText]
            .text
}