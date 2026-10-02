package com.reimen.cifra.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import android.os.Build
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Tema de la app: Material 3 con una paleta propia, en claro y en oscuro.
 *
 * El acento es el mismo verde que la app lleva usando, para que no salte de golpe
 * al pasar de claro a oscuro: el fondo y las superficies cambian, el color de
 * marca se mantiene.
 *
 * Se mantiene también [CifraColors], que expone los colores que Material no
 * tipifica (el borde sutil de las tarjetas, el fondo del código, el verde del
 * texto descifrado). Un `ColorScheme` no tiene sitio para eso, y el patrón
 * usual de sustituirlo por `surfaceVariant` acaba deixando la pantalla plana.
 */
private val AccentDark = Color(0xFF00C9A0)
private val AccentLight = Color(0xFF00785F)

private val DarkScheme = darkColorScheme(
    primary = AccentDark,
    onPrimary = Color(0xFF00382E),
    primaryContainer = Color(0xFF005142),
    onPrimaryContainer = Color(0xFF6FFFD6),
    secondary = Color(0xFF7FD3C6),
    onSecondary = Color(0xFF00382E),
    tertiary = Color(0xFF8FB8D8),
    onTertiary = Color(0xFF00334F),
    background = Color(0xFF0E1118),
    onBackground = Color(0xFFE2E8F0),
    surface = Color(0xFF141A24),
    onSurface = Color(0xFFE2E8F0),
    surfaceVariant = Color(0xFF1D2535),
    onSurfaceVariant = Color(0xFF9AA8BD),
    surfaceContainer = Color(0xFF161C27),
    surfaceContainerHigh = Color(0xFF1B2330),
    surfaceContainerHighest = Color(0xFF212A39),
    surfaceContainerLow = Color(0xFF11161F),
    surfaceContainerLowest = Color(0xFF0A0E14),
    outline = Color(0xFF2A3347),
    outlineVariant = Color(0xFF232B3B),
    error = Color(0xFFFF6B6B),
    onError = Color(0xFF3A0A0A),
    errorContainer = Color(0xFF5C1B1B),
    onErrorContainer = Color(0xFFFFDAD6),
    scrim = Color(0xFF000000)
)

private val LightScheme = lightColorScheme(
    primary = AccentLight,
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFF9BF2DA),
    onPrimaryContainer = Color(0xFF00201A),
    secondary = Color(0xFF2F6B60),
    onSecondary = Color(0xFFFFFFFF),
    tertiary = Color(0xFF3B6478),
    onTertiary = Color(0xFFFFFFFF),
    background = Color(0xFFF7F9FB),
    onBackground = Color(0xFF11161F),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF11161F),
    surfaceVariant = Color(0xFFEDF1F5),
    onSurfaceVariant = Color(0xFF4A5567),
    surfaceContainer = Color(0xFFF1F5F9),
    surfaceContainerHigh = Color(0xFFEBF0F4),
    surfaceContainerHighest = Color(0xFFE5EBF0),
    surfaceContainerLow = Color(0xFFF6F9FB),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    outline = Color(0xFFC6D0DB),
    outlineVariant = Color(0xFFDCE4EC),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
    scrim = Color(0xFF000000)
)

/** Colores que Material 3 no tipifica y esta pantalla sí necesita. */
@Immutable
data class CifraColors(
    val success: Color,
    val onSuccess: Color,
    val successContainer: Color,
    val onSuccessContainer: Color,
    val warning: Color,
    /** Fondo de los bloques de texto monoespaciado. */
    val codeBackground: Color,
    val codeForeground: Color,
    /** Color del texto plano recién descifrado. */
    val plaintext: Color,
    /** Borde fino de las tarjetas informative. */
    val hairline: Color
)

private val ExtraColorsDark = CifraColors(
    success = Color(0xFF4ADE80),
    onSuccess = Color(0xFF052E16),
    successContainer = Color(0xFF12351F),
    onSuccessContainer = Color(0xFF86EFAC),
    warning = Color(0xFFFBBF24),
    codeBackground = Color(0xFF0A1520),
    codeForeground = Color(0xFF9FE8C8),
    plaintext = Color(0xFF4ADE80),
    hairline = Color(0xFF232B3B)
)

private val ExtraColorsLight = CifraColors(
    success = Color(0xFF15803D),
    onSuccess = Color(0xFFFFFFFF),
    successContainer = Color(0xFFDCFCE7),
    onSuccessContainer = Color(0xFF14532D),
    warning = Color(0xFFB45309),
    codeBackground = Color(0xFF0F172A),
    codeForeground = Color(0xFFB9F6D9),
    plaintext = Color(0xFF14532D),
    hairline = Color(0xFFDCE4EC)
)

private val LocalExtraColors = staticCompositionLocalOf { ExtraColorsDark }

private val CifraTypography = Typography(
    displaySmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 30.sp,
        lineHeight = 36.sp
    ),
    headlineSmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 22.sp,
        lineHeight = 28.sp
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp,
        lineHeight = 22.sp
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 15.sp,
        lineHeight = 22.sp
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 13.sp,
        lineHeight = 18.sp
    ),
    labelLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 13.sp,
        letterSpacing = 0.4.sp
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        letterSpacing = 0.6.sp
    )
)

/**
 * Tema Material 3.
 *
 * @param darkTheme      sigue al sistema.
 * @param dynamicColor  usa el color dinámico (Material You) cuando el sistema lo
 *        ofrece, es decir, Android 12 o superior. En ese caso el móvil pinta la
 *        app con su paleta y [DarkScheme]/[LightScheme] quedan solo como
 *        respaldo para versiones anteriores. Ponerlo a `false` fuerza siempre la
 *        paleta de marca, que es lo que quiere quien prefiera que Cifra se vea
 *        igual en todos los teléfonos.
 */
@Composable
fun CifraTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val context = LocalContext.current
    val dynamic = dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
    val scheme = when {
        dynamic && darkTheme -> dynamicDarkColorScheme(context)
        dynamic -> dynamicLightColorScheme(context)
        darkTheme -> DarkScheme
        else -> LightScheme
    }
    val extra = if (darkTheme) ExtraColorsDark else ExtraColorsLight
    CompositionLocalProvider(LocalExtraColors provides extra) {
        MaterialTheme(
            colorScheme = scheme,
            typography = CifraTypography,
            content = content
        )
    }
}

/** Colores propios del tema, accessibles desde cualquier parte de la pantalla. */
object CifraTheme {
    val colors: CifraColors
        @Composable
        @ReadOnlyComposable
        get() = LocalExtraColors.current

    /** Atajo al esquema activo. */
    val scheme: ColorScheme
        @Composable
        @ReadOnlyComposable
        get() = MaterialTheme.colorScheme
}

/** Dimensiones repetidas, para que la pantalla no suelte dp sueltos por ahí. */
/**
 * Marcas de los nodos que los tests de instrumentación necesitan localizar.
 *
 * Los tests de UI no deberían depender de los textos visibles: si mañana el
 * botón pone "CIFRAR EL TEXTO", los tests siguen funcionando.
 */
object Tags {
    const val CONTENT = "contenido"
    const val PASSWORD = "contrasena"
    const val PEPPER = "pepper"
    const val PASTE = "pegar"
    const val RUN = "ejecutar"
    const val RESULT = "resultado"
}

object Space {
    val xs = 4.dp
    val s = 8.dp
    val m = 12.dp
    val l = 16.dp
    val xl = 24.dp
}