package com.reimen.cifra

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import com.reimen.cifra.ui.AppUI
import com.reimen.cifra.ui.C_accent
import com.reimen.cifra.ui.C_bg
import com.reimen.cifra.ui.C_panel
import com.reimen.cifra.ui.C_text

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No permitir capturas de pantalla ni vista previa en recents:
        // el texto plano, la clave y el sobre no deben quedar en el historial.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        // Edge-to-edge explícito: la UI aplica los insets (barra de estado,
        // barra de navegación) para que nada quede superpuesto debajo de ellos.
        enableEdgeToEdge()
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    background = C_bg,
                    surface = C_panel,
                    onBackground = C_text,
                    onSurface = C_text,
                    primary = C_accent
                )
            ) {
                AppUI()
            }
        }
    }
}
