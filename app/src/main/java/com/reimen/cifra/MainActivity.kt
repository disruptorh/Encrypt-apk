package com.reimen.cifra

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.reimen.cifra.ui.AppUI
import com.reimen.cifra.ui.CifraTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No permitir capturas de pantalla ni vista previa en la lista de apps
        // recientes: el texto plano, la contraseña y el sobre no deben quedar
        // en el historial del sistema.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        // Edge-to-edge explícito: el tema pinta las barras del sistema y el
        // `Scaffold` aplica los insets, para que nada quede bajo ellas.
        enableEdgeToEdge()
        setContent {
            // Sin `darkTheme` explícito: se sigue al ajuste del sistema.
            CifraTheme {
                AppUI()
            }
        }
    }
}