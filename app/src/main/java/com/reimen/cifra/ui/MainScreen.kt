package com.reimen.cifra.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.reimen.cifra.crypto.CryptoEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// Tema oscuro (misma paleta que el resto de apps del autor)
val C_bg = Color(0xFF0e1118)
val C_panel = Color(0xFF161c27)
val C_panel2 = Color(0xFF1d2535)
val C_border = Color(0xFF2a3347)
val C_accent = Color(0xFF00c9a0)
val C_text = Color(0xFFe2e8f0)
val C_dim = Color(0xFF94a3b8)
val C_muted = Color(0xFF475569)
val C_danger = Color(0xFFef4444)
val C_success = Color(0xFF22c55e)
val C_result_bg = Color(0xFF0a1520)
val C_result_fg = Color(0xFF4ade80)

private enum class Mode { ENCRYPT, DECRYPT }

@Composable
fun AppUI() {
    var tab by remember { mutableIntStateOf(0) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(C_bg)
            .safeDrawingPadding()
    ) {
        Header()
        TabRow(
            selectedTabIndex = tab,
            containerColor = C_panel,
            contentColor = C_accent,
            indicator = {}
        ) {
            Tab(selected = tab == 0, onClick = { tab = 0 }, text = { TabLabel("Cifrar", tab == 0) })
            Tab(selected = tab == 1, onClick = { tab = 1 }, text = { TabLabel("Descifrar", tab == 1) })
        }

        Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
            if (tab == 0) {
                CryptoScreen(mode = Mode.ENCRYPT)
            } else {
                CryptoScreen(mode = Mode.DECRYPT)
            }
        }
    }
}

@Composable
private fun Header() {
    Surface(color = C_panel, modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(horizontal = 20.dp, vertical = 14.dp)) {
            Text("Cifra", color = C_text, fontSize = 20.sp, fontWeight = FontWeight.Bold)
            Text("Cifrado local · AES-256-GCM + Argon2id", color = C_muted, fontSize = 11.sp)
        }
    }
}

@Composable
private fun TabLabel(label: String, selected: Boolean) {
    Text(
        label,
        color = if (selected) C_accent else C_dim,
        fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal
    )
}

@Composable
private fun CryptoScreen(mode: Mode) {
    var data by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var pepper by remember { mutableStateOf("") }
    var pepperVisible by remember { mutableStateOf(false) }
    var profile by remember { mutableStateOf(CryptoEngine.KdfProfile.STANDARD) }
    var result by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var messageIsError by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Column(modifier = Modifier.verticalScroll(rememberScrollState()).padding(16.dp)) {
        SectionTitle("DATOS")
        Card(colors = CardDefaults.cardColors(containerColor = C_panel), modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    if (mode == Mode.ENCRYPT) "Texto a cifrar" else "Sobre cifrado (Base64)",
                    color = C_dim, fontSize = 12.sp
                )
                OutlinedTextField(
                    value = data,
                    onValueChange = { data = it; result = ""; message = null },
                    modifier = Modifier.fillMaxWidth().height(110.dp),
                    minLines = 3,
                    textStyle = TextStyle(fontFamily = FontFamily.Monospace),
                    colors = fieldColors()
                )
                Spacer(modifier = Modifier.height(16.dp))
                SecretField("Contraseña (obligatoria)", password) {
                    password = it; result = ""; message = null
                }
                Spacer(modifier = Modifier.height(16.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Campo secreto adicional", color = C_dim, fontSize = 12.sp)
                    Spacer(modifier = Modifier.weight(1f))
                    TextButton(onClick = { pepperVisible = !pepperVisible }) {
                        Text(if (pepperVisible) "Ocultar" else "Mostrar", color = C_accent, fontSize = 12.sp)
                    }
                }
                if (pepperVisible) {
                    SecretField("Pepper (opcional, jamás se guarda)", pepper) {
                        pepper = it; result = ""; message = null
                    }
                    Text(
                        "Si lo usas al cifrar, debes escribirlo de nuevo al descifrar. Se pierde si lo olvidas.",
                        color = C_muted, fontSize = 11.sp, modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }
        }

        if (mode == Mode.ENCRYPT) {
            Spacer(modifier = Modifier.height(16.dp))
            SectionTitle("FUERZA")
            Card(colors = CardDefaults.cardColors(containerColor = C_panel), modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row {
                        CryptoEngine.KdfProfile.ALL.forEach { p ->
                            ProfileChip(
                                label = p.label,
                                selected = profile == p,
                                onClick = { profile = p },
                                modifier = Modifier.weight(1f)
                            )
                            if (p != CryptoEngine.KdfProfile.ALL.last()) Spacer(modifier = Modifier.width(8.dp))
                        }
                    }
                    Text(
                        when (profile) {
                            CryptoEngine.KdfProfile.STANDARD -> "64 MiB · 3 iteraciones · ~0,5–1 s"
                            else -> "256 MiB · 6 iteraciones · ~2–4 s (más lento, más fuerte)"
                        },
                        color = C_muted, fontSize = 11.sp, modifier = Modifier.padding(top = 8.dp)
                    )
                }
            }
        }

        message?.let { msg ->
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                msg,
                color = if (messageIsError) C_danger else C_success,
                fontSize = 13.sp,
                fontWeight = if (messageIsError) FontWeight.SemiBold else FontWeight.Normal
            )
        }

        Spacer(modifier = Modifier.height(16.dp))
        Button(
            onClick = {
                if (data.isEmpty()) {
                    message = "Escribe algún dato primero"; messageIsError = true; return@Button
                }
                if (password.isEmpty()) {
                    message = "La contraseña es obligatoria"; messageIsError = true; return@Button
                }
                if (mode == Mode.DECRYPT && data.isBlank()) {
                    message = "No hay sobre que descifrar"; messageIsError = true; return@Button
                }
                message = null
                busy = true
                result = ""
                scope.launch {
                    val passwordChars = password.toCharArray()
                    val pepperChars = if (pepper.isNotEmpty()) pepper.toCharArray() else null
                    try {
                        when (mode) {
                            Mode.ENCRYPT -> {
                                val blob = withContext(Dispatchers.Default) {
                                    CryptoEngine.encrypt(
                                        data.toByteArray(Charsets.UTF_8),
                                        passwordChars,
                                        pepperChars,
                                        profile
                                    )
                                }
                                result = blob
                                message = "Cifrado correcto"; messageIsError = false
                            }
                            Mode.DECRYPT -> {
                                // trim() no copia si el blob ya está limpio (caso normal);
                                // si el usuario pegó saltos de línea, recorta una sola vez.
                                val blob = data.trim()
                                val plain = withContext(Dispatchers.Default) {
                                    CryptoEngine.decrypt(blob, passwordChars, pepperChars)
                                }
                                result = String(plain, Charsets.UTF_8)
                                message = "Descifrado correcto"; messageIsError = false
                            }
                        }
                    } catch (e: CryptoEngine.CryptoException) {
                        message = e.message ?: "Error"; messageIsError = true
                        result = ""
                    } catch (e: Exception) {
                        message = "Error inesperado"; messageIsError = true
                        result = ""
                    } finally {
                        passwordChars.fill('\u0000')
                        pepperChars?.fill('\u0000')
                        busy = false
                    }
                }
            },
            modifier = Modifier.fillMaxWidth().height(50.dp),
            colors = ButtonDefaults.buttonColors(containerColor = C_accent),
            enabled = !busy
        ) {
            Text(
                when {
                    busy && mode == Mode.ENCRYPT -> "CIFRANDO…"
                    busy && mode == Mode.DECRYPT -> "DESCIFRANDO…"
                    mode == Mode.ENCRYPT -> "CIFRAR"
                    else -> "DESCIFRAR"
                },
                color = C_bg, fontWeight = FontWeight.Bold
            )
        }

        TextButton(
            onClick = {
                data = ""; password = ""; pepper = ""; result = ""; message = null
            },
            modifier = Modifier.fillMaxWidth().padding(top = 4.dp)
        ) {
            Text("Limpiar campos", color = C_muted, fontSize = 14.sp)
        }

        if (result.isNotEmpty()) {
            Spacer(modifier = Modifier.height(16.dp))
            SectionTitle(if (mode == Mode.ENCRYPT) "SOBRE CIFRADO" else "TEXTO DESCIFRADO")
            ResultCard(result)
        }
    }
}

@Composable
private fun ResultCard(value: String) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()

    Card(
        colors = CardDefaults.cardColors(containerColor = C_result_bg),
        border = androidx.compose.foundation.BorderStroke(1.dp, C_accent),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(value, color = C_result_fg, fontFamily = FontFamily.Monospace, fontSize = 14.sp)
            Spacer(modifier = Modifier.height(16.dp))
            Row {
                Button(
                    onClick = {
                        val clipboard = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE)
                                as android.content.ClipboardManager
                        val clip = android.content.ClipData.newPlainText("Cifra", value)
                        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                            clip.description.extras = android.os.PersistableBundle().apply {
                                putBoolean(android.content.ClipDescription.EXTRA_IS_SENSITIVE, true)
                            }
                        }
                        clipboard.setPrimaryClip(clip)
                        android.widget.Toast.makeText(
                            context, "Copiado · se borrará del portapapeles en 45 s", android.widget.Toast.LENGTH_SHORT
                        ).show()
                        scope.launch {
                            delay(45_000)
                            val current = clipboard.primaryClip?.getItemAt(0)?.text
                            if (current != null && current == value) {
                                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                                    clipboard.clearPrimaryClip()
                                } else {
                                    clipboard.setPrimaryClip(android.content.ClipData.newPlainText("", ""))
                                }
                            }
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = C_panel2)
                ) {
                    Text("Copiar", color = C_text)
                }
            }
        }
    }
}

@Composable
private fun ProfileChip(label: String, selected: Boolean, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .height(42.dp)
            .background(if (selected) C_accent.copy(alpha = 0.18f) else C_panel2, RoundedCornerShape(10.dp))
            .border(1.dp, if (selected) C_accent else C_border, RoundedCornerShape(10.dp))
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Text(label, color = if (selected) C_accent else C_dim, fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal, fontSize = 13.sp)
    }
}

@Composable
private fun SectionTitle(title: String) {
    Text(title, color = C_accent, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(bottom = 8.dp))
}

@Composable
private fun fieldColors() = OutlinedTextFieldDefaults.colors(
    focusedContainerColor = C_panel2,
    unfocusedContainerColor = C_panel2,
    focusedTextColor = C_text,
    unfocusedTextColor = C_text,
    focusedBorderColor = C_accent,
    unfocusedBorderColor = Color.Transparent
)

@Composable
private fun SecretField(label: String, value: String, onValueChange: (String) -> Unit) {
    var show by remember { mutableStateOf(false) }
    Column {
        Text(label, color = C_dim, fontSize = 12.sp)
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            trailingIcon = {
                Text(
                    if (show) "Ocultar" else "Ver",
                    modifier = Modifier.clickable { show = !show },
                    color = C_accent, fontSize = 12.sp
                )
            },
            modifier = Modifier.fillMaxWidth(),
            colors = fieldColors()
        )
    }
}
