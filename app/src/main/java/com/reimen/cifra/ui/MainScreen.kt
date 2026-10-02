package com.reimen.cifra.ui

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.reimen.cifra.crypto.CryptoEngine
import com.reimen.cifra.data.Sources

/**
 * Pantalla única: elegir operación, elegir entrada, credenciales, fuerza, ejecutar
 * y ver el resultado.
 *
 * Dos decisiones que atraviesan toda la pantalla:
 *
 *  - **Nada grande se pinta.** Un resultado por encima de
 *    [Sources.INLINE_LIMIT_BYTES] va a un archivo elegido por el usuario, porque
 *    meter 200 MB en un `Text` de Compose no es una opción ni un mal rato.
 *  - **Las operaciones largas se cancelan y enseñan progreso real**, no un
 *    spinner infinito: el trabajo va por trozos y cada trozo mueve la barra.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppUI(viewModel: CryptoViewModel = viewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val snackbars = remember { SnackbarHostState() }

    // El picker se lanza antes de saber el URI de destino, así que hay que
    // acordarse de qué operación iba a escribir en él.
    var pending by remember { mutableStateOf<Pending?>(null) }

    val pickInput = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            // Sin permiso persistente, el URI muere con el proceso y el
            // descifrado de un archivo deja de funcionar al volver de segundo plano.
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            }
            viewModel.setInputFile(uri)
        }
    }

    val pickOutput =
        rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
            val job = pending
            pending = null
            if (uri != null && job != null) {
                when (job) {
                    Pending.Encrypt -> viewModel.encryptTo(uri)
                    Pending.Decrypt -> viewModel.decryptTo(uri)
                }
            }
        }

    // Los mensajes se disparan una sola vez por resultado. Sin este cuidado,
    // `LaunchedEffect(phase)` se relanzaría en cada trozo de 64 KiB porque
    // `Running` es un objeto nuevo en cada actualización de progreso.
    val terminal = when (val p = state.phase) {
        is CryptoViewModel.Phase.Ok -> p.message
        is CryptoViewModel.Phase.Failed -> p.message
        CryptoViewModel.Phase.Cancelled -> "Operación cancelada"
        else -> null
    }
    LaunchedEffect(terminal) {
        if (terminal != null) {
            snackbars.showSnackbar(terminal)
            viewModel.dismissPhase()
        }
    }

    fun run() {
        when {
            state.mode == CryptoViewModel.Mode.ENCRYPT && state.outputNeedsFile -> {
                pending = Pending.Encrypt
                pickOutput.launch(suggestedName(state))
            }
            state.mode == CryptoViewModel.Mode.ENCRYPT -> viewModel.encrypt()
            state.outputNeedsFile -> {
                pending = Pending.Decrypt
                pickOutput.launch(suggestedName(state))
            }
            else -> viewModel.decrypt()
        }
    }

    Scaffold(
        topBar = { AppBar() },
        snackbarHost = { SnackbarHost(snackbars) },
        containerColor = MaterialTheme.colorScheme.background
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = Space.l, vertical = Space.m)
        ) {
            ModeTabs(state.mode, viewModel::setMode)
            Spacer(Modifier.height(Space.l))

            InputCard(
                state = state,
                onTextChange = viewModel::setInputText,
                onPickFile = { pickInput.launch(arrayOf("*/*")) },
                onClear = viewModel::clearInput
            )
            Spacer(Modifier.height(Space.l))

            CredentialsCard(state, viewModel)
            Spacer(Modifier.height(Space.l))

            if (state.mode == CryptoViewModel.Mode.ENCRYPT) {
                StrengthCard(state.profile, viewModel::setProfile)
                Spacer(Modifier.height(Space.l))
            }

            RunSection(state = state, onRun = ::run, onCancel = viewModel::cancel)

            AnimatedVisibility(
                visible = state.outcome !is CryptoViewModel.Outcome.None,
                enter = fadeIn() + expandVertically(),
                exit = fadeOut() + shrinkVertically()
            ) {
                Column {
                    Spacer(Modifier.height(Space.l))
                    OutcomeCard(
                        state = state,
                        onSave = {
                            pending =
                                if (state.mode == CryptoViewModel.Mode.ENCRYPT) Pending.Encrypt else Pending.Decrypt
                            pickOutput.launch(suggestedName(state))
                        },
                        onDismiss = viewModel::clearInput
                    )
                }
            }

            Spacer(Modifier.height(Space.xl))
            FooterNote()
        }
    }
}

/** Qué hay que hacer en cuanto el usuario elija el archivo de destino. */
private enum class Pending { Encrypt, Decrypt }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AppBar() {
    TopAppBar(
        title = {
            Column {
                Text("Cifra", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Cifrado local · XChaCha20-Poly1305 + Argon2id",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = MaterialTheme.colorScheme.surface,
            titleContentColor = MaterialTheme.colorScheme.onSurface
        )
    )
}

@Composable
private fun ModeTabs(mode: CryptoViewModel.Mode, onChange: (CryptoViewModel.Mode) -> Unit) {
    val modes = CryptoViewModel.Mode.entries
    TabRow(
        selectedTabIndex = modes.indexOf(mode),
        containerColor = MaterialTheme.colorScheme.surface,
        contentColor = MaterialTheme.colorScheme.primary
    ) {
        modes.forEach { m ->
            Tab(
                selected = m == mode,
                onClick = { onChange(m) },
                text = {
                    Text(
                        text = if (m == CryptoViewModel.Mode.ENCRYPT) "Cifrar" else "Descifrar",
                        fontWeight = if (m == mode) FontWeight.Bold else FontWeight.Normal
                    )
                }
            )
        }
    }
}

@Composable
private fun SectionCard(
    title: String,
    modifier: Modifier = Modifier,
    trailing: @Composable (() -> Unit)? = null,
    content: @Composable () -> Unit
) {
    ElevatedCard(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(Modifier.padding(Space.l)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = title.uppercase(),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary
                )
                Spacer(Modifier.weight(1f))
                trailing?.invoke()
            }
            Spacer(Modifier.height(Space.m))
            content()
        }
    }
}

@Composable
private fun InputCard(
    state: CryptoViewModel.UiState,
    onTextChange: (String) -> Unit,
    onPickFile: () -> Unit,
    onClear: () -> Unit
) {
    val context = LocalContext.current
    val encrypting = state.mode == CryptoViewModel.Mode.ENCRYPT
    // Pegar REEMPLAZA lo que hubiera, no lo añade al final. Si no, en modo
    // descifrar un sobre pegado encima de lo anterior daría un error de formato
    // que no explica dónde está el problema.
    val pasteAction = {
        val text = readClipboard(context)
        if (text.isNullOrBlank()) {
            Toast.makeText(context, "El portapapeles está vacío", Toast.LENGTH_SHORT).show()
        } else {
            onTextChange(text)
        }
    }
    SectionCard(
        title = if (encrypting) "Contenido" else "Sobre",
        trailing = {
            if (state.input !is CryptoViewModel.Content.None) {
                TextButton(onClick = onClear) {
                    Text(text = "Quitar", style = MaterialTheme.typography.labelSmall)
                }
            }
        }
    ) {
        when (val input = state.input) {
            CryptoViewModel.Content.None -> {
                Text(
                    text = if (encrypting) {
                        "Pega el texto o elige un archivo."
                    } else {
                        "Pega el sobre cifrado o elige el archivo que lo contiene."
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(Space.m))
                // Sin esto el texto era inalcanzable: el campo editable de la
                // rama `Content.Text` solo se ve cuando el contenido YA es texto,
                // y la única forma de que eso pase es ese mismo campo. La app
                // pedía «pega el texto» sin ofrecer ningún sitio donde pegar,
                // y no se enteraba nadie porque los tests no llegan a la
                // navegación de estados y el lint no mira eso.
                OutlinedButton(onClick = pasteAction, modifier = Modifier.fillMaxWidth().testTag(Tags.PASTE)) {
                    Icon(Icons.Default.ContentPaste, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(Space.s))
                    Text(text = if (encrypting) "Pegar texto" else "Pegar sobre")
                }
                Spacer(Modifier.height(Space.s))
                OutlinedButton(onClick = onPickFile, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.FolderOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(Space.s))
                    Text(text = "Elegir archivo")
                }
            }

            is CryptoViewModel.Content.File -> {
                FileRow(input.name, state.inputNote, onPickFile)
                if (state.outputNeedsFile) {
                    Spacer(Modifier.height(Space.m))
                    Text(
                        text = "El resultado no cabe en pantalla, así que se escribirá en un archivo que elijas.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = CifraTheme.colors.warning
                    )
                }
            }

            is CryptoViewModel.Content.Text -> {
                OutlinedTextField(
                    value = input.value,
                    onValueChange = onTextChange,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 140.dp, max = 320.dp)
                        .testTag(Tags.CONTENT),
                    textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
                    label = { Text(text = if (encrypting) "Texto a cifrar" else "Sobre en Base64") },
                    placeholder = {
                        Text(
                            text = if (encrypting) "Lo que quieras ocultar…" else "v1:AAAA…",
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                )
                Spacer(Modifier.height(Space.s))
                Text(
                    text = state.inputNote,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                TextButton(onClick = onPickFile) {
                    Icon(Icons.Default.FolderOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(Space.s))
                    Text(text = "Usar un archivo en su lugar", style = MaterialTheme.typography.labelLarge)
                }
                Spacer(Modifier.height(Space.xs))
                // El botón de pegar también aquí, y no solo cuando no hay nada:
                // si solo existiera en el estado vacío, en cuanto hubiera texto
                // desaparecería y no se podría pegar otro sobre para reemplazarlo,
                // que es justo lo que hace falta al probar una contraseña nueva.
                OutlinedButton(
                    onClick = pasteAction,
                    modifier = Modifier.fillMaxWidth().testTag(Tags.PASTE)
                ) {
                    Icon(Icons.Default.ContentPaste, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(Space.s))
                    Text(text = if (encrypting) "Pegar texto" else "Pegar sobre")
                }
            }
        }
    }
}

@Composable
private fun FileRow(name: String, note: String, onReplace: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .clickable(onClick = onReplace)
            .padding(Space.m),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = Icons.Default.Description,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary
        )
        Spacer(Modifier.width(Space.m))
        Column(Modifier.weight(1f)) {
            Text(
                text = name,
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = note,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(Modifier.width(Space.s))
        Icon(
            imageVector = Icons.Default.Close,
            contentDescription = "Cambiar de archivo",
            tint = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun CredentialsCard(state: CryptoViewModel.UiState, viewModel: CryptoViewModel) {
    SectionCard(title = "Credenciales") {
        SecretField(
            label = "Contraseña",
            value = state.password,
            onValueChange = viewModel::setPassword,
            hint = "Obligatoria. Se usa solo aquí y se borra de memoria al terminar.",
            tag = Tags.PASSWORD
        )
        Spacer(Modifier.height(Space.m))
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Spacer(Modifier.height(Space.s))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(text = "Campo secreto adicional", style = MaterialTheme.typography.bodyLarge)
                Text(
                    text = if (state.pepperVisible) {
                        "Opcional. Se mezcla con la contraseña para derivar la clave."
                    } else {
                        "Opcional. Se puede dejar vacío."
                    },
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            TextButton(onClick = viewModel::togglePepper) {
                Text(
                    text = if (state.pepperVisible) "Ocultar" else "Usar",
                    style = MaterialTheme.typography.labelLarge
                )
            }
        }

        if (state.pepperVisible) {
            SecretField(
                label = "Pepper",
                value = state.pepper,
                onValueChange = viewModel::setPepper,
                hint = "Hay que repetirlo al descifrar. Si se pierde, el archivo no se puede abrir.",
                tag = Tags.PEPPER
            )
        }
    }
}

@Composable
private fun StrengthCard(profile: CryptoEngine.KdfProfile, onChange: (CryptoEngine.KdfProfile) -> Unit) {
    SectionCard(title = "Fuerza") {
        Column(Modifier.selectableGroup()) {
            CryptoEngine.KdfProfile.ALL.forEach { p ->
                ProfileRow(profile = p, selected = p == profile, onClick = { onChange(p) })
            }
        }
        Spacer(Modifier.height(Space.s))
        Text(
            text = if (profile == CryptoEngine.KdfProfile.STANDARD) {
                "Rápido y más que suficiente contra ataques por fuerza bruta."
            } else {
                "Mucho más lento a propósito: para cuando la contraseña sea el punto más débil."
            },
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun ProfileRow(profile: CryptoEngine.KdfProfile, selected: Boolean, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .clickable(onClick = onClick)
            .padding(vertical = Space.xs),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Spacer(Modifier.width(Space.s))
        Column {
            Text(text = profile.label, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = "${profile.memKib / 1024} MiB · ${profile.iterations} iteraciones",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun SecretField(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
    hint: String,
    tag: String
) {
    var visible by remember { mutableStateOf(false) }
    Column {
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            modifier = Modifier.fillMaxWidth().testTag(tag),
            label = { Text(text = label) },
            singleLine = true,
            visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            trailingIcon = {
                IconButton(onClick = { visible = !visible }) {
                    Icon(
                        imageVector = if (visible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                        contentDescription = if (visible) "Ocultar" else "Mostrar"
                    )
                }
            }
        )
        Spacer(Modifier.height(Space.xs))
        Text(
            text = hint,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun RunSection(
    state: CryptoViewModel.UiState,
    onRun: () -> Unit,
    onCancel: () -> Unit
) {
    val running = state.phase as? CryptoViewModel.Phase.Running
    Column {
        Button(
            onClick = onRun,
            enabled = state.canRun,
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp)
                .testTag(Tags.RUN),
            shape = RoundedCornerShape(14.dp)
        ) {
            Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(Space.s))
            Text(
                text = when {
                    running != null -> running.label.uppercase() + "…"
                    state.mode == CryptoViewModel.Mode.ENCRYPT -> "CIFRAR"
                    else -> "DESCIFRAR"
                },
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Bold
            )
        }

        AnimatedVisibility(visible = running != null) {
            Column {
                Spacer(Modifier.height(Space.m))
                val fraction = running?.fraction
                if (fraction != null) {
                    LinearProgressIndicator(
                        progress = { fraction },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(6.dp)
                            .clip(RoundedCornerShape(3.dp)),
                        color = MaterialTheme.colorScheme.primary,
                        trackColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                } else {
                    // Sin total conocido: indeterminado, pero con los bytes hechos
                    // a la vista para que no parezca colgado.
                    LinearProgressIndicator(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(6.dp)
                            .clip(RoundedCornerShape(3.dp)),
                        color = MaterialTheme.colorScheme.primary,
                        trackColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                }
                Spacer(Modifier.height(Space.s))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = running?.let { progressText(it) }.orEmpty(),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(onClick = onCancel) {
                        Text(
                            text = "Cancelar",
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                }
            }
        }
    }
}

private fun progressText(running: CryptoViewModel.Phase.Running): String {
    val done = Sources.formatBytes(running.doneBytes)
    return if (running.totalBytes > 0) {
        "$done de ${Sources.formatBytes(running.totalBytes)}"
    } else {
        "$done procesados"
    }
}

@Composable
private fun OutcomeCard(
    state: CryptoViewModel.UiState,
    onSave: () -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val colors = CifraTheme.colors
    SectionCard(
        title = when (state.outcome) {
            is CryptoViewModel.Outcome.Blob -> "Sobre cifrado"
            is CryptoViewModel.Outcome.Plain -> "Texto descifrado"
            is CryptoViewModel.Outcome.Saved -> "Guardado"
            CryptoViewModel.Outcome.None -> "Resultado"
        }
    ) {
        when (val outcome = state.outcome) {
            is CryptoViewModel.Outcome.Blob -> {
                CodeBlock(outcome.value)
                Spacer(Modifier.height(Space.m))
                ResultActions(
                    onCopy = { copyAndExpire(context, outcome.value) },
                    onSave = onSave
                )
            }

            is CryptoViewModel.Outcome.Plain -> {
                CodeBlock(outcome.value, maxHeight = 400.dp)
                Spacer(Modifier.height(Space.m))
                ResultActions(
                    onCopy = { copyAndExpire(context, outcome.value) },
                    onSave = onSave
                )
            }

            is CryptoViewModel.Outcome.Saved -> {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Description,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(Modifier.width(Space.m))
                    Column(Modifier.weight(1f)) {
                        Text(
                            text = outcome.name,
                            style = MaterialTheme.typography.bodyLarge,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = Sources.formatBytes(outcome.bytes),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                if (!outcome.verified) {
                    Spacer(Modifier.height(Space.s))
                    Text(
                        text = "El contenido no pasó la comprobación de autenticación. No es fiable.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = colors.warning
                    )
                }
            }

            CryptoViewModel.Outcome.None -> Unit
        }
        Spacer(Modifier.height(Space.s))
        TextButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
            Text(text = "Limpiar resultado", style = MaterialTheme.typography.labelLarge)
        }
    }
}

@Composable
private fun CodeBlock(value: String, maxHeight: androidx.compose.ui.unit.Dp = 320.dp) {
    val colors = CifraTheme.colors
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(max = maxHeight)
            .clip(RoundedCornerShape(12.dp))
            .background(colors.codeBackground)
            .padding(Space.m)
    ) {
        Text(
            text = value,
            fontFamily = FontFamily.Monospace,
            fontSize = 13.sp,
            color = colors.codeForeground,
            modifier = Modifier
                .verticalScroll(rememberScrollState())
                .testTag(Tags.RESULT)
        )
    }
}

@Composable
private fun ResultActions(onCopy: () -> Unit, onSave: () -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(Space.s)) {
        Button(onClick = onCopy) {
            Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(Space.s))
            Text(text = "Copiar")
        }
        OutlinedButton(onClick = onSave) {
            Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(Space.s))
            Text(text = "Guardar")
        }
    }
}

@Composable
private fun FooterNote() {
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
        Text(
            text = "El texto nunca sale del dispositivo. No hay servidores, ni cuentas, ni copias.",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(Space.xs))
        Text(
            text = "Interoperable con Encrypt-C++: mismo sobre y mismo AAD.",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

private fun suggestedName(state: CryptoViewModel.UiState): String = Plan.outputName(
    inputName = (state.input as? CryptoViewModel.Content.File)?.name,
    encrypting = state.mode == CryptoViewModel.Mode.ENCRYPT
)

/**
 * Lee texto del portapapeles, o `null` si no hay nada legible.
 *
 * Desde Android 10 el portapapeles solo se puede leer con la app enfocada, que es
 * justo el caso de un botón: por eso se lee al pulsar y no al abrir la pantalla.
 * [ClipboardManager.hasPrimaryClip] y `primaryClip` se consultan dentro de
 * `runCatching` porque hay proveedores que devuelven datos raros y un crash por
 * leer un `ClipData` ajeno sería absurdo.
 */
private fun readClipboard(context: Context): String? = runCatching {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    if (clipboard.hasPrimaryClip()) {
        clipboard.primaryClip?.getItemAt(0)?.text?.toString()
    } else {
        null
    }
}.getOrNull()

/**
 * Copia al portapapeles y lo borra pasado un rato.
 *
 * El portapapeles es de las pocas partes del sistema donde un texto plano
 * sobrevive a cerrar la app, así que se marca como sensible y se retira solo.
 * Solo se borra si sigue siendo el mismo contenido: otro copiado posterior no
 * debe desaparecer por error.
 *
 * El borrado se agenda con un `Handler` y no con una corrutina de la
 * composición a propósito: si el resultado se limpia antes de que pase el plazo,
 * la tarjeta sale de la composición, su `CoroutineScope` se cancela y el texto
 * se quedaría pegado para siempre.
 */
private fun copyAndExpire(
    context: Context,
    value: String,
    seconds: Long = 45
) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val clip = ClipData.newPlainText("Cifra", value)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        clip.description.extras = PersistableBundle().apply {
            putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
    }
    clipboard.setPrimaryClip(clip)
    Toast.makeText(context, "Copiado · se borrará en $seconds s", Toast.LENGTH_SHORT).show()

    Handler(Looper.getMainLooper()).postDelayed({
        val current = runCatching { clipboard.primaryClip?.getItemAt(0)?.text?.toString() }.getOrNull()
        if (current != value) return@postDelayed
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            clipboard.clearPrimaryClip()
        } else {
            clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
        }
    }, seconds * 1000)
}
