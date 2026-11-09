package com.airdrop.p2p

import android.Manifest
import android.app.Activity
import android.app.DownloadManager
import android.bluetooth.BluetoothAdapter
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.StatFs
import android.provider.Settings
import android.webkit.MimeTypeMap
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.LinearOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import androidx.core.view.WindowCompat
import com.airdrop.p2p.theme.AirDropTheme
import ds.tokens.DsMotion
import ds.tokens.LocalDsColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

data class StagedFileItem(
    val id: String,
    val uri: Uri? = null,
    val textOrUrl: String? = null,
    val name: String,
    val sizeBytes: Long,
    val category: String
)

data class StorageBreakdown(
    val totalBytes: Long,
    val freeBytes: Long,
    val usedBytes: Long
)

private fun middleTruncate(text: String, maxChars: Int = 34): String {
    if (text.length <= maxChars) return text
    val dotIdx = text.lastIndexOf('.')
    if (dotIdx in 2 until text.length - 1 && (text.length - dotIdx) <= 10) {
        val ext = text.substring(dotIdx)
        val stemBudget = (maxChars - ext.length - 1).coerceAtLeast(6)
        val head = (stemBudget * 2 / 3).coerceAtLeast(4)
        val tail = (stemBudget - head).coerceAtLeast(2)
        val stem = text.substring(0, dotIdx)
        return stem.take(head) + "\u2026" + stem.takeLast(tail) + ext
    }
    val keepStart = (maxChars * 3 / 5).coerceAtLeast(6)
    val keepEnd = (maxChars - 1 - keepStart).coerceAtLeast(4)
    return text.take(keepStart) + "\u2026" + text.takeLast(keepEnd)
}

private fun categoryForFileName(name: String, isUrl: Boolean = false): String {
    if (isUrl) return "Link"
    return when (name.substringAfterLast('.', "").lowercase(Locale.US)) {
        "jpg", "jpeg", "png", "webp", "heic", "heif", "gif", "bmp", "svg" -> "Image"
        "mp4", "mkv", "mov", "avi", "webm", "m4v", "ts" -> "Video"
        "mp3", "m4a", "flac", "wav", "aac", "ogg", "opus" -> "Audio"
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "md", "csv", "json" -> "Doc"
        "apk", "aab", "dmg", "pkg", "zip", "7z", "rar", "tar", "gz" -> "Archive"
        else -> "File"
    }
}

private fun Modifier.pressableScale(
    enabled: Boolean = true,
    pressedScale: Float = DsMotion.scalePress,
    onClick: () -> Unit
): Modifier = composed {
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()
    val scale by animateFloatAsState(
        targetValue = if (isPressed && enabled) pressedScale else 1f,
        animationSpec = DsMotion.springEffectsDefault(),
        label = "pressScale"
    )
    this
        .graphicsLayer {
            scaleX = scale
            scaleY = scale
        }
        .clickable(
            interactionSource = interactionSource,
            indication = null,
            enabled = enabled,
            onClick = onClick
        )
}

private fun timeOfDayGreeting(): String {
    val hour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY)
    return when (hour) {
        in 5..11 -> "Good Morning"
        in 12..16 -> "Good Afternoon"
        in 17..21 -> "Good Evening"
        else -> "Ready to Share"
    }
}

private fun readInternalStorage(): StorageBreakdown {
    return try {
        val stat = StatFs(Environment.getDataDirectory().path)
        val total = stat.totalBytes.coerceAtLeast(1L)
        val free = stat.availableBytes.coerceIn(0L, total)
        StorageBreakdown(
            totalBytes = total,
            freeBytes = free,
            usedBytes = (total - free).coerceAtLeast(0L)
        )
    } catch (_: Throwable) {
        StorageBreakdown(totalBytes = 128L * 1024 * 1024 * 1024, freeBytes = 64L * 1024 * 1024 * 1024, usedBytes = 64L * 1024 * 1024 * 1024)
    }
}

class MainActivity : ComponentActivity() {

    private lateinit var node: AirDropNode
    private val sharedUris = MutableStateFlow<List<Uri>>(emptyList())
    private val sharedText = MutableStateFlow<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        node = AirDropService.getNode(applicationContext)
        runCatching {
            startForegroundService(Intent(this, AirDropService::class.java))
        }
        captureShareIntent(intent)

        enableEdgeToEdge()
        setContent {
            val themeMode by node.themeModeFlow.collectAsState()
            val systemDark = isSystemInDarkTheme()
            val isDark = when (themeMode) {
                "light" -> false
                "dark" -> true
                else -> systemDark
            }
            val view = LocalView.current
            if (!view.isInEditMode) {
                SideEffect {
                    val window = (view.context as? Activity)?.window ?: return@SideEffect
                    val controller = WindowCompat.getInsetsController(window, view)
                    controller.isAppearanceLightStatusBars = !isDark
                    controller.isAppearanceLightNavigationBars = !isDark
                }
            }

            AirDropTheme(darkTheme = isDark) {
                val colors = LocalDsColors.current
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = colors.surfaceBase
                ) {
                    AirDropScreen(
                        node = node,
                        isDark = isDark,
                        themeMode = themeMode,
                        pendingSharedUris = sharedUris.collectAsState().value,
                        pendingSharedText = sharedText.collectAsState().value,
                        onClearPendingShare = {
                            sharedUris.value = emptyList()
                            sharedText.value = null
                        },
                        onOpenUrl = { url ->
                            runCatching {
                                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                            }
                        },
                        onOpenDownloads = {
                            runCatching {
                                startActivity(Intent(DownloadManager.ACTION_VIEW_DOWNLOADS))
                            }
                        }
                    )
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (::node.isInitialized) {
            node.refreshSystemReadiness()
        }
    }

    override fun onDestroy() {
        if (isFinishing && ::node.isInitialized && !node.isTransferInProgress) {
            runCatching {
                stopService(Intent(this, AirDropService::class.java))
            }
        }
        super.onDestroy()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        captureShareIntent(intent)
    }

    private fun captureShareIntent(intent: Intent?) {
        if (intent == null) return
        when (intent.action) {
            Intent.ACTION_SEND -> {
                val stream = if (Build.VERSION.SDK_INT >= 33) {
                    intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(Intent.EXTRA_STREAM)
                }
                if (stream != null) {
                    sharedUris.value = listOf(stream)
                    return
                }
                val text = intent.getStringExtra(Intent.EXTRA_TEXT)
                if (!text.isNullOrBlank()) {
                    sharedText.value = text.trim()
                }
            }
            Intent.ACTION_SEND_MULTIPLE -> {
                val streams = if (Build.VERSION.SDK_INT >= 33) {
                    intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM)
                }
                if (!streams.isNullOrEmpty()) sharedUris.value = streams
            }
        }
    }
}

private enum class QuickIconKind {
    SEND, RECEIVE, HISTORY, SETTINGS,
    IMAGE, VIDEO, DOC, AUDIO, LINK, FOLDER,
    SUN, MOON, REFRESH, CHECK, CLOSE, PLUS, SEARCH, BLUETOOTH, UPLOAD, DOWNLOAD
}

@Composable
fun AirDropScreen(
    node: AirDropNode,
    isDark: Boolean,
    themeMode: String,
    pendingSharedUris: List<Uri>,
    pendingSharedText: String?,
    onClearPendingShare: () -> Unit,
    onOpenUrl: (String) -> Unit,
    onOpenDownloads: () -> Unit
) {
    val c = LocalDsColors.current
    val context = LocalContext.current
    val running by node.running.collectAsState()
    val endpoints by node.localEndpoints.collectAsState()
    val peers by node.peers.collectAsState()
    val incomingAsk by node.incomingAsk.collectAsState()
    val receivedItems by node.receivedItems.collectAsState()
    val transferProgress by node.transferProgress.collectAsState()
    val p2pStatus by node.p2pStatus.collectAsState()
    val logs by node.logs.collectAsState()
    val deviceName by node.deviceNameFlow.collectAsState()
    val autoAccept by node.autoAcceptFlow.collectAsState()
    val btEnabled by node.bluetoothEnabled.collectAsState()
    val wifiEnabled by node.wifiEnabled.collectAsState()
    val permsGranted by node.permissionsGranted.collectAsState()

    // 4 Separate Tabs: 0 = Send, 1 = Receive, 2 = History, 3 = Settings
    var activeTab by rememberSaveable { mutableIntStateOf(0) }
    var historyFilter by rememberSaveable { mutableIntStateOf(0) }
    var historyQuery by rememberSaveable { mutableStateOf("") }
    var showLogs by rememberSaveable { mutableStateOf(false) }

    val stagedItems = remember { mutableStateListOf<StagedFileItem>() }
    var selectedPeerId by rememberSaveable { mutableStateOf<String?>(null) }

    var showTextModal by remember { mutableStateOf(false) }
    var textSnippetDraft by remember { mutableStateOf("") }
    var showRenameDialog by remember { mutableStateOf(false) }
    var renameText by remember { mutableStateOf(deviceName) }

    var storageInfo by remember { mutableStateOf(readInternalStorage()) }
    LaunchedEffect(receivedItems.size, activeTab) {
        withContext(Dispatchers.IO) {
            storageInfo = readInternalStorage()
        }
    }

    fun stageUris(uris: List<Uri>) {
        if (uris.isEmpty()) return
        var added = 0
        for (uri in uris) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            }
            val key = uri.toString()
            if (stagedItems.none { it.id == key }) {
                val (name, size) = node.inspectUriMeta(uri)
                stagedItems.add(
                    StagedFileItem(
                        id = key,
                        uri = uri,
                        name = name,
                        sizeBytes = size,
                        category = categoryForFileName(name)
                    )
                )
                added++
            }
        }
        activeTab = 0
        if (added > 0) {
            Toast.makeText(context, "${stagedItems.size} file(s) staged — tap Send when ready", Toast.LENGTH_SHORT).show()
        }
    }

    fun stageTextOrUrl(raw: String) {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return
        val isLink = trimmed.startsWith("http://") || trimmed.startsWith("https://")
        val key = "text:$trimmed"
        if (stagedItems.none { it.id == key }) {
            stagedItems.add(
                StagedFileItem(
                    id = key,
                    textOrUrl = trimmed,
                    name = if (isLink) trimmed else "Text note (${trimmed.take(28)})",
                    sizeBytes = trimmed.toByteArray().size.toLong(),
                    category = if (isLink) "Link" else "Doc"
                )
            )
        }
        activeTab = 0
    }

    // Ingest system Share Sheet intents into staging queue (never auto-sends without user confirmation)
    LaunchedEffect(pendingSharedUris, pendingSharedText) {
        if (pendingSharedUris.isNotEmpty()) {
            stageUris(pendingSharedUris)
            onClearPendingShare()
        } else if (!pendingSharedText.isNullOrBlank()) {
            stageTextOrUrl(pendingSharedText)
            onClearPendingShare()
        }
    }

    // Pickers — ALL stage into stagedItems rather than immediately transmitting
    val anyFilePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenMultipleDocuments()
    ) { uris -> stageUris(uris) }

    val imagePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenMultipleDocuments()
    ) { uris -> stageUris(uris) }

    val videoPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenMultipleDocuments()
    ) { uris -> stageUris(uris) }

    val audioPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenMultipleDocuments()
    ) { uris -> stageUris(uris) }

    val docPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenMultipleDocuments()
    ) { uris -> stageUris(uris) }

    val requiredPermissions = remember {
        buildList {
            add(Manifest.permission.BLUETOOTH_ADVERTISE)
            add(Manifest.permission.BLUETOOTH_CONNECT)
            add(Manifest.permission.BLUETOOTH_SCAN)
            add(Manifest.permission.ACCESS_FINE_LOCATION)
            add(Manifest.permission.ACCESS_COARSE_LOCATION)
            if (Build.VERSION.SDK_INT >= 33) {
                add(Manifest.permission.POST_NOTIFICATIONS)
                add(Manifest.permission.NEARBY_WIFI_DEVICES)
            } else {
                add(Manifest.permission.READ_EXTERNAL_STORAGE)
            }
        }.toTypedArray()
    }

    val permLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions()
    ) {
        node.refreshSystemReadiness()
        node.start()
    }

    LaunchedEffect(Unit) {
        permLauncher.launch(requiredPermissions)
    }

    // Trigger sending staged items only when user explicitly taps Send
    fun triggerSendStaged() {
        if (stagedItems.isEmpty() || transferProgress != null) return
        val activePeer = peers.firstOrNull { it.id == selectedPeerId }
            ?: peers.firstOrNull()
            ?: AirDropPeer(
                id = "ble-mac",
                name = "Nearby Mac",
                host = "ble://mac",
                port = 192,
                rssi = -55,
                transport = "BLE + 5GHz P2P"
            )
        val urisToSend = stagedItems.mapNotNull { it.uri }
        val textsToSend = stagedItems.mapNotNull { it.textOrUrl }

        if (urisToSend.isNotEmpty()) {
            node.sendUrisAsync(activePeer, urisToSend) { ok ->
                if (ok) {
                    stagedItems.removeAll { it.uri != null }
                    if (textsToSend.isNotEmpty()) {
                        node.sendTextSnippetAsync(activePeer, textsToSend.joinToString("\n")) { textOk ->
                            if (textOk) stagedItems.clear()
                        }
                    } else {
                        Toast.makeText(context, "Sent ${urisToSend.size} file(s)", Toast.LENGTH_SHORT).show()
                    }
                } else {
                    Toast.makeText(context, "Transfer did not complete — files kept in selection", Toast.LENGTH_LONG).show()
                }
            }
        } else if (textsToSend.isNotEmpty()) {
            val combined = textsToSend.joinToString("\n")
            node.sendTextSnippetAsync(activePeer, combined) { ok ->
                if (ok) {
                    stagedItems.clear()
                    Toast.makeText(context, "Sent shared link / text", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(context, "Transfer did not complete — item kept in selection", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    // Incoming Ask Consent Modal
    incomingAsk?.let { ask ->
        AlertDialog(
            onDismissRequest = { ask.decision.complete(false) },
            containerColor = c.surfaceOverlay,
            titleContentColor = c.textPrimary,
            textContentColor = c.textSecondary,
            shape = RoundedCornerShape(20.dp),
            title = {
                Text(
                    text = "Incoming AirDrop",
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "${ask.senderName} wants to send:",
                        color = c.textSecondary,
                        fontSize = 14.sp
                    )
                    Surface(
                        color = c.surfaceSunken,
                        shape = RoundedCornerShape(12.dp),
                        border = BorderStroke(1.dp, c.borderSubtle),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text(
                                text = ask.summary,
                                color = c.textPrimary,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 13.sp,
                                maxLines = 4,
                                overflow = TextOverflow.Ellipsis
                            )
                            if (ask.totalBytes > 0L) {
                                Text(
                                    text = "Total size: ${AirDropNode.formatBytes(ask.totalBytes)}",
                                    color = c.textAccent,
                                    fontSize = 12.sp,
                                    style = TextStyle(fontFeatureSettings = "tnum")
                                )
                            }
                        }
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = { ask.decision.complete(true) },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = c.bgActionPrimary,
                        contentColor = c.textOnAction
                    ),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Text("Accept", fontWeight = FontWeight.SemiBold)
                }
            },
            dismissButton = {
                OutlinedButton(
                    onClick = { ask.decision.complete(false) },
                    border = BorderStroke(1.dp, c.borderDefault),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Text("Decline", color = c.textPrimary)
                }
            }
        )
    }

    // Add Link / Text Snippet Dialog (stages into selection queue)
    if (showTextModal) {
        AlertDialog(
            onDismissRequest = { showTextModal = false },
            containerColor = c.surfaceOverlay,
            shape = RoundedCornerShape(20.dp),
            title = {
                Text(
                    text = "Stage Link or Note",
                    color = c.textPrimary,
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Add a URL or text note to your send queue",
                            color = c.textSecondary,
                            fontSize = 13.sp,
                            modifier = Modifier.weight(1f)
                        )
                        TextButton(
                            onClick = {
                                val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                                val pasted = cm?.primaryClip?.getItemAt(0)?.coerceToText(context)?.toString().orEmpty()
                                if (pasted.isNotBlank()) textSnippetDraft = pasted
                            }
                        ) {
                            Text("Paste", color = c.textAccent, fontWeight = FontWeight.SemiBold)
                        }
                    }
                    OutlinedTextField(
                        value = textSnippetDraft,
                        onValueChange = { textSnippetDraft = it },
                        placeholder = { Text("https://example.com or note…", color = c.textTertiary) },
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 96.dp, max = 180.dp)
                    )
                }
            },
            confirmButton = {
                Button(
                    enabled = textSnippetDraft.isNotBlank(),
                    onClick = {
                        stageTextOrUrl(textSnippetDraft)
                        textSnippetDraft = ""
                        showTextModal = false
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = c.bgActionPrimary,
                        contentColor = c.textOnAction
                    ),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Text("Add to Selection", fontWeight = FontWeight.SemiBold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showTextModal = false }) {
                    Text("Cancel", color = c.textSecondary)
                }
            }
        )
    }

    // Rename Device Modal
    if (showRenameDialog) {
        AlertDialog(
            onDismissRequest = { showRenameDialog = false },
            containerColor = c.surfaceOverlay,
            shape = RoundedCornerShape(20.dp),
            title = {
                Text("Device Name", color = c.textPrimary, fontWeight = FontWeight.Bold, fontSize = 18.sp)
            },
            text = {
                OutlinedTextField(
                    value = renameText,
                    onValueChange = { renameText = it.take(28) },
                    singleLine = true,
                    label = { Text("Visible to nearby Macs") },
                    modifier = Modifier.fillMaxWidth()
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        node.deviceName = renameText
                        showRenameDialog = false
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = c.bgActionPrimary,
                        contentColor = c.textOnAction
                    ),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Text("Save", fontWeight = FontWeight.SemiBold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showRenameDialog = false }) {
                    Text("Cancel", color = c.textSecondary)
                }
            }
        )
    }

    Scaffold(
        containerColor = c.surfaceBase,
        topBar = {
            QuickShareTopBar(
                deviceName = deviceName,
                running = running,
                isDark = isDark,
                stagedCount = stagedItems.size,
                onToggleTheme = {
                    node.themeMode = if (isDark) "light" else "dark"
                },
                onRenameClick = {
                    renameText = deviceName
                    showRenameDialog = true
                },
                onRescanClick = {
                    node.refreshP2p()
                    Toast.makeText(context, "Scanning nearby BLE + 5GHz P2P…", Toast.LENGTH_SHORT).show()
                }
            )
        },
        bottomBar = {
            QuickShareBottomBar(
                activeTab = activeTab,
                stagedCount = stagedItems.size,
                peerCount = peers.size,
                historyCount = receivedItems.size,
                onSelectTab = { activeTab = it }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            if (!btEnabled || !wifiEnabled || !permsGranted) {
                RadioReadinessCard(
                    btEnabled = btEnabled,
                    wifiEnabled = wifiEnabled,
                    permsGranted = permsGranted,
                    onEnableBluetooth = {
                        runCatching { context.startActivity(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)) }
                    },
                    onEnableWifi = {
                        runCatching { context.startActivity(Intent(Settings.Panel.ACTION_WIFI)) }
                    },
                    onGrantPerms = { permLauncher.launch(requiredPermissions) }
                )
            }

            // Live Connecting / Connected Peer Bridge Card (visible during both handshake AND transfer)
            AnimatedVisibility(visible = transferProgress != null) {
                transferProgress?.let { prog ->
                    LiveConnectionBridgeCard(
                        localDeviceName = deviceName,
                        progress = prog,
                        onCancel = { node.cancelActiveTransfer() }
                    )
                }
            }

            when (activeTab) {
                0 -> SendHomeTab(
                    stagedItems = stagedItems,
                    peers = peers,
                    selectedPeerId = selectedPeerId,
                    transferActive = transferProgress != null,
                    storage = storageInfo,
                    recentSent = receivedItems.filter { it.isOutgoing }.take(3),
                    onSelectPeer = { selectedPeerId = it },
                    onRemoveStaged = { item -> stagedItems.remove(item) },
                    onClearStaged = { stagedItems.clear() },
                    onSendStaged = { triggerSendStaged() },
                    onPickImages = { imagePicker.launch(arrayOf("image/*")) },
                    onPickVideos = { videoPicker.launch(arrayOf("video/*")) },
                    onPickDocs = {
                        docPicker.launch(
                            arrayOf(
                                "application/pdf",
                                "text/*",
                                "application/msword",
                                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                                "application/vnd.ms-excel",
                                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                "application/vnd.ms-powerpoint",
                                "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                            )
                        )
                    },
                    onPickAudio = { audioPicker.launch(arrayOf("audio/*")) },
                    onStageLinkOrText = { showTextModal = true },
                    onPickAnyFiles = { anyFilePicker.launch(arrayOf("*/*")) },
                    onSwitchToReceive = { activeTab = 1 },
                    onSwitchToHistory = {
                        historyFilter = 2
                        activeTab = 2
                    },
                    onRescan = { node.refreshP2p() }
                )
                1 -> ReceiveRadarTab(
                    running = running,
                    deviceName = deviceName,
                    autoAccept = autoAccept,
                    peers = peers,
                    p2pStatus = p2pStatus,
                    recentReceived = receivedItems.filter { !it.isOutgoing }.take(4),
                    onToggleAutoAccept = { node.autoAccept = it },
                    onRescan = { node.refreshP2p() },
                    onStartSendToPeer = { peer ->
                        selectedPeerId = peer.id
                        activeTab = 0
                        if (stagedItems.isEmpty()) {
                            anyFilePicker.launch(arrayOf("*/*"))
                        }
                    },
                    onOpenHistoryItem = { item ->
                        if (item.isUrl) onOpenUrl(item.pathOrUrl)
                        else openFileWithProvider(context, item.pathOrUrl, onOpenDownloads)
                    },
                    onViewAllReceived = {
                        historyFilter = 1
                        activeTab = 2
                    }
                )
                2 -> TransfersHistoryScreen(
                    items = receivedItems,
                    filter = historyFilter,
                    query = historyQuery,
                    onQueryChange = { historyQuery = it },
                    onFilterChange = { historyFilter = it },
                    onOpenItem = { item ->
                        if (item.isUrl) onOpenUrl(item.pathOrUrl)
                        else openFileWithProvider(context, item.pathOrUrl, onOpenDownloads)
                    },
                    onShareItem = { item -> shareFileOrUrl(context, item) },
                    onCopyText = { txt ->
                        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                        cm?.setPrimaryClip(ClipData.newPlainText("AirDrop", txt))
                        Toast.makeText(context, "Copied to clipboard", Toast.LENGTH_SHORT).show()
                    },
                    onClearAll = { node.clearReceivedItems() }
                )
                else -> SettingsScreenTab(
                    running = running,
                    deviceName = deviceName,
                    themeMode = themeMode,
                    autoAccept = autoAccept,
                    p2pStatus = p2pStatus,
                    endpoints = endpoints,
                    logs = logs,
                    showLogs = showLogs,
                    onSelectThemeMode = { node.themeMode = it },
                    onToggleRunning = { enabled -> if (enabled) node.start() else node.stop() },
                    onSelectAutoAccept = { node.autoAccept = it },
                    onRenameDevice = {
                        renameText = deviceName
                        showRenameDialog = true
                    },
                    onOpenDownloads = onOpenDownloads,
                    onRescanP2p = {
                        node.refreshP2p()
                        Toast.makeText(context, "Refreshed BLE + 5GHz P2P radio", Toast.LENGTH_SHORT).show()
                    },
                    onToggleLogs = { showLogs = !showLogs },
                    onClearLogs = { node.clearLogs() }
                )
            }
        }
    }
}

// ============================================================================
// Top Bar — Greeting + Device Chip + Day/Dark Quick Switch + Rescan
// ============================================================================
@Composable
private fun QuickShareTopBar(
    deviceName: String,
    running: Boolean,
    isDark: Boolean,
    stagedCount: Int,
    onToggleTheme: () -> Unit,
    onRenameClick: () -> Unit,
    onRescanClick: () -> Unit
) {
    val c = LocalDsColors.current
    Surface(
        color = c.surfaceBase,
        modifier = Modifier
            .fillMaxWidth()
            .statusBarsPadding()
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 18.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = timeOfDayGreeting(),
                            color = c.textPrimary,
                            fontSize = 21.sp,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        if (stagedCount > 0) {
                            Surface(
                                color = c.bgAccentSubtle,
                                shape = CircleShape
                            ) {
                                Text(
                                    text = "$stagedCount queued",
                                    color = c.textAccent,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    style = TextStyle(fontFeatureSettings = "tnum"),
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                                )
                            }
                        }
                    }
                    Spacer(modifier = Modifier.height(2.dp))
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        modifier = Modifier.clickable(onClick = onRenameClick)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(7.dp)
                                .clip(CircleShape)
                                .background(if (running) c.bgSuccessBold else c.textTertiary)
                        )
                        Text(
                            text = "$deviceName · 5GHz P2P",
                            color = c.textSecondary,
                            fontSize = 12.sp,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }

                // 1-Tap Day / Dark Theme Button
                Surface(
                    color = c.surfaceRaised,
                    shape = CircleShape,
                    border = BorderStroke(1.dp, c.borderSubtle),
                    modifier = Modifier
                        .size(40.dp)
                        .pressableScale(onClick = onToggleTheme)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        QuickVectorIcon(
                            kind = if (isDark) QuickIconKind.SUN else QuickIconKind.MOON,
                            tint = c.iconDefault,
                            size = 18.dp
                        )
                    }
                }

                // Rescan Radio Button
                Surface(
                    color = c.surfaceRaised,
                    shape = CircleShape,
                    border = BorderStroke(1.dp, c.borderSubtle),
                    modifier = Modifier
                        .size(40.dp)
                        .pressableScale(onClick = onRescanClick)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        QuickVectorIcon(
                            kind = QuickIconKind.REFRESH,
                            tint = c.iconAccent,
                            size = 18.dp
                        )
                    }
                }
            }
            HorizontalDivider(color = c.borderSeparator, thickness = 1.dp)
        }
    }
}

// ============================================================================
// Connected / Connecting Live Bridge Card (Mockup 2 Left: Sender <-> Receiver + Items | Size | Speed)
// ============================================================================
@Composable
private fun LiveConnectionBridgeCard(
    localDeviceName: String,
    progress: TransferProgress,
    onCancel: () -> Unit
) {
    val c = LocalDsColors.current
    val senderName = if (progress.isSending) localDeviceName else progress.peerName.ifEmpty { "Nearby Peer" }
    val receiverName = if (progress.isSending) progress.peerName.ifEmpty { "Nearby Peer" } else localDeviceName
    val animatedFraction by animateFloatAsState(
        targetValue = (progress.percent / 100f).coerceIn(0f, 1f),
        animationSpec = tween(250, easing = LinearOutSlowInEasing),
        label = "transferPct"
    )
    val pulseTransition = rememberInfiniteTransition(label = "bridgePulse")
    val dashPhase by pulseTransition.animateFloat(
        initialValue = 0f,
        targetValue = 36f,
        animationSpec = infiniteRepeatable(
            animation = tween(900, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "dashPhase"
    )

    Surface(
        color = c.surfaceRaised,
        shape = RoundedCornerShape(20.dp),
        border = BorderStroke(1.dp, c.borderAccent.copy(alpha = 0.45f)),
        shadowElevation = 4.dp,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Header: Connecting… / Connected + Cancel X
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Box(
                        modifier = Modifier
                            .size(9.dp)
                            .clip(CircleShape)
                            .background(if (progress.isConnecting) c.bgActionPrimary else c.bgSuccessBold)
                    )
                    Text(
                        text = if (progress.isConnecting) "Connecting\u2026" else "Connected",
                        color = c.textPrimary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp,
                        maxLines = 1
                    )
                }
                Surface(
                    color = c.bgNeutralSubtle,
                    shape = CircleShape,
                    modifier = Modifier
                        .size(32.dp)
                        .pressableScale(onClick = onCancel)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        QuickVectorIcon(kind = QuickIconKind.CLOSE, tint = c.textSecondary, size = 14.dp)
                    }
                }
            }

            // Peer Bridge: Sender <-> Dashed Arc + Upload/Download Icon <-> Receiver
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                PeerAvatarNode(
                    title = senderName,
                    badgeColor = c.bgAccentSubtle,
                    textColor = c.textAccent,
                    modifier = Modifier.width(92.dp)
                )

                Box(
                    modifier = Modifier
                        .weight(1f)
                        .height(52.dp),
                    contentAlignment = Alignment.Center
                ) {
                    val arcColor = c.borderAccent
                    Canvas(modifier = Modifier.fillMaxSize()) {
                        val p = Path().apply {
                            moveTo(8f, size.height * 0.65f)
                            quadraticTo(
                                size.width * 0.5f,
                                0f,
                                size.width - 8f,
                                size.height * 0.65f
                            )
                        }
                        drawPath(
                            path = p,
                            color = arcColor,
                            style = Stroke(
                                width = 2.dp.toPx(),
                                cap = StrokeCap.Round,
                                pathEffect = PathEffect.dashPathEffect(floatArrayOf(10f, 8f), -dashPhase)
                            )
                        )
                    }
                    Surface(
                        color = c.bgAccentSubtle,
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, c.borderAccent.copy(alpha = 0.5f)),
                        modifier = Modifier.size(34.dp)
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            QuickVectorIcon(
                                kind = if (progress.isSending) QuickIconKind.UPLOAD else QuickIconKind.DOWNLOAD,
                                tint = c.iconAccent,
                                size = 17.dp
                            )
                        }
                    }
                }

                PeerAvatarNode(
                    title = receiverName,
                    badgeColor = c.bgSuccessSubtle,
                    textColor = c.textSuccess,
                    modifier = Modifier.width(92.dp)
                )
            }

            // Live Phase Subtitle (never blind during handshake!)
            Text(
                text = progress.phase.ifEmpty {
                    if (progress.isConnecting) "Establishing 5GHz P2P link\u2026"
                    else if (progress.isSending) "Sending files"
                    else "Receiving files"
                },
                color = if (progress.isConnecting) c.textAccent else c.textSecondary,
                fontSize = 13.sp,
                fontWeight = FontWeight.Medium,
                textAlign = TextAlign.Center,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.fillMaxWidth()
            )

            // 3-Column Indigo Summary Strip: Items | Size | Speed
            Surface(
                color = c.bgActionPrimary,
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 10.dp, horizontal = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    MetricColumn(
                        label = "Items",
                        value = "${progress.fileCount} ${if (progress.fileCount == 1) "file" else "files"}",
                        textColor = c.textOnAction,
                        modifier = Modifier.weight(0.85f)
                    )
                    Box(
                        modifier = Modifier
                            .width(1.dp)
                            .height(26.dp)
                            .background(c.textOnAction.copy(alpha = 0.25f))
                    )
                    MetricColumn(
                        label = "Size",
                        value = when {
                            progress.isConnecting && progress.totalBytes > 0L -> AirDropNode.formatBytes(progress.totalBytes)
                            progress.isConnecting -> "Preparing\u2026"
                            else -> "${AirDropNode.formatBytes(progress.doneBytes)} / ${AirDropNode.formatBytes(progress.totalBytes)}"
                        },
                        textColor = c.textOnAction,
                        modifier = Modifier.weight(1.4f)
                    )
                    Box(
                        modifier = Modifier
                            .width(1.dp)
                            .height(26.dp)
                            .background(c.textOnAction.copy(alpha = 0.25f))
                    )
                    MetricColumn(
                        label = "Speed",
                        value = if (progress.isConnecting) "Handshake\u2026" else AirDropNode.formatSpeed(progress.speedBytesPerSec),
                        textColor = c.textOnAction,
                        modifier = Modifier.weight(0.95f)
                    )
                }
            }

            // File Details + Progress Bar
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = middleTruncate(progress.label, 32),
                        color = c.textPrimary,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Medium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = if (progress.isConnecting) {
                            "Connecting\u2026"
                        } else if (progress.etaSeconds > 0L) {
                            "${progress.percent}% · ${progress.etaSeconds}s left"
                        } else {
                            "${progress.percent}%"
                        },
                        color = c.textSecondary,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        style = TextStyle(fontFeatureSettings = "tnum")
                    )
                }

                if (progress.isConnecting) {
                    LinearProgressIndicator(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(6.dp)
                            .clip(CircleShape),
                        color = c.bgActionPrimary,
                        trackColor = c.bgAccentSubtle
                    )
                } else {
                    LinearProgressIndicator(
                        progress = { animatedFraction },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(6.dp)
                            .clip(CircleShape),
                        color = c.bgActionPrimary,
                        trackColor = c.bgAccentSubtle
                    )
                }
            }
        }
    }
}

@Composable
private fun PeerAvatarNode(
    title: String,
    badgeColor: Color,
    textColor: Color,
    modifier: Modifier = Modifier
) {
    val c = LocalDsColors.current
    val initial = title.trim().firstOrNull()?.uppercaseChar()?.toString() ?: "D"
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(5.dp)
    ) {
        Surface(
            color = badgeColor,
            shape = CircleShape,
            border = BorderStroke(1.5.dp, textColor.copy(alpha = 0.35f)),
            modifier = Modifier.size(48.dp)
        ) {
            Box(contentAlignment = Alignment.Center) {
                Text(
                    text = initial,
                    color = textColor,
                    fontWeight = FontWeight.Bold,
                    fontSize = 19.sp
                )
            }
        }
        Text(
            text = title,
            color = c.textPrimary,
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            textAlign = TextAlign.Center
        )
    }
}

@Composable
private fun MetricColumn(
    label: String,
    value: String,
    textColor: Color,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier.padding(horizontal = 4.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(2.dp)
    ) {
        Text(
            text = label,
            color = textColor.copy(alpha = 0.8f),
            fontSize = 11.sp,
            fontWeight = FontWeight.Medium,
            maxLines = 1
        )
        Text(
            text = value,
            color = textColor,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            style = TextStyle(fontFeatureSettings = "tnum")
        )
    }
}

// ============================================================================
// TAB 0: SEND — Staged Selection Queue + Categories + Storage Donut + Quick Actions
// ============================================================================
@Composable
private fun SendHomeTab(
    stagedItems: List<StagedFileItem>,
    peers: List<AirDropPeer>,
    selectedPeerId: String?,
    transferActive: Boolean,
    storage: StorageBreakdown,
    recentSent: List<ReceivedItem>,
    onSelectPeer: (String) -> Unit,
    onRemoveStaged: (StagedFileItem) -> Unit,
    onClearStaged: () -> Unit,
    onSendStaged: () -> Unit,
    onPickImages: () -> Unit,
    onPickVideos: () -> Unit,
    onPickDocs: () -> Unit,
    onPickAudio: () -> Unit,
    onStageLinkOrText: () -> Unit,
    onPickAnyFiles: () -> Unit,
    onSwitchToReceive: () -> Unit,
    onSwitchToHistory: () -> Unit,
    onRescan: () -> Unit
) {
    val c = LocalDsColors.current
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // 1. Staged Selected Files Queue (shown whenever files/links are selected — never auto-sends!)
        if (stagedItems.isNotEmpty()) {
            item {
                SelectedFilesStagingCard(
                    stagedItems = stagedItems,
                    peers = peers,
                    selectedPeerId = selectedPeerId,
                    transferActive = transferActive,
                    onSelectPeer = onSelectPeer,
                    onAddMore = onPickAnyFiles,
                    onRemoveItem = onRemoveStaged,
                    onClearAll = onClearStaged,
                    onSendClick = onSendStaged,
                    onRescan = onRescan
                )
            }
        }

        // 2. Categories 2x3 Grid (Mockup 2 Center: Images, Videos, Docs, Music, Link, Files)
        item {
            Surface(
                color = c.surfaceRaised,
                shape = RoundedCornerShape(20.dp),
                border = BorderStroke(1.dp, c.borderSubtle),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Categories",
                            color = c.textPrimary,
                            fontWeight = FontWeight.Bold,
                            fontSize = 16.sp
                        )
                        Text(
                            text = "Select files to review before sending",
                            color = c.textTertiary,
                            fontSize = 12.sp
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        CategoryCircleItem(
                            label = "Images",
                            badgeBg = Color(0xFF0EA5E9),
                            icon = QuickIconKind.IMAGE,
                            onClick = onPickImages,
                            modifier = Modifier.weight(1f)
                        )
                        CategoryCircleItem(
                            label = "Videos",
                            badgeBg = Color(0xFFEC4899),
                            icon = QuickIconKind.VIDEO,
                            onClick = onPickVideos,
                            modifier = Modifier.weight(1f)
                        )
                        CategoryCircleItem(
                            label = "Docs",
                            badgeBg = Color(0xFF16A34A),
                            icon = QuickIconKind.DOC,
                            onClick = onPickDocs,
                            modifier = Modifier.weight(1f)
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        CategoryCircleItem(
                            label = "Music",
                            badgeBg = Color(0xFFF59E0B),
                            icon = QuickIconKind.AUDIO,
                            onClick = onPickAudio,
                            modifier = Modifier.weight(1f)
                        )
                        CategoryCircleItem(
                            label = "Link / Note",
                            badgeBg = Color(0xFFEF4444),
                            icon = QuickIconKind.LINK,
                            onClick = onStageLinkOrText,
                            modifier = Modifier.weight(1f)
                        )
                        CategoryCircleItem(
                            label = "Files",
                            badgeBg = Color(0xFF6366F1),
                            icon = QuickIconKind.FOLDER,
                            onClick = onPickAnyFiles,
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }
        }

        // 3. Storage Ring Card (Mockup 1 & Mockup 2 Storage Card)
        item {
            StorageOverviewCard(storage = storage)
        }

        // 4. Primary Send / Receive Action Buttons (Mockup 2 Bottom Action Pair)
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Surface(
                    color = c.bgActionPrimary,
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier
                        .weight(1f)
                        .height(54.dp)
                        .pressableScale(
                            onClick = {
                                if (stagedItems.isEmpty()) onPickAnyFiles() else onSendStaged()
                            }
                        )
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(horizontal = 14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {
                        QuickVectorIcon(kind = QuickIconKind.SEND, tint = c.textOnAction, size = 18.dp)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = if (stagedItems.isEmpty()) "Select Files" else "Send (${stagedItems.size})",
                            color = c.textOnAction,
                            fontWeight = FontWeight.Bold,
                            fontSize = 15.sp,
                            maxLines = 1
                        )
                    }
                }

                Surface(
                    color = c.bgSuccessBold,
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier
                        .weight(1f)
                        .height(54.dp)
                        .pressableScale(onClick = onSwitchToReceive)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(horizontal = 14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {
                        QuickVectorIcon(kind = QuickIconKind.RECEIVE, tint = c.textOnSuccess, size = 18.dp)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Receive",
                            color = c.textOnSuccess,
                            fontWeight = FontWeight.Bold,
                            fontSize = 15.sp,
                            maxLines = 1
                        )
                    }
                }
            }
        }

        // 5. Recent Sent Preview
        if (recentSent.isNotEmpty()) {
            item {
                Surface(
                    color = c.surfaceRaised,
                    shape = RoundedCornerShape(20.dp),
                    border = BorderStroke(1.dp, c.borderSubtle),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "Recently Sent",
                                color = c.textPrimary,
                                fontWeight = FontWeight.Bold,
                                fontSize = 15.sp
                            )
                            Text(
                                text = "View all",
                                color = c.textAccent,
                                fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold,
                                modifier = Modifier.clickable(onClick = onSwitchToHistory)
                            )
                        }
                        recentSent.forEach { sent ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Surface(
                                    color = c.bgAccentSubtle,
                                    shape = RoundedCornerShape(10.dp),
                                    modifier = Modifier.size(36.dp)
                                ) {
                                    Box(contentAlignment = Alignment.Center) {
                                        QuickVectorIcon(kind = QuickIconKind.UPLOAD, tint = c.iconAccent, size = 16.dp)
                                    }
                                }
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = middleTruncate(sent.title, 30),
                                        color = c.textPrimary,
                                        fontSize = 13.sp,
                                        fontWeight = FontWeight.Medium,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Text(
                                        text = "To ${sent.peerName} · ${AirDropNode.formatBytes(sent.sizeBytes)}",
                                        color = c.textSecondary,
                                        fontSize = 11.sp,
                                        style = TextStyle(fontFeatureSettings = "tnum"),
                                        maxLines = 1
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SelectedFilesStagingCard(
    stagedItems: List<StagedFileItem>,
    peers: List<AirDropPeer>,
    selectedPeerId: String?,
    transferActive: Boolean,
    onSelectPeer: (String) -> Unit,
    onAddMore: () -> Unit,
    onRemoveItem: (StagedFileItem) -> Unit,
    onClearAll: () -> Unit,
    onSendClick: () -> Unit,
    onRescan: () -> Unit
) {
    val c = LocalDsColors.current
    val totalBytes = stagedItems.sumOf { it.sizeBytes }
    val activePeer = peers.firstOrNull { it.id == selectedPeerId } ?: peers.firstOrNull()

    Surface(
        color = c.surfaceRaised,
        shape = RoundedCornerShape(20.dp),
        border = BorderStroke(1.5.dp, c.borderAccent),
        shadowElevation = 2.dp,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Header: N Files Selected + Add More + Clear
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "${stagedItems.size} ${if (stagedItems.size == 1) "file" else "files"} selected",
                        color = c.textPrimary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp
                    )
                    Text(
                        text = "Total ${AirDropNode.formatBytes(totalBytes)} · Ready to send",
                        color = c.textSecondary,
                        fontSize = 12.sp,
                        style = TextStyle(fontFeatureSettings = "tnum")
                    )
                }

                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Surface(
                        color = c.bgAccentSubtle,
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.pressableScale(onClick = onAddMore)
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 7.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            QuickVectorIcon(kind = QuickIconKind.PLUS, tint = c.textAccent, size = 13.dp)
                            Text("Add", color = c.textAccent, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                        }
                    }
                    Surface(
                        color = c.bgNeutralSubtle,
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.pressableScale(onClick = onClearAll)
                    ) {
                        Text(
                            text = "Clear",
                            color = c.textSecondary,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 7.dp)
                        )
                    }
                }
            }

            // File rows (scrollable up to 220dp when many files are selected)
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 220.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                stagedItems.forEach { item ->
                    Surface(
                        color = c.surfaceSunken,
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 9.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            val badgeTint = when (item.category) {
                                "Image" -> Color(0xFF0EA5E9)
                                "Video" -> Color(0xFFEC4899)
                                "Doc" -> Color(0xFF16A34A)
                                "Audio" -> Color(0xFFF59E0B)
                                "Link" -> Color(0xFFEF4444)
                                else -> Color(0xFF6366F1)
                            }
                            Surface(
                                color = badgeTint.copy(alpha = 0.16f),
                                shape = RoundedCornerShape(9.dp),
                                modifier = Modifier.size(34.dp)
                            ) {
                                Box(contentAlignment = Alignment.Center) {
                                    QuickVectorIcon(
                                        kind = when (item.category) {
                                            "Image" -> QuickIconKind.IMAGE
                                            "Video" -> QuickIconKind.VIDEO
                                            "Doc" -> QuickIconKind.DOC
                                            "Audio" -> QuickIconKind.AUDIO
                                            "Link" -> QuickIconKind.LINK
                                            else -> QuickIconKind.FOLDER
                                        },
                                        tint = badgeTint,
                                        size = 16.dp
                                    )
                                }
                            }

                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = middleTruncate(item.name, 30),
                                    color = c.textPrimary,
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = "${item.category} · ${AirDropNode.formatBytes(item.sizeBytes)}",
                                    color = c.textSecondary,
                                    fontSize = 11.sp,
                                    style = TextStyle(fontFeatureSettings = "tnum")
                                )
                            }

                            Box(
                                modifier = Modifier
                                    .size(32.dp)
                                    .clip(CircleShape)
                                    .clickable { onRemoveItem(item) },
                                contentAlignment = Alignment.Center
                            ) {
                                QuickVectorIcon(kind = QuickIconKind.CLOSE, tint = c.textTertiary, size = 14.dp)
                            }
                        }
                    }
                }
            }

            // Target Peer Selector Strip
            Surface(
                color = c.surfaceSunken,
                shape = RoundedCornerShape(12.dp),
                border = BorderStroke(1.dp, c.borderSubtle),
                modifier = Modifier.fillMaxWidth()
            ) {
                if (activePeer != null) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                if (peers.size > 1) {
                                    val idx = peers.indexOfFirst { it.id == activePeer.id }
                                    val next = peers[(idx + 1) % peers.size]
                                    onSelectPeer(next.id)
                                }
                            }
                            .padding(horizontal = 12.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(9.dp)
                                .clip(CircleShape)
                                .background(c.bgSuccessBold)
                        )
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Destination: ${activePeer.name.substringBefore(" (PSM")}",
                                color = c.textPrimary,
                                fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                text = "${activePeer.transport} · ${activePeer.rssi} dBm",
                                color = c.textSecondary,
                                fontSize = 11.sp,
                                style = TextStyle(fontFeatureSettings = "tnum")
                            )
                        }
                        SignalStrengthBars(rssi = activePeer.rssi)
                    }
                } else {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = "Scanning nearby Mac over BLE…",
                            color = c.textSecondary,
                            fontSize = 12.sp,
                            modifier = Modifier.weight(1f)
                        )
                        Text(
                            text = "Rescan",
                            color = c.textAccent,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.clickable(onClick = onRescan)
                        )
                    }
                }
            }

            // Explicit Primary SEND Button
            Button(
                enabled = !transferActive,
                onClick = onSendClick,
                colors = ButtonDefaults.buttonColors(
                    containerColor = c.bgActionPrimary,
                    contentColor = c.textOnAction,
                    disabledContainerColor = c.bgDisabled,
                    disabledContentColor = c.textDisabled
                ),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp)
            ) {
                QuickVectorIcon(
                    kind = QuickIconKind.SEND,
                    tint = if (!transferActive) c.textOnAction else c.textDisabled,
                    size = 18.dp
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = if (transferActive) {
                        "Transfer in progress\u2026"
                    } else {
                        "Send ${stagedItems.size} ${if (stagedItems.size == 1) "File" else "Files"} (${AirDropNode.formatBytes(totalBytes)})"
                    },
                    fontWeight = FontWeight.Bold,
                    fontSize = 15.sp,
                    style = TextStyle(fontFeatureSettings = "tnum"),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

@Composable
private fun CategoryCircleItem(
    label: String,
    badgeBg: Color,
    icon: QuickIconKind,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val c = LocalDsColors.current
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(14.dp))
            .pressableScale(onClick = onClick)
            .padding(vertical = 6.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(7.dp)
    ) {
        Surface(
            color = badgeBg,
            shape = CircleShape,
            shadowElevation = 2.dp,
            modifier = Modifier.size(52.dp)
        ) {
            Box(contentAlignment = Alignment.Center) {
                QuickVectorIcon(kind = icon, tint = Color.White, size = 22.dp)
            }
        }
        Text(
            text = label,
            color = c.textPrimary,
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun StorageOverviewCard(storage: StorageBreakdown) {
    val c = LocalDsColors.current
    val usedFraction = (storage.usedBytes.toFloat() / storage.totalBytes.coerceAtLeast(1L).toFloat()).coerceIn(0.04f, 0.96f)
    val freeGb = storage.freeBytes.toDouble() / (1024.0 * 1024.0 * 1024.0)
    val totalGb = storage.totalBytes.toDouble() / (1024.0 * 1024.0 * 1024.0)

    Surface(
        color = c.surfaceRaised,
        shape = RoundedCornerShape(20.dp),
        border = BorderStroke(1.dp, c.borderSubtle),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(18.dp)
        ) {
            // Segmented Storage Donut Ring (Mockup 1 Center)
            Box(
                modifier = Modifier.size(104.dp),
                contentAlignment = Alignment.Center
            ) {
                val trackColor = c.surfaceSunken
                Canvas(modifier = Modifier.fillMaxSize()) {
                    val strokeW = 11.dp.toPx()
                    val inset = strokeW / 2f + 2f
                    val arcSize = Size(size.width - inset * 2, size.height - inset * 2)
                    drawArc(
                        color = trackColor,
                        startAngle = 0f,
                        sweepAngle = 360f,
                        useCenter = false,
                        topLeft = Offset(inset, inset),
                        size = arcSize,
                        style = Stroke(width = strokeW, cap = StrokeCap.Round)
                    )
                    val totalSweep = usedFraction * 330f
                    val seg1 = totalSweep * 0.48f
                    val seg2 = totalSweep * 0.30f
                    val seg3 = totalSweep * 0.22f
                    drawArc(
                        color = Color(0xFF5360F5),
                        startAngle = -90f,
                        sweepAngle = seg1,
                        useCenter = false,
                        topLeft = Offset(inset, inset),
                        size = arcSize,
                        style = Stroke(width = strokeW, cap = StrokeCap.Butt)
                    )
                    drawArc(
                        color = Color(0xFFEC4899),
                        startAngle = -90f + seg1,
                        sweepAngle = seg2,
                        useCenter = false,
                        topLeft = Offset(inset, inset),
                        size = arcSize,
                        style = Stroke(width = strokeW, cap = StrokeCap.Butt)
                    )
                    drawArc(
                        color = Color(0xFF16A34A),
                        startAngle = -90f + seg1 + seg2,
                        sweepAngle = seg3,
                        useCenter = false,
                        topLeft = Offset(inset, inset),
                        size = arcSize,
                        style = Stroke(width = strokeW, cap = StrokeCap.Butt)
                    )
                }
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = String.format(Locale.US, "%.1f GB", freeGb),
                        color = c.textPrimary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp,
                        style = TextStyle(fontFeatureSettings = "tnum")
                    )
                    Text(
                        text = "Available",
                        color = c.textTertiary,
                        fontSize = 10.sp
                    )
                }
            }

            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text(
                    text = "Internal Storage",
                    color = c.textPrimary,
                    fontWeight = FontWeight.Bold,
                    fontSize = 15.sp
                )
                Text(
                    text = String.format(Locale.US, "%.1f GB free of %.0f GB", freeGb, totalGb),
                    color = c.textSecondary,
                    fontSize = 12.sp,
                    style = TextStyle(fontFeatureSettings = "tnum")
                )
                Spacer(modifier = Modifier.height(2.dp))
                StorageLegendDot(color = Color(0xFF5360F5), label = "Media & Videos")
                StorageLegendDot(color = Color(0xFFEC4899), label = "Photos & Audio")
                StorageLegendDot(color = Color(0xFF16A34A), label = "Documents & Apps")
            }
        }
    }
}

@Composable
private fun StorageLegendDot(color: Color, label: String) {
    val c = LocalDsColors.current
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(7.dp)
    ) {
        Box(
            modifier = Modifier
                .size(8.dp)
                .clip(RoundedCornerShape(2.dp))
                .background(color)
        )
        Text(text = label, color = c.textSecondary, fontSize = 11.sp, maxLines = 1)
    }
}

// ============================================================================
// TAB 1: RECEIVE — Concentric Pulse Radar ("Looking for Connections…") + Available Devices
// ============================================================================
@Composable
private fun ReceiveRadarTab(
    running: Boolean,
    deviceName: String,
    autoAccept: Boolean,
    peers: List<AirDropPeer>,
    p2pStatus: String,
    recentReceived: List<ReceivedItem>,
    onToggleAutoAccept: (Boolean) -> Unit,
    onRescan: () -> Unit,
    onStartSendToPeer: (AirDropPeer) -> Unit,
    onOpenHistoryItem: (ReceivedItem) -> Unit,
    onViewAllReceived: () -> Unit
) {
    val c = LocalDsColors.current
    val pulseTransition = rememberInfiniteTransition(label = "receiveRadar")
    val radarWave by pulseTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(2400, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "radarWave"
    )

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Scanning Header + Concentric Radar Card (Mockup 1 Right)
        item {
            Surface(
                color = c.surfaceRaised,
                shape = RoundedCornerShape(22.dp),
                border = BorderStroke(1.dp, c.borderSubtle),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = "Nearby Bluetooth & 5GHz Wi-Fi Direct",
                        color = c.textSecondary,
                        fontSize = 13.sp
                    )
                    Text(
                        text = if (!running) {
                            "Receiver Paused"
                        } else if (peers.isEmpty()) {
                            "Looking for Connections\u2026"
                        } else {
                            "${peers.size} ${if (peers.size == 1) "Device" else "Devices"} Nearby"
                        },
                        color = c.textPrimary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 22.sp
                    )

                    // Concentric Periwinkle/Indigo Radar Visual
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(228.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        val accentColor = c.bgActionPrimary
                        Canvas(modifier = Modifier.size(216.dp)) {
                            val center = Offset(size.width / 2f, size.height / 2f)
                            val maxR = size.minDimension / 2f
                            drawCircle(color = accentColor.copy(alpha = 0.08f), radius = maxR, center = center)
                            drawCircle(color = accentColor.copy(alpha = 0.14f), radius = maxR * 0.72f, center = center)
                            drawCircle(color = accentColor.copy(alpha = 0.24f), radius = maxR * 0.46f, center = center)
                            if (running) {
                                val pulseR = maxR * (0.28f + 0.72f * radarWave)
                                drawCircle(
                                    color = accentColor.copy(alpha = (1f - radarWave) * 0.35f),
                                    radius = pulseR,
                                    center = center,
                                    style = Stroke(width = 2.5.dp.toPx())
                                )
                            }
                        }

                        // Central Bluetooth / P2P Badge
                        Surface(
                            color = c.bgActionPrimary,
                            shape = CircleShape,
                            shadowElevation = 6.dp,
                            modifier = Modifier
                                .size(62.dp)
                                .pressableScale(onClick = onRescan)
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                QuickVectorIcon(kind = QuickIconKind.BLUETOOTH, tint = Color.White, size = 26.dp)
                            }
                        }

                        // Orbiting Live Peer Avatar (when discovered)
                        peers.firstOrNull()?.let { firstPeer ->
                            val cleanTitle = firstPeer.name.substringBefore(" (PSM")
                            Surface(
                                color = c.surfaceRaised,
                                shape = CircleShape,
                                border = BorderStroke(2.dp, c.bgSuccessBold),
                                shadowElevation = 4.dp,
                                modifier = Modifier
                                    .align(Alignment.TopEnd)
                                    .padding(end = 26.dp, top = 18.dp)
                                    .pressableScale { onStartSendToPeer(firstPeer) }
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(8.dp)
                                            .clip(CircleShape)
                                            .background(c.bgSuccessBold)
                                    )
                                    Text(
                                        text = middleTruncate(cleanTitle, 16),
                                        color = c.textPrimary,
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.SemiBold
                                    )
                                }
                            }
                        }
                    }

                    // Receive Approval Quick Toggle Strip
                    Surface(
                        color = c.surfaceSunken,
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 14.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "Visible as \"$deviceName\"",
                                    color = c.textPrimary,
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = if (autoAccept) "Auto-accepting incoming files to Downloads/AirDrop" else "Ask before saving incoming files",
                                    color = c.textSecondary,
                                    fontSize = 11.sp,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                            Spacer(modifier = Modifier.width(8.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                FilterChipPill(
                                    label = "Ask First",
                                    selected = !autoAccept,
                                    onClick = { onToggleAutoAccept(false) }
                                )
                                FilterChipPill(
                                    label = "Auto",
                                    selected = autoAccept,
                                    onClick = { onToggleAutoAccept(true) }
                                )
                            }
                        }
                    }
                }
            }
        }

        // Available Devices List (Mockup 1 Right Bottom)
        item {
            Text(
                text = "Available Devices",
                color = c.textPrimary,
                fontWeight = FontWeight.Bold,
                fontSize = 16.sp,
                modifier = Modifier.padding(horizontal = 4.dp)
            )
        }

        if (peers.isEmpty()) {
            item {
                Surface(
                    color = c.surfaceRaised,
                    shape = RoundedCornerShape(16.dp),
                    border = BorderStroke(1.dp, c.borderSubtle),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Waiting for nearby Mac…",
                                color = c.textPrimary,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = p2pStatus,
                                color = c.textSecondary,
                                fontSize = 12.sp,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        OutlinedButton(
                            onClick = onRescan,
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, c.borderDefault)
                        ) {
                            Text("Rescan", color = c.textAccent, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }
        } else {
            items(peers, key = { it.id }) { peer ->
                val cleanName = peer.name.substringBefore(" (PSM")
                Surface(
                    color = c.surfaceRaised,
                    shape = RoundedCornerShape(16.dp),
                    border = BorderStroke(1.dp, c.borderSubtle),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Surface(
                            color = c.bgAccentSubtle,
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.size(46.dp)
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Text(
                                    text = cleanName.firstOrNull()?.uppercase() ?: "M",
                                    color = c.textAccent,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 18.sp
                                )
                            }
                        }
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = cleanName,
                                color = c.textPrimary,
                                fontWeight = FontWeight.Bold,
                                fontSize = 15.sp,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                text = "${peer.transport} · ${peer.rssi} dBm",
                                color = c.textSecondary,
                                fontSize = 12.sp,
                                style = TextStyle(fontFeatureSettings = "tnum")
                            )
                        }
                        Button(
                            onClick = { onStartSendToPeer(peer) },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = c.bgActionPrimary,
                                contentColor = c.textOnAction
                            ),
                            shape = RoundedCornerShape(10.dp),
                            contentPadding = PaddingValues(horizontal = 14.dp, vertical = 8.dp)
                        ) {
                            Text("Send Files", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }
        }

        // Recently Received Section
        if (recentReceived.isNotEmpty()) {
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Recently Received",
                        color = c.textPrimary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp
                    )
                    Text(
                        text = "View all",
                        color = c.textAccent,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.clickable(onClick = onViewAllReceived)
                    )
                }
            }
            items(recentReceived, key = { "${it.timestampMs}-${it.title}" }) { rx ->
                Surface(
                    color = c.surfaceRaised,
                    shape = RoundedCornerShape(14.dp),
                    border = BorderStroke(1.dp, c.borderSubtle),
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onOpenHistoryItem(rx) }
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Surface(
                            color = c.bgSuccessSubtle,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.size(38.dp)
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                QuickVectorIcon(kind = QuickIconKind.DOWNLOAD, tint = c.textSuccess, size = 16.dp)
                            }
                        }
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = middleTruncate(rx.title, 30),
                                color = c.textPrimary,
                                fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                text = "From ${rx.peerName} · ${AirDropNode.formatBytes(rx.sizeBytes)}",
                                color = c.textSecondary,
                                fontSize = 11.sp,
                                style = TextStyle(fontFeatureSettings = "tnum")
                            )
                        }
                        Text(
                            text = "Open",
                            color = c.textAccent,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }
            }
        }
    }
}

// ============================================================================
// TAB 2: HISTORY — Search Bar + Filter Pills + Received / Sent File Cards
// ============================================================================
@Composable
private fun TransfersHistoryScreen(
    items: List<ReceivedItem>,
    filter: Int,
    query: String,
    onQueryChange: (String) -> Unit,
    onFilterChange: (Int) -> Unit,
    onOpenItem: (ReceivedItem) -> Unit,
    onShareItem: (ReceivedItem) -> Unit,
    onCopyText: (String) -> Unit,
    onClearAll: () -> Unit
) {
    val c = LocalDsColors.current
    val filtered = remember(items, filter, query) {
        items.filter { item ->
            val dirMatch = when (filter) {
                1 -> !item.isOutgoing
                2 -> item.isOutgoing
                else -> true
            }
            val q = query.trim()
            val qMatch = q.isEmpty() ||
                item.title.contains(q, ignoreCase = true) ||
                item.peerName.contains(q, ignoreCase = true) ||
                item.pathOrUrl.contains(q, ignoreCase = true)
            dirMatch && qMatch
        }
    }
    val fmt = remember { SimpleDateFormat("MMM d, HH:mm", Locale.US) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Search Bar (Mockup 1 Center: "Search for a File...")
        OutlinedTextField(
            value = query,
            onValueChange = onQueryChange,
            singleLine = true,
            placeholder = { Text("Search for a file or device…", color = c.textTertiary, fontSize = 13.sp) },
            leadingIcon = {
                QuickVectorIcon(kind = QuickIconKind.SEARCH, tint = c.iconSubtle, size = 17.dp)
            },
            trailingIcon = {
                if (query.isNotEmpty()) {
                    Box(
                        modifier = Modifier
                            .size(28.dp)
                            .clip(CircleShape)
                            .clickable { onQueryChange("") },
                        contentAlignment = Alignment.Center
                    ) {
                        QuickVectorIcon(kind = QuickIconKind.CLOSE, tint = c.iconSubtle, size = 13.dp)
                    }
                }
            },
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth()
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChipPill("All (${items.size})", filter == 0) { onFilterChange(0) }
                FilterChipPill("Received", filter == 1) { onFilterChange(1) }
                FilterChipPill("Sent", filter == 2) { onFilterChange(2) }
            }
            if (items.isNotEmpty()) {
                Text(
                    text = "Clear",
                    color = c.textDanger,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.clickable(onClick = onClearAll)
                )
            }
        }

        if (filtered.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = if (items.isEmpty()) "No transfer history yet" else "No matching files found",
                    color = c.textTertiary,
                    fontSize = 14.sp
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                items(filtered, key = { "${it.timestampMs}-${it.title}-${it.isOutgoing}" }) { item ->
                    Surface(
                        color = c.surfaceRaised,
                        shape = RoundedCornerShape(16.dp),
                        border = BorderStroke(1.dp, c.borderSubtle),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Surface(
                                    color = if (item.isOutgoing) c.bgAccentSubtle else c.bgSuccessSubtle,
                                    shape = RoundedCornerShape(10.dp),
                                    modifier = Modifier.size(40.dp)
                                ) {
                                    Box(contentAlignment = Alignment.Center) {
                                        QuickVectorIcon(
                                            kind = if (item.isOutgoing) QuickIconKind.UPLOAD else QuickIconKind.DOWNLOAD,
                                            tint = if (item.isOutgoing) c.textAccent else c.textSuccess,
                                            size = 18.dp
                                        )
                                    }
                                }
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = middleTruncate(item.title, 32),
                                        color = c.textPrimary,
                                        fontWeight = FontWeight.SemiBold,
                                        fontSize = 14.sp,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Text(
                                        text = "${if (item.isOutgoing) "Sent to" else "From"} ${item.peerName} · ${AirDropNode.formatBytes(item.sizeBytes)} · ${fmt.format(Date(item.timestampMs))}",
                                        color = c.textSecondary,
                                        fontSize = 11.sp,
                                        style = TextStyle(fontFeatureSettings = "tnum"),
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }

                            if (!item.isOutgoing || item.isUrl) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.End
                                ) {
                                    if (item.isUrl) {
                                        TextButton(onClick = { onCopyText(item.pathOrUrl) }) {
                                            Text("Copy Link", color = c.textSecondary, fontSize = 12.sp)
                                        }
                                    }
                                    TextButton(onClick = { onShareItem(item) }) {
                                        Text("Share", color = c.textSecondary, fontSize = 12.sp)
                                    }
                                    TextButton(onClick = { onOpenItem(item) }) {
                                        Text("Open", color = c.textAccent, fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// TAB 3: SETTINGS — Theme Selector (Day / Dark / System) + Receive Mode + Radio
// ============================================================================
@Composable
private fun SettingsScreenTab(
    running: Boolean,
    deviceName: String,
    themeMode: String,
    autoAccept: Boolean,
    p2pStatus: String,
    endpoints: List<String>,
    logs: List<String>,
    showLogs: Boolean,
    onSelectThemeMode: (String) -> Unit,
    onToggleRunning: (Boolean) -> Unit,
    onSelectAutoAccept: (Boolean) -> Unit,
    onRenameDevice: () -> Unit,
    onOpenDownloads: () -> Unit,
    onRescanP2p: () -> Unit,
    onToggleLogs: () -> Unit,
    onClearLogs: () -> Unit
) {
    val c = LocalDsColors.current
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // 1. Theme / Appearance Card (Day, Dark, System)
        item {
            Surface(
                color = c.surfaceRaised,
                shape = RoundedCornerShape(20.dp),
                border = BorderStroke(1.dp, c.borderSubtle),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = "Appearance",
                        color = c.textPrimary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        ThemeOptionButton(
                            label = "Day",
                            selected = themeMode == "light",
                            icon = QuickIconKind.SUN,
                            onClick = { onSelectThemeMode("light") },
                            modifier = Modifier.weight(1f)
                        )
                        ThemeOptionButton(
                            label = "Dark",
                            selected = themeMode == "dark",
                            icon = QuickIconKind.MOON,
                            onClick = { onSelectThemeMode("dark") },
                            modifier = Modifier.weight(1f)
                        )
                        ThemeOptionButton(
                            label = "System",
                            selected = themeMode == "system",
                            icon = null,
                            onClick = { onSelectThemeMode("system") },
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }
        }

        // 2. Receive Approval Mode
        item {
            Surface(
                color = c.surfaceRaised,
                shape = RoundedCornerShape(20.dp),
                border = BorderStroke(1.dp, c.borderSubtle),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text(
                        text = "Incoming File Approval",
                        color = c.textPrimary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        FilterChipPill(
                            label = "Ask First",
                            selected = !autoAccept,
                            onClick = { onSelectAutoAccept(false) },
                            modifier = Modifier.weight(1f)
                        )
                        FilterChipPill(
                            label = "Auto-Accept",
                            selected = autoAccept,
                            onClick = { onSelectAutoAccept(true) },
                            modifier = Modifier.weight(1f)
                        )
                    }
                    Text(
                        text = if (autoAccept) {
                            "Incoming files save directly to Downloads/AirDrop without prompting."
                        } else {
                            "Each incoming transfer shows sender name, file list, and size before saving."
                        },
                        color = c.textSecondary,
                        fontSize = 12.sp
                    )
                }
            }
        }

        // 3. Device Identity & Downloads
        item {
            Surface(
                color = c.surfaceRaised,
                shape = RoundedCornerShape(20.dp),
                border = BorderStroke(1.dp, c.borderSubtle),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Device Name", color = c.textSecondary, fontSize = 12.sp)
                            Text(
                                text = deviceName,
                                color = c.textPrimary,
                                fontWeight = FontWeight.Bold,
                                fontSize = 15.sp,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        OutlinedButton(
                            onClick = onRenameDevice,
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, c.borderDefault)
                        ) {
                            Text("Rename", color = c.textPrimary, fontSize = 12.sp)
                        }
                    }

                    HorizontalDivider(color = c.borderSeparator)

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Save Location", color = c.textSecondary, fontSize = 12.sp)
                            Text("Downloads/AirDrop", color = c.textPrimary, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                        }
                        OutlinedButton(
                            onClick = onOpenDownloads,
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, c.borderDefault)
                        ) {
                            Text("Open Folder", color = c.textAccent, fontSize = 12.sp)
                        }
                    }
                }
            }
        }

        // 4. P2P Service & Diagnostics
        item {
            Surface(
                color = c.surfaceRaised,
                shape = RoundedCornerShape(20.dp),
                border = BorderStroke(1.dp, c.borderSubtle),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Background P2P Service",
                                color = c.textPrimary,
                                fontWeight = FontWeight.Bold,
                                fontSize = 15.sp
                            )
                            Text(
                                text = p2pStatus,
                                color = c.textSecondary,
                                fontSize = 12.sp,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        Switch(
                            checked = running,
                            onCheckedChange = onToggleRunning,
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = Color.White,
                                checkedTrackColor = c.bgActionPrimary
                            )
                        )
                    }

                    if (endpoints.isNotEmpty()) {
                        endpoints.forEach { ep ->
                            Text(
                                text = "• $ep",
                                color = c.textTertiary,
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        OutlinedButton(
                            onClick = onRescanP2p,
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, c.borderDefault),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Refresh Radio", color = c.textPrimary, fontSize = 12.sp)
                        }
                        OutlinedButton(
                            onClick = onToggleLogs,
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, c.borderDefault),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(if (showLogs) "Hide Logs" else "Show Logs", color = c.textSecondary, fontSize = 12.sp)
                        }
                    }

                    if (showLogs) {
                        Surface(
                            color = c.surfaceSunken,
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(
                                modifier = Modifier.padding(12.dp),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text("Activity Log", color = c.textSecondary, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                    Text(
                                        text = "Clear",
                                        color = c.textAccent,
                                        fontSize = 11.sp,
                                        modifier = Modifier.clickable(onClick = onClearLogs)
                                    )
                                }
                                if (logs.isEmpty()) {
                                    Text("No events logged yet.", color = c.textTertiary, fontSize = 11.sp)
                                } else {
                                    logs.takeLast(20).forEach { line ->
                                        Text(
                                            text = line,
                                            color = c.textSecondary,
                                            fontSize = 10.sp,
                                            fontFamily = FontFamily.Monospace
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ThemeOptionButton(
    label: String,
    selected: Boolean,
    icon: QuickIconKind?,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val c = LocalDsColors.current
    Surface(
        color = if (selected) c.bgActionPrimary else c.surfaceSunken,
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(1.dp, if (selected) c.bgActionPrimary else c.borderSubtle),
        modifier = modifier
            .height(42.dp)
            .pressableScale(onClick = onClick)
    ) {
        Row(
            modifier = Modifier.fillMaxSize(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center
        ) {
            if (icon != null) {
                QuickVectorIcon(
                    kind = icon,
                    tint = if (selected) c.textOnAction else c.textSecondary,
                    size = 15.dp
                )
                Spacer(modifier = Modifier.width(6.dp))
            }
            Text(
                text = label,
                color = if (selected) c.textOnAction else c.textPrimary,
                fontWeight = FontWeight.SemiBold,
                fontSize = 13.sp
            )
        }
    }
}

@Composable
private fun FilterChipPill(
    label: String,
    selected: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    val c = LocalDsColors.current
    Surface(
        color = if (selected) c.bgActionPrimary else c.surfaceRaised,
        shape = RoundedCornerShape(10.dp),
        border = BorderStroke(1.dp, if (selected) c.bgActionPrimary else c.borderSubtle),
        modifier = modifier.pressableScale(onClick = onClick)
    ) {
        Box(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = label,
                color = if (selected) c.textOnAction else c.textSecondary,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1
            )
        }
    }
}

@Composable
private fun RadioReadinessCard(
    btEnabled: Boolean,
    wifiEnabled: Boolean,
    permsGranted: Boolean,
    onEnableBluetooth: () -> Unit,
    onEnableWifi: () -> Unit,
    onGrantPerms: () -> Unit
) {
    val c = LocalDsColors.current
    Surface(
        color = c.bgWarningSubtle,
        shape = RoundedCornerShape(14.dp),
        border = BorderStroke(1.dp, c.borderWarning),
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = when {
                    !permsGranted -> "Bluetooth & Nearby Wi-Fi permissions required"
                    !btEnabled -> "Bluetooth is off"
                    else -> "Wi-Fi is off (needed for 5GHz speed)"
                },
                color = c.textWarning,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.weight(1f)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = when {
                    !permsGranted -> "Grant"
                    !btEnabled -> "Turn On"
                    else -> "Enable"
                },
                color = c.textAccent,
                fontWeight = FontWeight.Bold,
                fontSize = 12.sp,
                modifier = Modifier.clickable {
                    when {
                        !permsGranted -> onGrantPerms()
                        !btEnabled -> onEnableBluetooth()
                        else -> onEnableWifi()
                    }
                }
            )
        }
    }
}

@Composable
private fun SignalStrengthBars(rssi: Int) {
    val c = LocalDsColors.current
    val activeBars = when {
        rssi >= -58 -> 4
        rssi >= -68 -> 3
        rssi >= -78 -> 2
        else -> 1
    }
    Row(
        verticalAlignment = Alignment.Bottom,
        horizontalArrangement = Arrangement.spacedBy(2.dp),
        modifier = Modifier.height(16.dp)
    ) {
        for (i in 1..4) {
            Box(
                modifier = Modifier
                    .width(3.dp)
                    .height((4 * i).dp)
                    .clip(RoundedCornerShape(1.5.dp))
                    .background(if (i <= activeBars) c.bgSuccessBold else c.borderDefault)
            )
        }
    }
}

// ============================================================================
// Bottom Navigation Bar — 4 Separate Tabs: Send, Receive, History, Settings
// ============================================================================
@Composable
private fun QuickShareBottomBar(
    activeTab: Int,
    stagedCount: Int,
    peerCount: Int,
    historyCount: Int,
    onSelectTab: (Int) -> Unit
) {
    val c = LocalDsColors.current
    Surface(
        color = c.surfaceNav,
        modifier = Modifier
            .fillMaxWidth()
            .navigationBarsPadding()
    ) {
        Column {
            HorizontalDivider(color = c.borderSeparator, thickness = 1.dp)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 8.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.SpaceAround,
                verticalAlignment = Alignment.CenterVertically
            ) {
                BottomNavTabItem(
                    label = "Send",
                    icon = QuickIconKind.SEND,
                    badge = if (stagedCount > 0) stagedCount.toString() else null,
                    selected = activeTab == 0,
                    onClick = { onSelectTab(0) },
                    modifier = Modifier.weight(1f)
                )
                BottomNavTabItem(
                    label = "Receive",
                    icon = QuickIconKind.RECEIVE,
                    badge = if (peerCount > 0) peerCount.toString() else null,
                    selected = activeTab == 1,
                    onClick = { onSelectTab(1) },
                    modifier = Modifier.weight(1f)
                )
                BottomNavTabItem(
                    label = "History",
                    icon = QuickIconKind.HISTORY,
                    badge = if (historyCount > 0) historyCount.coerceAtMost(99).toString() else null,
                    selected = activeTab == 2,
                    onClick = { onSelectTab(2) },
                    modifier = Modifier.weight(1f)
                )
                BottomNavTabItem(
                    label = "Settings",
                    icon = QuickIconKind.SETTINGS,
                    badge = null,
                    selected = activeTab == 3,
                    onClick = { onSelectTab(3) },
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }
}

@Composable
private fun BottomNavTabItem(
    label: String,
    icon: QuickIconKind,
    badge: String?,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val c = LocalDsColors.current
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .pressableScale(onClick = onClick)
            .padding(vertical = 5.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(3.dp)
    ) {
        Box {
            Surface(
                color = if (selected) c.bgAccentSubtle else Color.Transparent,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.size(width = 48.dp, height = 28.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    QuickVectorIcon(
                        kind = icon,
                        tint = if (selected) c.iconAccent else c.iconSubtle,
                        size = 18.dp
                    )
                }
            }
            if (badge != null) {
                Surface(
                    color = c.bgActionPrimary,
                    shape = CircleShape,
                    modifier = Modifier.align(Alignment.TopEnd)
                ) {
                    Text(
                        text = badge,
                        color = Color.White,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold,
                        style = TextStyle(fontFeatureSettings = "tnum"),
                        modifier = Modifier.padding(horizontal = 5.dp, vertical = 1.dp)
                    )
                }
            }
        }
        Text(
            text = label,
            color = if (selected) c.textAccent else c.textSecondary,
            fontSize = 11.sp,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
            maxLines = 1
        )
    }
}

// ============================================================================
// Clean Custom Vector Icons (Zero external icon-pack bloat)
// ============================================================================
@Composable
private fun QuickVectorIcon(
    kind: QuickIconKind,
    tint: Color,
    size: Dp
) {
    Canvas(modifier = Modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val sw = (w * 0.095f).coerceAtLeast(1.6.dp.toPx())
        val stroke = Stroke(width = sw, cap = StrokeCap.Round, join = StrokeJoin.Round)

        when (kind) {
            QuickIconKind.SEND -> {
                val p = Path().apply {
                    moveTo(w * 0.14f, h * 0.48f)
                    lineTo(w * 0.86f, h * 0.16f)
                    lineTo(w * 0.56f, h * 0.86f)
                    lineTo(w * 0.44f, h * 0.56f)
                    close()
                }
                drawPath(p, color = tint, style = stroke)
            }
            QuickIconKind.RECEIVE, QuickIconKind.DOWNLOAD -> {
                drawLine(tint, Offset(w * 0.5f, h * 0.16f), Offset(w * 0.5f, h * 0.66f), strokeWidth = sw, cap = StrokeCap.Round)
                val arrow = Path().apply {
                    moveTo(w * 0.28f, h * 0.46f)
                    lineTo(w * 0.5f, h * 0.68f)
                    lineTo(w * 0.72f, h * 0.46f)
                }
                drawPath(arrow, color = tint, style = stroke)
                drawLine(tint, Offset(w * 0.2f, h * 0.84f), Offset(w * 0.8f, h * 0.84f), strokeWidth = sw, cap = StrokeCap.Round)
            }
            QuickIconKind.UPLOAD -> {
                drawLine(tint, Offset(w * 0.5f, h * 0.68f), Offset(w * 0.5f, h * 0.2f), strokeWidth = sw, cap = StrokeCap.Round)
                val arrow = Path().apply {
                    moveTo(w * 0.28f, h * 0.42f)
                    lineTo(w * 0.5f, h * 0.18f)
                    lineTo(w * 0.72f, h * 0.42f)
                }
                drawPath(arrow, color = tint, style = stroke)
                drawLine(tint, Offset(w * 0.2f, h * 0.84f), Offset(w * 0.8f, h * 0.84f), strokeWidth = sw, cap = StrokeCap.Round)
            }
            QuickIconKind.HISTORY -> {
                drawCircle(color = tint, radius = w * 0.38f, center = Offset(w * 0.5f, h * 0.5f), style = stroke)
                val hands = Path().apply {
                    moveTo(w * 0.5f, h * 0.28f)
                    lineTo(w * 0.5f, h * 0.52f)
                    lineTo(w * 0.66f, h * 0.62f)
                }
                drawPath(hands, color = tint, style = stroke)
            }
            QuickIconKind.SETTINGS -> {
                drawCircle(color = tint, radius = w * 0.22f, center = Offset(w * 0.5f, h * 0.5f), style = stroke)
                drawCircle(color = tint, radius = w * 0.38f, center = Offset(w * 0.5f, h * 0.5f), style = Stroke(width = sw * 0.75f, pathEffect = PathEffect.dashPathEffect(floatArrayOf(sw * 1.4f, sw * 1.2f))))
            }
            QuickIconKind.IMAGE -> {
                drawRoundRect(tint, Offset(w * 0.14f, h * 0.18f), Size(w * 0.72f, h * 0.64f), CornerRadius(w * 0.12f), style = stroke)
                drawCircle(tint, radius = w * 0.08f, center = Offset(w * 0.34f, h * 0.38f))
                val mtn = Path().apply {
                    moveTo(w * 0.2f, h * 0.74f)
                    lineTo(w * 0.46f, h * 0.48f)
                    lineTo(w * 0.62f, h * 0.64f)
                    lineTo(w * 0.74f, h * 0.52f)
                    lineTo(w * 0.84f, h * 0.74f)
                }
                drawPath(mtn, color = tint, style = stroke)
            }
            QuickIconKind.VIDEO -> {
                val tri = Path().apply {
                    moveTo(w * 0.34f, h * 0.24f)
                    lineTo(w * 0.78f, h * 0.5f)
                    lineTo(w * 0.34f, h * 0.76f)
                    close()
                }
                drawPath(tri, color = tint, style = stroke)
            }
            QuickIconKind.DOC -> {
                drawRoundRect(tint, Offset(w * 0.2f, h * 0.14f), Size(w * 0.6f, h * 0.72f), CornerRadius(w * 0.1f), style = stroke)
                drawLine(tint, Offset(w * 0.32f, h * 0.38f), Offset(w * 0.68f, h * 0.38f), strokeWidth = sw, cap = StrokeCap.Round)
                drawLine(tint, Offset(w * 0.32f, h * 0.54f), Offset(w * 0.68f, h * 0.54f), strokeWidth = sw, cap = StrokeCap.Round)
                drawLine(tint, Offset(w * 0.32f, h * 0.7f), Offset(w * 0.54f, h * 0.7f), strokeWidth = sw, cap = StrokeCap.Round)
            }
            QuickIconKind.AUDIO -> {
                drawLine(tint, Offset(w * 0.42f, h * 0.7f), Offset(w * 0.42f, h * 0.22f), strokeWidth = sw, cap = StrokeCap.Round)
                drawLine(tint, Offset(w * 0.42f, h * 0.22f), Offset(w * 0.76f, h * 0.16f), strokeWidth = sw, cap = StrokeCap.Round)
                drawLine(tint, Offset(w * 0.76f, h * 0.16f), Offset(w * 0.76f, h * 0.62f), strokeWidth = sw, cap = StrokeCap.Round)
                drawCircle(tint, radius = w * 0.12f, center = Offset(w * 0.3f, h * 0.72f))
                drawCircle(tint, radius = w * 0.12f, center = Offset(w * 0.64f, h * 0.64f))
            }
            QuickIconKind.LINK -> {
                drawRoundRect(tint, Offset(w * 0.14f, h * 0.34f), Size(w * 0.42f, h * 0.32f), CornerRadius(w * 0.16f), style = stroke)
                drawRoundRect(tint, Offset(w * 0.44f, h * 0.34f), Size(w * 0.42f, h * 0.32f), CornerRadius(w * 0.16f), style = stroke)
            }
            QuickIconKind.FOLDER -> {
                val p = Path().apply {
                    moveTo(w * 0.14f, h * 0.26f)
                    lineTo(w * 0.4f, h * 0.26f)
                    lineTo(w * 0.48f, h * 0.36f)
                    lineTo(w * 0.86f, h * 0.36f)
                    lineTo(w * 0.86f, h * 0.78f)
                    lineTo(w * 0.14f, h * 0.78f)
                    close()
                }
                drawPath(p, color = tint, style = stroke)
            }
            QuickIconKind.SUN -> {
                drawCircle(tint, radius = w * 0.22f, center = Offset(w * 0.5f, h * 0.5f), style = stroke)
                drawLine(tint, Offset(w * 0.5f, h * 0.1f), Offset(w * 0.5f, h * 0.2f), strokeWidth = sw, cap = StrokeCap.Round)
                drawLine(tint, Offset(w * 0.5f, h * 0.8f), Offset(w * 0.5f, h * 0.9f), strokeWidth = sw, cap = StrokeCap.Round)
                drawLine(tint, Offset(w * 0.1f, h * 0.5f), Offset(w * 0.2f, h * 0.5f), strokeWidth = sw, cap = StrokeCap.Round)
                drawLine(tint, Offset(w * 0.8f, h * 0.5f), Offset(w * 0.9f, h * 0.5f), strokeWidth = sw, cap = StrokeCap.Round)
            }
            QuickIconKind.MOON -> {
                val crescent = Path().apply {
                    moveTo(w * 0.66f, h * 0.18f)
                    quadraticTo(w * 0.24f, h * 0.28f, w * 0.28f, h * 0.66f)
                    quadraticTo(w * 0.36f, h * 0.88f, w * 0.78f, h * 0.74f)
                    quadraticTo(w * 0.48f, h * 0.66f, w * 0.66f, h * 0.18f)
                }
                drawPath(crescent, color = tint, style = stroke)
            }
            QuickIconKind.REFRESH -> {
                drawArc(tint, startAngle = -35f, sweepAngle = 290f, useCenter = false, topLeft = Offset(w * 0.18f, h * 0.18f), size = Size(w * 0.64f, h * 0.64f), style = stroke)
            }
            QuickIconKind.CHECK -> {
                val p = Path().apply {
                    moveTo(w * 0.2f, h * 0.52f)
                    lineTo(w * 0.42f, h * 0.74f)
                    lineTo(w * 0.82f, h * 0.28f)
                }
                drawPath(p, color = tint, style = stroke)
            }
            QuickIconKind.CLOSE -> {
                drawLine(tint, Offset(w * 0.24f, h * 0.24f), Offset(w * 0.76f, h * 0.76f), strokeWidth = sw, cap = StrokeCap.Round)
                drawLine(tint, Offset(w * 0.76f, h * 0.24f), Offset(w * 0.24f, h * 0.76f), strokeWidth = sw, cap = StrokeCap.Round)
            }
            QuickIconKind.PLUS -> {
                drawLine(tint, Offset(w * 0.5f, h * 0.2f), Offset(w * 0.5f, h * 0.8f), strokeWidth = sw, cap = StrokeCap.Round)
                drawLine(tint, Offset(w * 0.2f, h * 0.5f), Offset(w * 0.8f, h * 0.5f), strokeWidth = sw, cap = StrokeCap.Round)
            }
            QuickIconKind.SEARCH -> {
                drawCircle(tint, radius = w * 0.28f, center = Offset(w * 0.44f, h * 0.44f), style = stroke)
                drawLine(tint, Offset(w * 0.65f, h * 0.65f), Offset(w * 0.84f, h * 0.84f), strokeWidth = sw, cap = StrokeCap.Round)
            }
            QuickIconKind.BLUETOOTH -> {
                val bt = Path().apply {
                    moveTo(w * 0.32f, h * 0.3f)
                    lineTo(w * 0.68f, h * 0.68f)
                    lineTo(w * 0.5f, h * 0.86f)
                    lineTo(w * 0.5f, h * 0.14f)
                    lineTo(w * 0.68f, h * 0.32f)
                    lineTo(w * 0.32f, h * 0.7f)
                }
                drawPath(bt, color = tint, style = stroke)
            }
        }
    }
}

private fun openFileWithProvider(context: Context, path: String, fallback: () -> Unit) {
    try {
        val file = File(path)
        if (!file.exists()) {
            fallback()
            return
        }
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        val ext = file.extension.lowercase()
        val mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: "*/*"
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, mime)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(Intent.createChooser(intent, "Open ${file.name}"))
    } catch (_: Throwable) {
        fallback()
    }
}

private fun shareFileOrUrl(context: Context, item: ReceivedItem) {
    try {
        if (item.isUrl) {
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, item.pathOrUrl)
            }
            context.startActivity(Intent.createChooser(intent, "Share link"))
            return
        }
        val file = File(item.pathOrUrl)
        if (!file.exists()) return
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        val ext = file.extension.lowercase()
        val mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: "*/*"
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = mime
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, "Share ${file.name}"))
    } catch (_: Throwable) {
        Toast.makeText(context, "Unable to share file", Toast.LENGTH_SHORT).show()
    }
}
