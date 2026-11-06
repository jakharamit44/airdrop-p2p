package com.s23.airdrop

import android.Manifest
import android.app.DownloadManager
import android.bluetooth.BluetoothAdapter
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
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
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import com.s23.airdrop.theme.S23AirDropTheme
import ds.tokens.DsDarkColors
import ds.tokens.DsMotion
import ds.tokens.DsSpace
import ds.tokens.DsType
import ds.tokens.LocalDsColors
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.cos
import kotlin.math.roundToInt
import kotlin.math.sin

// Tabular figures helper (STD-visual-details-02)
private val TabularNums = TextStyle(fontFeatureSettings = "tnum")

// Subtle 0.97 press scale feedback (STD-mobile-touch-05)
private fun Modifier.pressableScale(
    enabled: Boolean = true,
    onClick: () -> Unit
): Modifier = composed {
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()
    val scale by animateFloatAsState(
        targetValue = if (isPressed && enabled) DsMotion.scalePress else 1f,
        animationSpec = tween(durationMillis = DsMotion.durationMicroMs),
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

// Middle truncation for filenames and paths so extensions remain visible (break-ui rule)
private fun middleTruncate(text: String, maxChars: Int = 34): String {
    if (text.length <= maxChars) return text
    val keepStart = (maxChars - 1) / 2
    val keepEnd = maxChars - 1 - keepStart
    return text.take(keepStart) + "\u2026" + text.takeLast(keepEnd)
}

class MainActivity : ComponentActivity() {

    private lateinit var node: AirDropNode
    private val sharedUris = MutableStateFlow<List<Uri>>(emptyList())
    private val sharedUrl = MutableStateFlow<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        node = AirDropService.getNode(applicationContext)
        runCatching {
            startForegroundService(Intent(this, AirDropService::class.java))
        }
        captureShareIntent(intent)

        enableEdgeToEdge()
        setContent {
            val colors = DsDarkColors
            CompositionLocalProvider(LocalDsColors provides colors) {
                S23AirDropTheme {
                    Surface(
                        modifier = Modifier.fillMaxSize(),
                        color = colors.surfaceBase
                    ) {
                        AirDropScreen(
                            node = node,
                            pendingSharedUris = sharedUris.collectAsState().value,
                            pendingSharedUrl = sharedUrl.collectAsState().value,
                            onClearPendingShare = {
                                sharedUris.value = emptyList()
                                sharedUrl.value = null
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
    }

    override fun onResume() {
        super.onResume()
        if (::node.isInitialized) {
            node.refreshSystemReadiness()
        }
    }

    override fun onDestroy() {
        // Do NOT stop the node or kill AirDropService on activity destroy.
        // The foreground service keeps background transfers alive and maintains discovery.
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
                val text = intent.getStringExtra(Intent.EXTRA_TEXT)
                if (!text.isNullOrBlank() && (text.startsWith("http://") || text.startsWith("https://"))) {
                    sharedUrl.value = text.trim()
                    return
                }
                val stream = if (Build.VERSION.SDK_INT >= 33) {
                    intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(Intent.EXTRA_STREAM)
                }
                if (stream != null) sharedUris.value = listOf(stream)
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

@Composable
fun AirDropScreen(
    node: AirDropNode,
    pendingSharedUris: List<Uri>,
    pendingSharedUrl: String?,
    onClearPendingShare: () -> Unit,
    onOpenUrl: (String) -> Unit,
    onOpenDownloads: () -> Unit
) {
    val c = LocalDsColors.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
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
    val bluetoothEnabled by node.bluetoothEnabled.collectAsState()
    val wifiEnabled by node.wifiEnabled.collectAsState()
    val permissionsGranted by node.permissionsGranted.collectAsState()

    // Navigation items named for their contents (STD-visual-details-34)
    var selectedTab by remember { mutableIntStateOf(0) } // 0 = Nearby, 1 = History, 2 = Settings
    var historyFilter by remember { mutableIntStateOf(0) } // 0 = All, 1 = Received, 2 = Sent
    var showLogs by remember { mutableStateOf(false) }
    var linkPeerTarget by remember { mutableStateOf<AirDropPeer?>(null) }
    var linkText by remember { mutableStateOf("") }
    var showRenameDialog by remember { mutableStateOf(false) }
    var renameText by remember { mutableStateOf(deviceName) }
    var targetPeerForPicker by remember { mutableStateOf<AirDropPeer?>(null) }

    val requiredPermissions = remember {
        buildList {
            if (Build.VERSION.SDK_INT >= 33) {
                add(Manifest.permission.NEARBY_WIFI_DEVICES)
                add(Manifest.permission.POST_NOTIFICATIONS)
            }
            if (Build.VERSION.SDK_INT >= 31) {
                add(Manifest.permission.BLUETOOTH_ADVERTISE)
                add(Manifest.permission.BLUETOOTH_CONNECT)
                add(Manifest.permission.BLUETOOTH_SCAN)
            }
            add(Manifest.permission.ACCESS_FINE_LOCATION)
            add(Manifest.permission.ACCESS_COARSE_LOCATION)
        }.toTypedArray()
    }

    val permLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) {
        node.refreshSystemReadiness()
        node.start()
    }

    val enableBtLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        node.refreshSystemReadiness()
        node.refreshP2p()
    }

    val wifiPanelLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        node.refreshSystemReadiness()
        node.refreshP2p()
    }

    val filePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments()
    ) { uris ->
        val peer = targetPeerForPicker ?: peers.firstOrNull()
        if (peer != null && uris.isNotEmpty()) {
            node.sendUrisAsync(peer, uris) { ok ->
                Toast.makeText(
                    context.applicationContext,
                    if (ok) "Sent ${uris.size} file(s) to ${peer.name.substringBefore(" (")}" else "Transfer failed",
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
    }

    val mediaPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments()
    ) { uris ->
        val peer = targetPeerForPicker ?: peers.firstOrNull()
        if (peer != null && uris.isNotEmpty()) {
            node.sendUrisAsync(peer, uris) { ok ->
                Toast.makeText(
                    context.applicationContext,
                    if (ok) "Sent ${uris.size} media item(s) to ${peer.name.substringBefore(" (")}" else "Transfer failed",
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
    }

    LaunchedEffect(Unit) {
        node.refreshSystemReadiness()
        permLauncher.launch(requiredPermissions)
    }

    // Incoming Transfer Accept / Decline Modal (When Ask First is active)
    incomingAsk?.let { prompt ->
        AlertDialog(
            onDismissRequest = { prompt.decision.complete(false) },
            containerColor = c.surfaceOverlay,
            titleContentColor = c.textPrimary,
            textContentColor = c.textSecondary,
            shape = RoundedCornerShape(DsSpace.radiusOverlay),
            title = {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(DsSpace.space12)
                ) {
                    Box(
                        modifier = Modifier
                            .size(DsSpace.sizeControlMd)
                            .clip(RoundedCornerShape(DsSpace.radius8))
                            .background(c.bgAccentSubtle),
                        contentAlignment = Alignment.Center
                    ) {
                        DsVectorIcon(kind = IconKind.Download, tint = c.iconAccent, size = DsSpace.sizeIconMd)
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Incoming files",
                            style = DsType.titleSm,
                            color = c.textPrimary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = "From ${prompt.senderName}",
                            style = DsType.bodySm,
                            color = c.textSecondary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(DsSpace.space8)) {
                    Surface(
                        color = c.surfaceSunken,
                        shape = RoundedCornerShape(DsSpace.radius8),
                        border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(DsSpace.space12),
                            verticalArrangement = Arrangement.spacedBy(DsSpace.space4)
                        ) {
                            if (prompt.fileNames.isNotEmpty()) {
                                val countLabel = if (prompt.fileNames.size == 1) "1 file" else "${prompt.fileNames.size} files"
                                Text(
                                    text = "$countLabel · ${AirDropNode.formatBytes(prompt.totalBytes)}",
                                    style = DsType.bodySm.merge(TabularNums),
                                    fontWeight = FontWeight.SemiBold,
                                    color = c.textAccent
                                )
                                prompt.fileNames.take(4).forEach { fname ->
                                    Text(
                                        text = middleTruncate(fname, 36),
                                        style = DsType.bodyMd,
                                        color = c.textPrimary,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                                if (prompt.fileNames.size > 4) {
                                    Text(
                                        text = "+${prompt.fileNames.size - 4} more",
                                        style = DsType.bodySm,
                                        color = c.textSecondary
                                    )
                                }
                            } else {
                                Text(
                                    text = prompt.summary,
                                    style = DsType.bodyMd,
                                    color = c.textPrimary
                                )
                            }
                        }
                    }
                    Text(
                        text = "Saves to Downloads/AirDrop",
                        style = DsType.bodySm,
                        color = c.textTertiary
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = { prompt.decision.complete(true) },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = c.bgActionPrimary,
                        contentColor = c.textOnAction
                    ),
                    shape = RoundedCornerShape(DsSpace.radiusControl)
                ) {
                    Text("Accept", style = DsType.labelLg, fontWeight = FontWeight.SemiBold)
                }
            },
            dismissButton = {
                OutlinedButton(
                    onClick = { prompt.decision.complete(false) },
                    border = BorderStroke(DsSpace.borderWidthDefault, c.borderDefault),
                    shape = RoundedCornerShape(DsSpace.radiusControl)
                ) {
                    Text("Decline", style = DsType.labelLg, color = c.textSecondary)
                }
            }
        )
    }

    // Send Text / Link Dialog
    linkPeerTarget?.let { peer ->
        val peerShort = peer.name.substringBefore(" (")
        AlertDialog(
            onDismissRequest = { linkPeerTarget = null },
            containerColor = c.surfaceOverlay,
            titleContentColor = c.textPrimary,
            shape = RoundedCornerShape(DsSpace.radiusOverlay),
            title = {
                Text(
                    text = "Send link or text to $peerShort",
                    style = DsType.titleSm,
                    color = c.textPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(DsSpace.space8)) {
                    OutlinedTextField(
                        value = linkText,
                        onValueChange = { linkText = it },
                        placeholder = { Text("https://… or note text", style = DsType.bodyMd, color = c.textTertiary) },
                        textStyle = DsType.bodyMd.copy(color = c.textPrimary),
                        singleLine = false,
                        maxLines = 4,
                        modifier = Modifier.fillMaxWidth()
                    )
                    TextButton(
                        onClick = {
                            val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                            val clip = cm?.primaryClip?.getItemAt(0)?.coerceToText(context)?.toString()
                            if (!clip.isNullOrBlank()) {
                                linkText = clip
                            }
                        },
                        contentPadding = PaddingValues(horizontal = DsSpace.space8, vertical = DsSpace.space4)
                    ) {
                        Text("Paste from clipboard", style = DsType.bodySm, color = c.textLink)
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val payload = linkText.trim()
                        linkPeerTarget = null
                        linkText = ""
                        if (payload.isNotEmpty()) {
                            node.sendTextSnippetAsync(peer, payload) { ok ->
                                Toast.makeText(
                                    context.applicationContext,
                                    if (ok) "Sent to $peerShort" else "Send failed",
                                    Toast.LENGTH_SHORT
                                ).show()
                            }
                        }
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = c.bgActionPrimary,
                        contentColor = c.textOnAction
                    ),
                    shape = RoundedCornerShape(DsSpace.radiusControl)
                ) {
                    Text("Send", style = DsType.labelLg, fontWeight = FontWeight.SemiBold)
                }
            },
            dismissButton = {
                TextButton(onClick = { linkPeerTarget = null }) {
                    Text("Cancel", style = DsType.labelLg, color = c.textSecondary)
                }
            }
        )
    }

    // Rename Device Dialog
    if (showRenameDialog) {
        AlertDialog(
            onDismissRequest = { showRenameDialog = false },
            containerColor = c.surfaceOverlay,
            titleContentColor = c.textPrimary,
            shape = RoundedCornerShape(DsSpace.radiusOverlay),
            title = { Text("Device name", style = DsType.titleSm, color = c.textPrimary) },
            text = {
                OutlinedTextField(
                    value = renameText,
                    onValueChange = { renameText = it.take(32) },
                    placeholder = { Text("Visible to nearby devices", style = DsType.bodyMd, color = c.textTertiary) },
                    textStyle = DsType.bodyMd.copy(color = c.textPrimary),
                    singleLine = true,
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
                    shape = RoundedCornerShape(DsSpace.radiusControl)
                ) {
                    Text("Save", style = DsType.labelLg, fontWeight = FontWeight.SemiBold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showRenameDialog = false }) {
                    Text("Cancel", style = DsType.labelLg, color = c.textSecondary)
                }
            }
        )
    }

    Scaffold(
        containerColor = c.surfaceBase,
        topBar = {
            TopHeaderBar(
                deviceName = deviceName,
                running = running,
                autoAccept = autoAccept,
                onRenameClick = {
                    renameText = deviceName
                    showRenameDialog = true
                },
                onReceiveModeClick = {
                    node.autoAccept = !autoAccept
                    Toast.makeText(
                        context,
                        if (node.autoAccept) "Auto-accept enabled" else "Ask before receiving enabled",
                        Toast.LENGTH_SHORT
                    ).show()
                },
                onRescanClick = {
                    node.refreshP2p()
                    Toast.makeText(context, "Scanning nearby devices\u2026", Toast.LENGTH_SHORT).show()
                }
            )
        },
        bottomBar = {
            BottomTabNavigation(
                selectedTab = selectedTab,
                peerCount = peers.size,
                historyCount = receivedItems.size,
                onSelectTab = { selectedTab = it }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = DsSpace.space16)
        ) {
            // System Readiness Banner (Permissions + Bluetooth + Wi-Fi power states)
            AnimatedVisibility(visible = !permissionsGranted || !bluetoothEnabled || !wifiEnabled) {
                Box(modifier = Modifier.padding(top = DsSpace.space8, bottom = DsSpace.space4)) {
                    SystemReadinessBanner(
                        permissionsGranted = permissionsGranted,
                        bluetoothEnabled = bluetoothEnabled,
                        wifiEnabled = wifiEnabled,
                        onRequestPermissions = { permLauncher.launch(requiredPermissions) },
                        onEnableBluetooth = {
                            runCatching {
                                enableBtLauncher.launch(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE))
                            }.onFailure {
                                runCatching {
                                    context.startActivity(Intent(Settings.ACTION_BLUETOOTH_SETTINGS))
                                }
                            }
                        },
                        onEnableWifi = {
                            runCatching {
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                                    wifiPanelLauncher.launch(Intent(Settings.Panel.ACTION_WIFI))
                                } else {
                                    context.startActivity(Intent(Settings.ACTION_WIFI_SETTINGS))
                                }
                            }.onFailure {
                                runCatching {
                                    context.startActivity(Intent(Settings.ACTION_WIFI_SETTINGS))
                                }
                            }
                        }
                    )
                }
            }

            // Active transfer bar (only visible when sending or receiving)
            AnimatedVisibility(visible = transferProgress != null) {
                transferProgress?.let { tp ->
                    Box(modifier = Modifier.padding(top = DsSpace.space8, bottom = DsSpace.space4)) {
                        LiveTransferTelemetryCard(
                            tp = tp,
                            onCancel = {
                                node.cancelActiveTransfer()
                                Toast.makeText(context, "Transfer stopped", Toast.LENGTH_SHORT).show()
                            }
                        )
                    }
                }
            }

            // System Share Sheet Banner
            if (pendingSharedUris.isNotEmpty() || pendingSharedUrl != null) {
                PendingShareBanner(
                    uris = pendingSharedUris,
                    url = pendingSharedUrl,
                    peers = peers,
                    onSendToPeer = { peer ->
                        val u = pendingSharedUris
                        val link = pendingSharedUrl
                        val peerLabel = peer.name.substringBefore(" (")
                        onClearPendingShare()
                        if (link != null) {
                            node.sendUrlAsync(peer, link) { ok ->
                                Toast.makeText(
                                    context.applicationContext,
                                    if (ok) "Sent to $peerLabel" else "Transfer failed",
                                    Toast.LENGTH_SHORT
                                ).show()
                            }
                        } else {
                            node.sendUrisAsync(peer, u) { ok ->
                                Toast.makeText(
                                    context.applicationContext,
                                    if (ok) "Sent to $peerLabel" else "Transfer failed",
                                    Toast.LENGTH_SHORT
                                ).show()
                            }
                        }
                    },
                    onDismiss = onClearPendingShare
                )
            }

            when (selectedTab) {
                0 -> NearbyRadarTab(
                    running = running,
                    deviceName = deviceName,
                    p2pStatus = p2pStatus,
                    peers = peers,
                    onRescan = { node.refreshP2p() },
                    onSendFiles = { peer ->
                        targetPeerForPicker = peer
                        filePicker.launch(arrayOf("*/*"))
                    },
                    onSendMedia = { peer ->
                        targetPeerForPicker = peer
                        mediaPicker.launch(arrayOf("image/*", "video/*"))
                    },
                    onSendTextOrLink = { peer ->
                        linkPeerTarget = peer
                    }
                )
                1 -> TransfersHistoryTab(
                    items = receivedItems,
                    filter = historyFilter,
                    onFilterChange = { historyFilter = it },
                    onOpenDownloads = onOpenDownloads,
                    onClearHistory = { node.clearReceivedItems() },
                    onOpenItem = { item ->
                        if (item.isUrl) {
                            onOpenUrl(item.pathOrUrl)
                        } else {
                            openFileWithProvider(context, item.pathOrUrl, onOpenDownloads)
                        }
                    },
                    onShareItem = { item ->
                        shareFileOrUrl(context, item)
                    }
                )
                2 -> SettingsAndP2pTab(
                    running = running,
                    deviceName = deviceName,
                    serviceId = node.serviceId,
                    autoAccept = autoAccept,
                    p2pStatus = p2pStatus,
                    endpoints = endpoints,
                    logs = logs,
                    showLogs = showLogs,
                    onToggleRunning = { enabled ->
                        if (enabled) node.start() else node.stop()
                    },
                    onSelectDirectGet = { direct ->
                        node.autoAccept = direct
                    },
                    onRenameDevice = {
                        renameText = deviceName
                        showRenameDialog = true
                    },
                    onOpenDownloads = onOpenDownloads,
                    onRescanP2p = {
                        node.refreshP2p()
                        Toast.makeText(context, "Refreshed P2P + BLE radio", Toast.LENGTH_SHORT).show()
                    },
                    onToggleLogs = { showLogs = !showLogs },
                    onClearLogs = { node.clearLogs() }
                )
            }
        }
    }
}

// ============================================================================
// Top Shell Header — Overflow-proof at 320dp..430dp and 200% font scale
// ============================================================================
@Composable
private fun TopHeaderBar(
    deviceName: String,
    running: Boolean,
    autoAccept: Boolean,
    onRenameClick: () -> Unit,
    onReceiveModeClick: () -> Unit,
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
                    .heightIn(min = DsSpace.sizeRowLg)
                    .padding(horizontal = DsSpace.space16, vertical = DsSpace.space8),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(DsSpace.space12)
            ) {
                // Brand Mark (40dp control container, 8dp nested radius)
                Box(
                    modifier = Modifier
                        .size(DsSpace.sizeControlMd)
                        .clip(RoundedCornerShape(DsSpace.radius8))
                        .background(c.bgAccentSubtle)
                        .border(DsSpace.borderWidthDefault, c.borderAccent.copy(alpha = 0.45f), RoundedCornerShape(DsSpace.radius8)),
                    contentAlignment = Alignment.Center
                ) {
                    DsVectorIcon(kind = IconKind.Radar, tint = c.iconAccent, size = DsSpace.sizeIconMd)
                }

                // Title & Device Name Column — weight(1f) prevents right-side controls from EVER overflowing!
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .pressableScale(onClick = onRenameClick),
                    verticalArrangement = Arrangement.spacedBy(DsSpace.space2)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(DsSpace.space6)
                    ) {
                        Text(
                            text = "AirDrop P2P",
                            style = DsType.titleMd,
                            color = c.textPrimary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Box(
                            modifier = Modifier
                                .size(DsSpace.space6)
                                .clip(CircleShape)
                                .background(if (running) c.textSuccess else c.textTertiary)
                        )
                    }
                    Text(
                        text = deviceName,
                        style = DsType.bodySm,
                        color = c.textSecondary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                // Receive Mode Status Chip (flex-shrink: 0)
                Surface(
                    color = if (autoAccept) c.bgSuccessSubtle else c.bgNeutralSubtle,
                    shape = RoundedCornerShape(DsSpace.radiusControl),
                    border = BorderStroke(
                        DsSpace.borderWidthDefault,
                        if (autoAccept) c.borderSuccess.copy(alpha = 0.55f) else c.borderSubtle
                    ),
                    modifier = Modifier.pressableScale(onClick = onReceiveModeClick)
                ) {
                    Row(
                        modifier = Modifier
                            .heightIn(min = DsSpace.sizeControlSm)
                            .padding(horizontal = DsSpace.space8, vertical = DsSpace.space4),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(DsSpace.space4)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(DsSpace.space6)
                                .clip(CircleShape)
                                .background(if (autoAccept) c.textSuccess else c.textWarning)
                        )
                        Text(
                            text = if (autoAccept) "Auto-accept" else "Ask first",
                            style = DsType.labelMd,
                            fontWeight = FontWeight.Medium,
                            color = if (autoAccept) c.textSuccess else c.textPrimary,
                            maxLines = 1
                        )
                    }
                }

                // Scan Icon Action (40dp control height with 48dp touch area)
                Box(
                    modifier = Modifier
                        .size(DsSpace.sizeControlMd)
                        .clip(RoundedCornerShape(DsSpace.radiusControl))
                        .background(c.surfaceRaised)
                        .border(DsSpace.borderWidthDefault, c.borderSubtle, RoundedCornerShape(DsSpace.radiusControl))
                        .pressableScale(onClick = onRescanClick),
                    contentAlignment = Alignment.Center
                ) {
                    DsVectorIcon(kind = IconKind.Refresh, tint = c.iconDefault, size = DsSpace.sizeIconSm)
                }
            }
            HorizontalDivider(thickness = DsSpace.borderWidthDefault, color = c.borderSeparator)
        }
    }
}

// ============================================================================
// System Readiness Banner — Permissions + Bluetooth & Wi-Fi Power Prompts
// ============================================================================
@Composable
private fun SystemReadinessBanner(
    permissionsGranted: Boolean,
    bluetoothEnabled: Boolean,
    wifiEnabled: Boolean,
    onRequestPermissions: () -> Unit,
    onEnableBluetooth: () -> Unit,
    onEnableWifi: () -> Unit
) {
    val c = LocalDsColors.current
    val missingItems = buildList {
        if (!permissionsGranted) add("Permissions")
        if (!bluetoothEnabled) add("Bluetooth")
        if (!wifiEnabled) add("Wi-Fi")
    }

    Surface(
        color = c.surfaceRaised,
        shape = RoundedCornerShape(DsSpace.radius12),
        border = BorderStroke(DsSpace.borderWidthDefault, c.textWarning.copy(alpha = 0.65f)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(DsSpace.space12),
            verticalArrangement = Arrangement.spacedBy(DsSpace.space8)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(DsSpace.space8)
            ) {
                Box(
                    modifier = Modifier
                        .size(DsSpace.space8)
                        .clip(CircleShape)
                        .background(c.textWarning)
                )
                Text(
                    text = "Turn on ${missingItems.joinToString(" & ")} for AirDrop P2P",
                    style = DsType.titleSm,
                    color = c.textPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
            }
            Text(
                text = "Bluetooth discovers nearby devices and 5 GHz Wi-Fi Direct transfers large files at full speed.",
                style = DsType.bodySm,
                color = c.textSecondary
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(DsSpace.space8),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (!permissionsGranted) {
                    Surface(
                        color = c.bgActionPrimary,
                        shape = RoundedCornerShape(DsSpace.radiusControl),
                        modifier = Modifier
                            .height(DsSpace.sizeControlSm)
                            .pressableScale(onClick = onRequestPermissions)
                    ) {
                        Box(
                            modifier = Modifier.padding(horizontal = DsSpace.space12),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "Allow permissions",
                                style = DsType.labelMd,
                                fontWeight = FontWeight.SemiBold,
                                color = c.textOnAction,
                                maxLines = 1
                            )
                        }
                    }
                }
                if (!bluetoothEnabled) {
                    Surface(
                        color = c.bgActionPrimary,
                        shape = RoundedCornerShape(DsSpace.radiusControl),
                        modifier = Modifier
                            .height(DsSpace.sizeControlSm)
                            .pressableScale(onClick = onEnableBluetooth)
                    ) {
                        Box(
                            modifier = Modifier.padding(horizontal = DsSpace.space12),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "Turn on Bluetooth",
                                style = DsType.labelMd,
                                fontWeight = FontWeight.SemiBold,
                                color = c.textOnAction,
                                maxLines = 1
                            )
                        }
                    }
                }
                if (!wifiEnabled) {
                    Surface(
                        color = c.bgNeutralSubtle,
                        shape = RoundedCornerShape(DsSpace.radiusControl),
                        border = BorderStroke(DsSpace.borderWidthDefault, c.borderAccent),
                        modifier = Modifier
                            .height(DsSpace.sizeControlSm)
                            .pressableScale(onClick = onEnableWifi)
                    ) {
                        Box(
                            modifier = Modifier.padding(horizontal = DsSpace.space12),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "Turn on Wi-Fi",
                                style = DsType.labelMd,
                                fontWeight = FontWeight.SemiBold,
                                color = c.textAccent,
                                maxLines = 1
                            )
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// Live Transfer Telemetry Card — Tabular numerals, clean single progress bar + Cancel
// ============================================================================
@Composable
private fun LiveTransferTelemetryCard(
    tp: TransferProgress,
    onCancel: () -> Unit
) {
    val c = LocalDsColors.current
    val animatedProgress by animateFloatAsState(
        targetValue = (tp.percent / 100f).coerceIn(0f, 1f),
        animationSpec = tween(durationMillis = DsMotion.durationShortMs, easing = LinearEasing),
        label = "transferPct"
    )

    Surface(
        color = c.surfaceRaised,
        shape = RoundedCornerShape(DsSpace.radius12),
        border = BorderStroke(DsSpace.borderWidthDefault, c.borderAccent),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(DsSpace.space12),
            verticalArrangement = Arrangement.spacedBy(DsSpace.space8)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(DsSpace.space8)
            ) {
                DsVectorIcon(
                    kind = if (tp.isSending) IconKind.Upload else IconKind.Download,
                    tint = c.iconAccent,
                    size = DsSpace.sizeIconSm
                )
                Text(
                    text = middleTruncate(tp.label, 26),
                    style = DsType.titleSm,
                    color = c.textPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
                Text(
                    text = AirDropNode.formatSpeed(tp.speedBytesPerSec),
                    style = DsType.numericMd.merge(TabularNums),
                    fontWeight = FontWeight.SemiBold,
                    color = c.textAccent,
                    maxLines = 1
                )
                Surface(
                    color = c.bgNeutralSubtle,
                    shape = RoundedCornerShape(DsSpace.radiusControl),
                    border = BorderStroke(DsSpace.borderWidthDefault, c.borderStrong),
                    modifier = Modifier
                        .height(DsSpace.sizeControlSm)
                        .pressableScale(onClick = onCancel)
                ) {
                    Box(
                        modifier = Modifier.padding(horizontal = DsSpace.space12),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "Cancel",
                            style = DsType.labelMd,
                            fontWeight = FontWeight.SemiBold,
                            color = c.textPrimary,
                            maxLines = 1
                        )
                    }
                }
            }

            // Progress Track (6dp nested radius)
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(DsSpace.space6)
                    .clip(RoundedCornerShape(DsSpace.radiusFull))
                    .background(c.surfaceSunken)
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth(animatedProgress.coerceAtLeast(0.02f))
                        .height(DsSpace.space6)
                        .clip(RoundedCornerShape(DsSpace.radiusFull))
                        .background(c.bgActionPrimary)
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "${AirDropNode.formatBytes(tp.doneBytes)} of ${AirDropNode.formatBytes(tp.totalBytes)}",
                    style = DsType.bodySm.merge(TabularNums),
                    color = c.textSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
                Row(horizontalArrangement = Arrangement.spacedBy(DsSpace.space8)) {
                    if (tp.etaSeconds > 0L) {
                        Text(
                            text = "${tp.etaSeconds}s left",
                            style = DsType.bodySm.merge(TabularNums),
                            color = c.textTertiary,
                            maxLines = 1
                        )
                    }
                    Text(
                        text = "${tp.percent}%",
                        style = DsType.bodySm.merge(TabularNums),
                        fontWeight = FontWeight.SemiBold,
                        color = c.textPrimary,
                        maxLines = 1
                    )
                }
            }
        }
    }
}

// ============================================================================
// Tab 0: Nearby Radar & Discovered Devices (Quick Share / AirDrop Reference)
// ============================================================================
@Composable
private fun NearbyRadarTab(
    running: Boolean,
    deviceName: String,
    p2pStatus: String,
    peers: List<AirDropPeer>,
    onRescan: () -> Unit,
    onSendFiles: (AirDropPeer) -> Unit,
    onSendMedia: (AirDropPeer) -> Unit,
    onSendTextOrLink: (AirDropPeer) -> Unit
) {
    val c = LocalDsColors.current
    val transition = rememberInfiniteTransition(label = "radar")
    val pulse by transition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(DsMotion.durationExtraMs * 3, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "pulse"
    )

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(DsSpace.space12),
        contentPadding = PaddingValues(top = DsSpace.space12, bottom = DsSpace.space24)
    ) {
        // 1. Compact Radar Stage
        item {
            Surface(
                color = c.surfaceRaised,
                shape = RoundedCornerShape(DsSpace.radius12),
                border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(DsSpace.space16),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(DsSpace.space12)
                ) {
                    // Header Line inside Radar Stage
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(DsSpace.space6),
                            modifier = Modifier.weight(1f)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(DsSpace.space6)
                                    .clip(CircleShape)
                                    .background(if (running) c.textSuccess else c.textTertiary)
                            )
                            Text(
                                text = if (running) "P2P radar active" else "Radar paused",
                                style = DsType.bodySm,
                                color = c.textSecondary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        Text(
                            text = if (peers.size == 1) "1 device nearby" else "${peers.size} devices nearby",
                            style = DsType.bodySm.merge(TabularNums),
                            fontWeight = FontWeight.Medium,
                            color = if (peers.isNotEmpty()) c.textSuccess else c.textTertiary,
                            maxLines = 1
                        )
                    }

                    // Radar Ring Graphic (160dp height — compact, restrained, zero clutter)
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(DsSpace.space80 * 2),
                        contentAlignment = Alignment.Center
                    ) {
                        val ringColor = c.borderSubtle
                        val pulseColor = c.borderAccent
                        val strokeThin = DsSpace.borderWidthDefault
                        val strokeMed = DsSpace.borderWidthSelected
                        Canvas(modifier = Modifier.size(DsSpace.space80 * 2)) {
                            val maxR = size.minDimension / 2f
                            for (i in 1..3) {
                                drawCircle(
                                    color = ringColor,
                                    radius = maxR * (i / 3f),
                                    style = Stroke(width = strokeThin.toPx())
                                )
                            }
                            if (running) {
                                drawCircle(
                                    color = pulseColor.copy(alpha = (1f - pulse) * 0.45f),
                                    radius = maxR * pulse,
                                    style = Stroke(width = strokeMed.toPx())
                                )
                            }
                        }

                        // Center Self Node
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Box(
                                modifier = Modifier
                                    .size(DsSpace.sizeTargetMin)
                                    .clip(CircleShape)
                                    .background(c.bgAccentSubtle)
                                    .border(DsSpace.borderWidthSelected, c.borderAccent, CircleShape),
                                contentAlignment = Alignment.Center
                            ) {
                                DsVectorIcon(kind = IconKind.Phone, tint = c.iconAccent, size = DsSpace.sizeIconMd)
                            }
                            Spacer(Modifier.height(DsSpace.space4))
                            Text(
                                text = deviceName,
                                style = DsType.bodySm,
                                fontWeight = FontWeight.Medium,
                                color = c.textPrimary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }

                        // Discovered Peers Plotted on Radar
                        peers.take(3).forEachIndexed { idx, peer ->
                            val angleRad = Math.toRadians(-45.0 + idx * 110.0)
                            val radiusDp = DsSpace.space64
                            Surface(
                                color = c.surfaceOverlay,
                                shape = RoundedCornerShape(DsSpace.radiusFull),
                                border = BorderStroke(DsSpace.borderWidthDefault, c.borderSuccess),
                                modifier = Modifier
                                    .offset {
                                        IntOffset(
                                            x = (cos(angleRad) * radiusDp.toPx()).roundToInt(),
                                            y = (sin(angleRad) * radiusDp.toPx()).roundToInt()
                                        )
                                    }
                                    .pressableScale { onSendFiles(peer) }
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = DsSpace.space8, vertical = DsSpace.space4),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(DsSpace.space4)
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(DsSpace.space6)
                                            .clip(CircleShape)
                                            .background(c.textSuccess)
                                    )
                                    Text(
                                        text = peer.name.substringBefore(" (").take(16),
                                        style = DsType.bodySm,
                                        fontWeight = FontWeight.Medium,
                                        color = c.textPrimary,
                                        maxLines = 1
                                    )
                                }
                            }
                        }
                    }

                    // Bottom Radio Status Bar inside Stage (8dp nested radius)
                    Surface(
                        color = c.surfaceSunken,
                        shape = RoundedCornerShape(DsSpace.radius8),
                        border = BorderStroke(DsSpace.borderWidthDefault, c.borderSeparator),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = DsSpace.space12, vertical = DsSpace.space8),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(DsSpace.space8)
                        ) {
                            Text(
                                text = p2pStatus,
                                style = DsType.bodySm.merge(TabularNums),
                                color = c.textSecondary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f)
                            )
                            Text(
                                text = "Rescan",
                                style = DsType.bodySm,
                                fontWeight = FontWeight.SemiBold,
                                color = c.textLink,
                                modifier = Modifier
                                    .clip(RoundedCornerShape(DsSpace.radius4))
                                    .pressableScale(onClick = onRescan)
                                    .padding(horizontal = DsSpace.space6, vertical = DsSpace.space2)
                            )
                        }
                    }
                }
            }
        }

        // 2. Section Heading
        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = DsSpace.space4),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Nearby devices",
                    style = DsType.titleSm,
                    color = c.textPrimary
                )
                Text(
                    text = "Tap a device to send",
                    style = DsType.bodySm,
                    color = c.textTertiary
                )
            }
        }

        // 3. Peer List or Empty State
        if (peers.isEmpty()) {
            item {
                Surface(
                    color = c.surfaceRaised,
                    shape = RoundedCornerShape(DsSpace.radius12),
                    border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(DsSpace.space16),
                        verticalAlignment = Alignment.Top,
                        horizontalArrangement = Arrangement.spacedBy(DsSpace.space12)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(DsSpace.sizeControlMd)
                                .clip(RoundedCornerShape(DsSpace.radius8))
                                .background(c.surfaceSunken),
                            contentAlignment = Alignment.Center
                        ) {
                            DsVectorIcon(kind = IconKind.Laptop, tint = c.iconSubtle, size = DsSpace.sizeIconMd)
                        }
                        Column(
                            modifier = Modifier.weight(1f),
                            verticalArrangement = Arrangement.spacedBy(DsSpace.space4)
                        ) {
                            Text(
                                text = "Looking for nearby devices\u2026",
                                style = DsType.titleSm,
                                color = c.textPrimary
                            )
                            Text(
                                text = "Open AirDrop P2P on your Mac or another Android device with Bluetooth enabled. Only live devices within range appear here.",
                                style = DsType.bodyMd,
                                color = c.textSecondary
                            )
                        }
                    }
                }
            }
        } else {
            items(peers, key = { it.id }) { peer ->
                PeerDeviceCard(
                    peer = peer,
                    onSendFiles = { onSendFiles(peer) },
                    onSendMedia = { onSendMedia(peer) },
                    onSendTextOrLink = { onSendTextOrLink(peer) }
                )
            }
        }
    }
}

// ============================================================================
// Peer Device Card — Overflow-proof, nested corners, 1 primary + 2 secondary actions
// ============================================================================
@Composable
private fun PeerDeviceCard(
    peer: AirDropPeer,
    onSendFiles: () -> Unit,
    onSendMedia: () -> Unit,
    onSendTextOrLink: () -> Unit
) {
    val c = LocalDsColors.current
    val cleanName = peer.name.substringBefore(" (")
    val isMac = cleanName.contains("Mac", ignoreCase = true) || peer.name.contains("Mac", ignoreCase = true)

    Surface(
        color = c.surfaceRaised,
        shape = RoundedCornerShape(DsSpace.radius12),
        border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(DsSpace.space16),
            verticalArrangement = Arrangement.spacedBy(DsSpace.space12)
        ) {
            // Top Row: Device Icon + Name/Transport (weight(1f)) + Signal Bars (flex-shrink: 0)
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(DsSpace.space12)
            ) {
                Box(
                    modifier = Modifier
                        .size(DsSpace.sizeControlMd)
                        .clip(RoundedCornerShape(DsSpace.radius8))
                        .background(c.bgAccentSubtle),
                    contentAlignment = Alignment.Center
                ) {
                    DsVectorIcon(
                        kind = if (isMac) IconKind.Laptop else IconKind.Phone,
                        tint = c.iconAccent,
                        size = DsSpace.sizeIconMd
                    )
                }

                // weight(1f) guarantees long device names or transport strings NEVER push signal bars off-screen
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(DsSpace.space2)
                ) {
                    Text(
                        text = cleanName,
                        style = DsType.titleSm,
                        color = c.textPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(DsSpace.space6)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(DsSpace.space6)
                                .clip(CircleShape)
                                .background(c.textSuccess)
                        )
                        Text(
                            text = "${peer.transport} · ${peer.rssi} dBm",
                            style = DsType.bodySm.merge(TabularNums),
                            color = c.textSecondary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }

                // Signal Bars Indicator (fixed 20dp width, never squished)
                SignalBarsIndicator(rssi = peer.rssi, activeColor = c.textSuccess, inactiveColor = c.borderSubtle)
            }

            // Action Controls: 1 Primary CTA ("Send files") + 2 quiet secondary buttons ("Media", "Link")
            // Follows OpenDesigner making.md §10: "One primary button for the one action the view exists for"
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(DsSpace.space8),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Primary Action Button
                Surface(
                    color = c.bgActionPrimary,
                    shape = RoundedCornerShape(DsSpace.radiusControl),
                    modifier = Modifier
                        .weight(1.25f)
                        .height(DsSpace.sizeControlMd)
                        .pressableScale(onClick = onSendFiles)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(horizontal = DsSpace.space12),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        DsVectorIcon(kind = IconKind.File, tint = c.textOnAction, size = DsSpace.sizeIconSm)
                        Spacer(Modifier.width(DsSpace.space6))
                        Text(
                            text = "Send files",
                            style = DsType.labelLg,
                            fontWeight = FontWeight.SemiBold,
                            color = c.textOnAction,
                            maxLines = 1
                        )
                    }
                }

                // Secondary Action: Media
                Surface(
                    color = c.bgNeutralSubtle,
                    shape = RoundedCornerShape(DsSpace.radiusControl),
                    border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
                    modifier = Modifier
                        .weight(0.9f)
                        .height(DsSpace.sizeControlMd)
                        .pressableScale(onClick = onSendMedia)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(horizontal = DsSpace.space8),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        DsVectorIcon(kind = IconKind.Image, tint = c.iconDefault, size = DsSpace.sizeIconSm)
                        Spacer(Modifier.width(DsSpace.space6))
                        Text(
                            text = "Media",
                            style = DsType.labelLg,
                            color = c.textPrimary,
                            maxLines = 1
                        )
                    }
                }

                // Secondary Action: Link / Text
                Surface(
                    color = c.bgNeutralSubtle,
                    shape = RoundedCornerShape(DsSpace.radiusControl),
                    border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
                    modifier = Modifier
                        .weight(0.85f)
                        .height(DsSpace.sizeControlMd)
                        .pressableScale(onClick = onSendTextOrLink)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(horizontal = DsSpace.space8),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        DsVectorIcon(kind = IconKind.Link, tint = c.iconDefault, size = DsSpace.sizeIconSm)
                        Spacer(Modifier.width(DsSpace.space6))
                        Text(
                            text = "Link",
                            style = DsType.labelLg,
                            color = c.textPrimary,
                            maxLines = 1
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun SignalBarsIndicator(rssi: Int, activeColor: Color, inactiveColor: Color) {
    val bars = when {
        rssi >= -55 -> 4
        rssi >= -68 -> 3
        rssi >= -80 -> 2
        else -> 1
    }
    Row(
        verticalAlignment = Alignment.Bottom,
        horizontalArrangement = Arrangement.spacedBy(DsSpace.space2),
        modifier = Modifier
            .width(DsSpace.space20)
            .height(DsSpace.space16)
    ) {
        for (b in 1..4) {
            Box(
                modifier = Modifier
                    .width(DsSpace.space4)
                    .height(DsSpace.space4 * b)
                    .clip(RoundedCornerShape(DsSpace.radius2))
                    .background(if (b <= bars) activeColor else inactiveColor)
            )
        }
    }
}

// ============================================================================
// Tab 1: Transfer History — Clean 2-Card KPI Row + Overflow-Free Filter Bar
// ============================================================================
@Composable
private fun TransfersHistoryTab(
    items: List<ReceivedItem>,
    filter: Int,
    onFilterChange: (Int) -> Unit,
    onOpenDownloads: () -> Unit,
    onClearHistory: () -> Unit,
    onOpenItem: (ReceivedItem) -> Unit,
    onShareItem: (ReceivedItem) -> Unit
) {
    val c = LocalDsColors.current
    val context = LocalContext.current
    val filteredItems = remember(items, filter) {
        when (filter) {
            1 -> items.filter { !it.isOutgoing }
            2 -> items.filter { it.isOutgoing }
            else -> items
        }
    }
    val receivedCount = remember(items) { items.count { !it.isOutgoing } }
    val sentCount = remember(items) { items.count { it.isOutgoing } }
    val totalReceivedBytes = remember(items) { items.filter { !it.isOutgoing }.sumOf { it.sizeBytes } }
    val totalSentBytes = remember(items) { items.filter { it.isOutgoing }.sumOf { it.sizeBytes } }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(DsSpace.space12),
        contentPadding = PaddingValues(top = DsSpace.space12, bottom = DsSpace.space24)
    ) {
        // 1. Sibling KPI Summary Cards (Share top edge and height per OpenDesigner quality.md)
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(DsSpace.space12)
            ) {
                Surface(
                    color = c.surfaceRaised,
                    shape = RoundedCornerShape(DsSpace.radius12),
                    border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
                    modifier = Modifier.weight(1f)
                ) {
                    Column(
                        modifier = Modifier.padding(DsSpace.space12),
                        verticalArrangement = Arrangement.spacedBy(DsSpace.space4)
                    ) {
                        Text(
                            text = "Received",
                            style = DsType.bodySm,
                            color = c.textSecondary,
                            maxLines = 1
                        )
                        Text(
                            text = AirDropNode.formatBytes(totalReceivedBytes),
                            style = DsType.numericLg.merge(TabularNums),
                            color = c.textPrimary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = if (receivedCount == 1) "1 file saved" else "$receivedCount files saved",
                            style = DsType.bodySm.merge(TabularNums),
                            color = c.textTertiary,
                            maxLines = 1
                        )
                    }
                }
                Surface(
                    color = c.surfaceRaised,
                    shape = RoundedCornerShape(DsSpace.radius12),
                    border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
                    modifier = Modifier.weight(1f)
                ) {
                    Column(
                        modifier = Modifier.padding(DsSpace.space12),
                        verticalArrangement = Arrangement.spacedBy(DsSpace.space4)
                    ) {
                        Text(
                            text = "Sent",
                            style = DsType.bodySm,
                            color = c.textSecondary,
                            maxLines = 1
                        )
                        Text(
                            text = AirDropNode.formatBytes(totalSentBytes),
                            style = DsType.numericLg.merge(TabularNums),
                            color = c.textPrimary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = if (sentCount == 1) "1 file sent" else "$sentCount files sent",
                            style = DsType.bodySm.merge(TabularNums),
                            color = c.textTertiary,
                            maxLines = 1
                        )
                    }
                }
            }
        }

        // 2. Segmented Filter + Folder/Clear Bar (Overflow-proof: segmented control on left, compact actions on right)
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Segmented Control container (8dp outer radius, 6dp inner pills)
                Surface(
                    color = c.surfaceSunken,
                    shape = RoundedCornerShape(DsSpace.radius8),
                    border = BorderStroke(DsSpace.borderWidthDefault, c.borderSeparator)
                ) {
                    Row(
                        modifier = Modifier.padding(DsSpace.space2),
                        horizontalArrangement = Arrangement.spacedBy(DsSpace.space2)
                    ) {
                        listOf("All", "Received", "Sent").forEachIndexed { idx, title ->
                            val active = filter == idx
                            Surface(
                                color = if (active) c.surfaceRaised else Color.Transparent,
                                shape = RoundedCornerShape(DsSpace.radiusControl),
                                modifier = Modifier.pressableScale { onFilterChange(idx) }
                            ) {
                                Text(
                                    text = title,
                                    style = DsType.labelMd,
                                    fontWeight = if (active) FontWeight.SemiBold else FontWeight.Normal,
                                    color = if (active) c.textPrimary else c.textSecondary,
                                    maxLines = 1,
                                    modifier = Modifier.padding(horizontal = DsSpace.space12, vertical = DsSpace.space6)
                                )
                            }
                        }
                    }
                }

                // Right Actions (Folder & Clear)
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(DsSpace.space6)
                ) {
                    Surface(
                        color = c.surfaceRaised,
                        shape = RoundedCornerShape(DsSpace.radiusControl),
                        border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
                        modifier = Modifier
                            .height(DsSpace.sizeControlSm)
                            .pressableScale(onClick = onOpenDownloads)
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = DsSpace.space8),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(DsSpace.space4)
                        ) {
                            DsVectorIcon(kind = IconKind.Folder, tint = c.iconDefault, size = DsSpace.sizeIconSm)
                            Text(
                                text = "Folder",
                                style = DsType.labelMd,
                                color = c.textPrimary,
                                maxLines = 1
                            )
                        }
                    }
                    if (items.isNotEmpty()) {
                        Surface(
                            color = c.surfaceRaised,
                            shape = RoundedCornerShape(DsSpace.radiusControl),
                            border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
                            modifier = Modifier
                                .height(DsSpace.sizeControlSm)
                                .pressableScale(onClick = onClearHistory)
                        ) {
                            Box(
                                modifier = Modifier.padding(horizontal = DsSpace.space8),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = "Clear",
                                    style = DsType.labelMd,
                                    color = c.textSecondary,
                                    maxLines = 1
                                )
                            }
                        }
                    }
                }
            }
        }

        // 3. History List or Empty State
        if (filteredItems.isEmpty()) {
            item {
                Surface(
                    color = c.surfaceRaised,
                    shape = RoundedCornerShape(DsSpace.radius12),
                    border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(DsSpace.space24),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(DsSpace.space6)
                    ) {
                        DsVectorIcon(kind = IconKind.Folder, tint = c.iconSubtle, size = DsSpace.sizeIconLg)
                        Text(
                            text = "No transfers yet",
                            style = DsType.titleSm,
                            color = c.textPrimary
                        )
                        Text(
                            text = "Files and links you send or receive appear here.",
                            style = DsType.bodyMd,
                            color = c.textSecondary,
                            textAlign = TextAlign.Center
                        )
                    }
                }
            }
        } else {
            items(filteredItems, key = { "${it.timestampMs}_${it.title}" }) { item ->
                val timeStr = remember(item.timestampMs) {
                    SimpleDateFormat("HH:mm · MMM d", Locale.US).format(Date(item.timestampMs))
                }
                val iconKind = remember(item.title, item.isUrl) {
                    when {
                        item.isUrl -> IconKind.Link
                        item.title.substringAfterLast('.', "").lowercase() in setOf("jpg", "jpeg", "png", "webp", "heic", "gif", "mp4", "mov", "mkv") -> IconKind.Image
                        else -> IconKind.File
                    }
                }

                Surface(
                    color = c.surfaceRaised,
                    shape = RoundedCornerShape(DsSpace.radius12),
                    border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(DsSpace.space12),
                        verticalArrangement = Arrangement.spacedBy(DsSpace.space8)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(DsSpace.space12)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(DsSpace.sizeControlMd)
                                    .clip(RoundedCornerShape(DsSpace.radius8))
                                    .background(c.surfaceSunken),
                                contentAlignment = Alignment.Center
                            ) {
                                DsVectorIcon(kind = iconKind, tint = c.iconDefault, size = DsSpace.sizeIconSm)
                            }

                            Column(
                                modifier = Modifier.weight(1f),
                                verticalArrangement = Arrangement.spacedBy(DsSpace.space2)
                            ) {
                                Text(
                                    text = middleTruncate(item.title, 36),
                                    style = DsType.titleSm,
                                    color = c.textPrimary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = "${if (item.isOutgoing) "Sent to" else "From"} ${item.peerName.substringBefore(" (")} · ${AirDropNode.formatBytes(item.sizeBytes)} · $timeStr",
                                    style = DsType.bodySm.merge(TabularNums),
                                    color = c.textSecondary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        }

                        // Action Footer: Secondary left, Primary right (OpenDesigner making.md §10 preflight 41)
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(horizontalArrangement = Arrangement.spacedBy(DsSpace.space12)) {
                                Text(
                                    text = "Copy path",
                                    style = DsType.bodySm,
                                    color = c.textSecondary,
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(DsSpace.radius4))
                                        .pressableScale {
                                            val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                                            cm?.setPrimaryClip(ClipData.newPlainText("AirDrop", item.pathOrUrl))
                                            Toast.makeText(context, "Copied to clipboard", Toast.LENGTH_SHORT).show()
                                        }
                                        .padding(vertical = DsSpace.space4, horizontal = DsSpace.space4)
                                )
                                if (!item.isOutgoing || item.isUrl) {
                                    Text(
                                        text = "Share",
                                        style = DsType.bodySm,
                                        color = c.textSecondary,
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(DsSpace.radius4))
                                            .pressableScale { onShareItem(item) }
                                            .padding(vertical = DsSpace.space4, horizontal = DsSpace.space4)
                                    )
                                }
                            }

                            if (!item.isOutgoing || item.isUrl) {
                                Surface(
                                    color = c.bgNeutralSubtle,
                                    shape = RoundedCornerShape(DsSpace.radiusControl),
                                    border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
                                    modifier = Modifier
                                        .height(DsSpace.sizeControlSm)
                                        .pressableScale { onOpenItem(item) }
                                ) {
                                    Box(
                                        modifier = Modifier.padding(horizontal = DsSpace.space12),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Text(
                                            text = if (item.isUrl) "Open link" else "Open file",
                                            style = DsType.labelMd,
                                            fontWeight = FontWeight.SemiBold,
                                            color = c.textPrimary,
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
}

// ============================================================================
// Tab 2: Settings & P2P Radio — Every Row Overflow-Protected with weight(1f)
// ============================================================================
@Composable
private fun SettingsAndP2pTab(
    running: Boolean,
    deviceName: String,
    serviceId: String,
    autoAccept: Boolean,
    p2pStatus: String,
    endpoints: List<String>,
    logs: List<String>,
    showLogs: Boolean,
    onToggleRunning: (Boolean) -> Unit,
    onSelectDirectGet: (Boolean) -> Unit,
    onRenameDevice: () -> Unit,
    onOpenDownloads: () -> Unit,
    onRescanP2p: () -> Unit,
    onToggleLogs: () -> Unit,
    onClearLogs: () -> Unit
) {
    val c = LocalDsColors.current
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(DsSpace.space16),
        contentPadding = PaddingValues(top = DsSpace.space12, bottom = DsSpace.space24)
    ) {
        // 1. Receiving Preference Group
        item {
            Surface(
                color = c.surfaceRaised,
                shape = RoundedCornerShape(DsSpace.radius12),
                border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(DsSpace.space16),
                    verticalArrangement = Arrangement.spacedBy(DsSpace.space12)
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(DsSpace.space2)) {
                        Text(
                            text = "Receiving files",
                            style = DsType.titleSm,
                            color = c.textPrimary
                        )
                        Text(
                            text = "Choose how incoming transfers from nearby devices are handled.",
                            style = DsType.bodySm,
                            color = c.textSecondary
                        )
                    }

                    ReceiveModeOptionCard(
                        title = "Auto-accept files (Direct Get)",
                        subtitle = "Save incoming files directly to Downloads/AirDrop without a prompt.",
                        badge = "Fastest",
                        selected = autoAccept,
                        onClick = { onSelectDirectGet(true) }
                    )

                    ReceiveModeOptionCard(
                        title = "Ask every time",
                        subtitle = "Show sender name, file list, and size before downloading.",
                        badge = "Confirm",
                        selected = !autoAccept,
                        onClick = { onSelectDirectGet(false) }
                    )
                }
            }
        }

        // 2. Device Identity & Storage Group (Every left column has weight(1f)!)
        item {
            Surface(
                color = c.surfaceRaised,
                shape = RoundedCornerShape(DsSpace.radius12),
                border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(DsSpace.space16),
                    verticalArrangement = Arrangement.spacedBy(DsSpace.space12)
                ) {
                    Text(
                        text = "Device & storage",
                        style = DsType.titleSm,
                        color = c.textPrimary
                    )

                    // Row 1: Visibility Switch
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = DsSpace.sizeRowMd),
                        horizontalArrangement = Arrangement.spacedBy(DsSpace.space12),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(
                            modifier = Modifier.weight(1f),
                            verticalArrangement = Arrangement.spacedBy(DsSpace.space2)
                        ) {
                            Text(
                                text = if (running) "Visible to nearby devices" else "Hidden (radio off)",
                                style = DsType.bodyMd,
                                fontWeight = FontWeight.Medium,
                                color = c.textPrimary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                text = "Broadcasts BLE L2CAP + 5GHz Wi-Fi Direct",
                                style = DsType.bodySm,
                                color = c.textSecondary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        Switch(
                            checked = running,
                            onCheckedChange = onToggleRunning,
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = c.textOnAction,
                                checkedTrackColor = c.bgActionPrimary
                            )
                        )
                    }

                    HorizontalDivider(thickness = DsSpace.borderWidthDefault, color = c.borderSeparator)

                    // Row 2: Device Name (weight(1f) prevents Rename button overflow)
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = DsSpace.sizeRowMd),
                        horizontalArrangement = Arrangement.spacedBy(DsSpace.space12),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(
                            modifier = Modifier.weight(1f),
                            verticalArrangement = Arrangement.spacedBy(DsSpace.space2)
                        ) {
                            Text(
                                text = "Device name",
                                style = DsType.bodyMd,
                                fontWeight = FontWeight.Medium,
                                color = c.textPrimary,
                                maxLines = 1
                            )
                            Text(
                                text = "$deviceName · ID $serviceId",
                                style = DsType.bodySm.merge(TabularNums),
                                color = c.textSecondary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        Surface(
                            color = c.bgNeutralSubtle,
                            shape = RoundedCornerShape(DsSpace.radiusControl),
                            border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
                            modifier = Modifier
                                .height(DsSpace.sizeControlSm)
                                .pressableScale(onClick = onRenameDevice)
                        ) {
                            Box(
                                modifier = Modifier.padding(horizontal = DsSpace.space12),
                                contentAlignment = Alignment.Center
                            ) {
                                Text("Rename", style = DsType.labelMd, color = c.textPrimary, maxLines = 1)
                            }
                        }
                    }

                    HorizontalDivider(thickness = DsSpace.borderWidthDefault, color = c.borderSeparator)

                    // Row 3: Save Location (weight(1f) + middleTruncate prevents Open button overflow!)
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = DsSpace.sizeRowMd),
                        horizontalArrangement = Arrangement.spacedBy(DsSpace.space12),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(
                            modifier = Modifier.weight(1f),
                            verticalArrangement = Arrangement.spacedBy(DsSpace.space2)
                        ) {
                            Text(
                                text = "Download folder",
                                style = DsType.bodyMd,
                                fontWeight = FontWeight.Medium,
                                color = c.textPrimary,
                                maxLines = 1
                            )
                            Text(
                                text = middleTruncate("/storage/emulated/0/Download/AirDrop", 32),
                                style = DsType.bodySm,
                                color = c.textSecondary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        Surface(
                            color = c.bgNeutralSubtle,
                            shape = RoundedCornerShape(DsSpace.radiusControl),
                            border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
                            modifier = Modifier
                                .height(DsSpace.sizeControlSm)
                                .pressableScale(onClick = onOpenDownloads)
                        ) {
                            Box(
                                modifier = Modifier.padding(horizontal = DsSpace.space12),
                                contentAlignment = Alignment.Center
                            ) {
                                Text("Open", style = DsType.labelMd, color = c.textPrimary, maxLines = 1)
                            }
                        }
                    }

                    HorizontalDivider(thickness = DsSpace.borderWidthDefault, color = c.borderSeparator)

                    // Row 4: End-to-End Encryption & Privacy
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = DsSpace.sizeRowMd),
                        horizontalArrangement = Arrangement.spacedBy(DsSpace.space12),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(
                            modifier = Modifier.weight(1f),
                            verticalArrangement = Arrangement.spacedBy(DsSpace.space2)
                        ) {
                            Text(
                                text = "End-to-end encryption",
                                style = DsType.bodyMd,
                                fontWeight = FontWeight.Medium,
                                color = c.textPrimary,
                                maxLines = 1
                            )
                            Text(
                                text = "TLS 1.3 (ECDSA P-256) + AES-256-GCM + Ephemeral WPA2",
                                style = DsType.bodySm,
                                color = c.textSecondary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        Surface(
                            color = c.bgSuccessSubtle,
                            shape = RoundedCornerShape(DsSpace.radiusControl),
                            border = BorderStroke(DsSpace.borderWidthDefault, c.borderSuccess.copy(alpha = 0.55f))
                        ) {
                            Box(
                                modifier = Modifier
                                    .heightIn(min = DsSpace.sizeControlSm)
                                    .padding(horizontal = DsSpace.space8, vertical = DsSpace.space4),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = "Active",
                                    style = DsType.labelMd,
                                    fontWeight = FontWeight.SemiBold,
                                    color = c.textSuccess,
                                    maxLines = 1
                                )
                            }
                        }
                    }
                }
            }
        }

        // 3. P2P Radio Diagnostics & Live Protocol Log
        item {
            Surface(
                color = c.surfaceRaised,
                shape = RoundedCornerShape(DsSpace.radius12),
                border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(DsSpace.space16),
                    verticalArrangement = Arrangement.spacedBy(DsSpace.space12)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "P2P radio diagnostics",
                            style = DsType.titleSm,
                            color = c.textPrimary,
                            modifier = Modifier.weight(1f)
                        )
                        Surface(
                            color = c.bgNeutralSubtle,
                            shape = RoundedCornerShape(DsSpace.radiusControl),
                            border = BorderStroke(DsSpace.borderWidthDefault, c.borderSubtle),
                            modifier = Modifier
                                .height(DsSpace.sizeControlSm)
                                .pressableScale(onClick = onRescanP2p)
                        ) {
                            Box(
                                modifier = Modifier.padding(horizontal = DsSpace.space12),
                                contentAlignment = Alignment.Center
                            ) {
                                Text("Restart radio", style = DsType.labelMd, color = c.textPrimary, maxLines = 1)
                            }
                        }
                    }

                    Text(
                        text = p2pStatus,
                        style = DsType.bodyMd.merge(TabularNums),
                        color = c.textSuccess
                    )

                    if (endpoints.isNotEmpty()) {
                        Text(
                            text = "Listeners: ${endpoints.joinToString(" · ")}",
                            style = DsType.bodySm.merge(TabularNums),
                            color = c.textSecondary,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = if (showLogs) "Hide protocol logs" else "Show protocol logs (${logs.size})",
                            style = DsType.bodySm,
                            fontWeight = FontWeight.Medium,
                            color = c.textLink,
                            modifier = Modifier
                                .clip(RoundedCornerShape(DsSpace.radius4))
                                .pressableScale(onClick = onToggleLogs)
                                .padding(vertical = DsSpace.space4)
                        )
                        if (showLogs && logs.isNotEmpty()) {
                            Text(
                                text = "Clear",
                                style = DsType.bodySm,
                                color = c.textSecondary,
                                modifier = Modifier
                                    .clip(RoundedCornerShape(DsSpace.radius4))
                                    .pressableScale(onClick = onClearLogs)
                                    .padding(vertical = DsSpace.space4, horizontal = DsSpace.space6)
                            )
                        }
                    }

                    if (showLogs) {
                        Surface(
                            color = c.surfaceSunken,
                            shape = RoundedCornerShape(DsSpace.radius8),
                            border = BorderStroke(DsSpace.borderWidthDefault, c.borderSeparator),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(
                                modifier = Modifier.padding(DsSpace.space8),
                                verticalArrangement = Arrangement.spacedBy(DsSpace.space2)
                            ) {
                                for (line in logs.takeLast(24)) {
                                    Text(
                                        text = line,
                                        style = DsType.codeSm.merge(TabularNums),
                                        fontFamily = FontFamily.Monospace,
                                        color = c.textSecondary
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
private fun ReceiveModeOptionCard(
    title: String,
    subtitle: String,
    badge: String,
    selected: Boolean,
    onClick: () -> Unit
) {
    val c = LocalDsColors.current
    Surface(
        color = if (selected) c.bgAccentSubtle else c.surfaceSunken,
        shape = RoundedCornerShape(DsSpace.radius8),
        border = BorderStroke(
            if (selected) DsSpace.borderWidthSelected else DsSpace.borderWidthDefault,
            if (selected) c.borderAccent else c.borderSeparator
        ),
        modifier = Modifier
            .fillMaxWidth()
            .pressableScale(onClick = onClick)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(DsSpace.space12),
            verticalAlignment = Alignment.Top,
            horizontalArrangement = Arrangement.spacedBy(DsSpace.space12)
        ) {
            // Radio Circle (flex-shrink: 0, top-aligned with first line of text per break-ui)
            Box(
                modifier = Modifier
                    .padding(top = DsSpace.space2)
                    .size(DsSpace.sizeIconSm)
                    .clip(CircleShape)
                    .border(
                        width = if (selected) DsSpace.borderWidthSelected else DsSpace.borderWidthDefault,
                        color = if (selected) c.borderFocus else c.borderStrong,
                        shape = CircleShape
                    ),
                contentAlignment = Alignment.Center
            ) {
                if (selected) {
                    Box(
                        modifier = Modifier
                            .size(DsSpace.space8)
                            .clip(CircleShape)
                            .background(c.borderFocus)
                    )
                }
            }

            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(DsSpace.space2)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(DsSpace.space8)
                ) {
                    Text(
                        text = title,
                        style = DsType.titleSm,
                        color = c.textPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    Surface(
                        color = if (selected) c.bgActionPrimary else c.bgNeutralSubtle,
                        shape = RoundedCornerShape(DsSpace.radius4)
                    ) {
                        Text(
                            text = badge,
                            style = DsType.labelSm,
                            color = if (selected) c.textOnAction else c.textSecondary,
                            maxLines = 1,
                            modifier = Modifier.padding(horizontal = DsSpace.space6, vertical = DsSpace.space2)
                        )
                    }
                }
                Text(
                    text = subtitle,
                    style = DsType.bodySm,
                    color = c.textSecondary
                )
            }
        }
    }
}

@Composable
private fun PendingShareBanner(
    uris: List<Uri>,
    url: String?,
    peers: List<AirDropPeer>,
    onSendToPeer: (AirDropPeer) -> Unit,
    onDismiss: () -> Unit
) {
    val c = LocalDsColors.current
    Surface(
        color = c.surfaceRaised,
        shape = RoundedCornerShape(DsSpace.radius12),
        border = BorderStroke(DsSpace.borderWidthDefault, c.borderAccent),
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = DsSpace.space6)
    ) {
        Column(
            modifier = Modifier.padding(DsSpace.space12),
            verticalArrangement = Arrangement.spacedBy(DsSpace.space8)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = if (url != null) "Ready to share link" else "Ready to share ${uris.size} file(s)",
                    style = DsType.titleSm,
                    color = c.textPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
                Text(
                    text = "Dismiss",
                    style = DsType.bodySm,
                    color = c.textSecondary,
                    modifier = Modifier
                        .clip(RoundedCornerShape(DsSpace.radius4))
                        .pressableScale(onClick = onDismiss)
                        .padding(horizontal = DsSpace.space6, vertical = DsSpace.space4)
                )
            }
            if (peers.isEmpty()) {
                Text(
                    text = "Searching for nearby devices\u2026",
                    style = DsType.bodySm,
                    color = c.textSecondary
                )
            } else {
                peers.forEach { peer ->
                    Button(
                        onClick = { onSendToPeer(peer) },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = c.bgActionPrimary,
                            contentColor = c.textOnAction
                        ),
                        shape = RoundedCornerShape(DsSpace.radiusControl),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = "Send to ${peer.name.substringBefore(" (")}",
                            style = DsType.labelLg,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }
        }
    }
}

// ============================================================================
// Bottom Navigation Bar — Clean vertical Icon + 1-word label (Zero horizontal wrap)
// Follows OpenDesigner making.md §12 "Lists and sidebars breathe"
// ============================================================================
@Composable
private fun BottomTabNavigation(
    selectedTab: Int,
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
        Column(modifier = Modifier.fillMaxWidth()) {
            HorizontalDivider(thickness = DsSpace.borderWidthDefault, color = c.borderSeparator)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(DsSpace.sizeRowLg)
                    .padding(horizontal = DsSpace.space8, vertical = DsSpace.space4),
                horizontalArrangement = Arrangement.spacedBy(DsSpace.space8),
                verticalAlignment = Alignment.CenterVertically
            ) {
                val tabs = listOf(
                    TabSpec("Nearby", IconKind.Radar, if (peerCount > 0) "$peerCount" else null, 0),
                    TabSpec("History", IconKind.Folder, if (historyCount > 0) "$historyCount" else null, 1),
                    TabSpec("Settings", IconKind.Sliders, null, 2)
                )
                tabs.forEach { tab ->
                    val active = selectedTab == tab.index
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .height(DsSpace.sizeRowMd)
                            .clip(RoundedCornerShape(DsSpace.radius8))
                            .background(if (active) c.bgAccentSubtle else Color.Transparent)
                            .pressableScale { onSelectTab(tab.index) },
                        contentAlignment = Alignment.Center
                    ) {
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(DsSpace.space2)
                        ) {
                            Box(contentAlignment = Alignment.TopEnd) {
                                Box(modifier = Modifier.padding(horizontal = DsSpace.space8, vertical = DsSpace.space2)) {
                                    DsVectorIcon(
                                        kind = tab.icon,
                                        tint = if (active) c.iconAccent else c.iconSubtle,
                                        size = DsSpace.sizeIconMd
                                    )
                                }
                                if (tab.badge != null) {
                                    Surface(
                                        color = if (active) c.bgActionPrimary else c.bgNeutralSubtle,
                                        shape = RoundedCornerShape(DsSpace.radiusFull)
                                    ) {
                                        Text(
                                            text = tab.badge,
                                            style = DsType.labelSm.merge(TabularNums),
                                            color = if (active) c.textOnAction else c.textSecondary,
                                            maxLines = 1,
                                            modifier = Modifier.padding(horizontal = DsSpace.space4, vertical = DsSpace.space0)
                                        )
                                    }
                                }
                            }
                            Text(
                                text = tab.label,
                                style = DsType.labelSm,
                                fontWeight = if (active) FontWeight.SemiBold else FontWeight.Normal,
                                color = if (active) c.textAccent else c.textSecondary,
                                maxLines = 1
                            )
                        }
                    }
                }
            }
        }
    }
}

private data class TabSpec(
    val label: String,
    val icon: IconKind,
    val badge: String?,
    val index: Int
)

// ============================================================================
// Crisp Vector Icons Drawn on Canvas (OpenDesigner making.md §12: never text/emoji)
// ============================================================================
private enum class IconKind {
    Radar, Laptop, Phone, File, Image, Link, Folder, Refresh, Sliders, Download, Upload
}

@Composable
private fun DsVectorIcon(
    kind: IconKind,
    tint: Color,
    size: Dp = DsSpace.sizeIconDefault
) {
    val minStrokeDp = DsSpace.borderWidthSelected
    Canvas(modifier = Modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val sw = (w * 0.09f).coerceAtLeast(minStrokeDp.toPx())
        val stroke = Stroke(width = sw, cap = StrokeCap.Round, join = StrokeJoin.Round)

        when (kind) {
            IconKind.Radar -> {
                val c = Offset(w / 2f, h / 2f)
                drawArc(
                    color = tint,
                    startAngle = 145f,
                    sweepAngle = 250f,
                    useCenter = false,
                    topLeft = Offset(w * 0.12f, h * 0.12f),
                    size = Size(w * 0.76f, h * 0.76f),
                    style = stroke
                )
                drawArc(
                    color = tint,
                    startAngle = 145f,
                    sweepAngle = 250f,
                    useCenter = false,
                    topLeft = Offset(w * 0.28f, h * 0.28f),
                    size = Size(w * 0.44f, h * 0.44f),
                    style = stroke
                )
                drawCircle(color = tint, radius = sw * 0.9f, center = c)
            }
            IconKind.Laptop -> {
                drawRoundRect(
                    color = tint,
                    topLeft = Offset(w * 0.16f, h * 0.20f),
                    size = Size(w * 0.68f, h * 0.48f),
                    cornerRadius = CornerRadius(w * 0.06f, w * 0.06f),
                    style = stroke
                )
                drawLine(
                    color = tint,
                    start = Offset(w * 0.08f, h * 0.78f),
                    end = Offset(w * 0.92f, h * 0.78f),
                    strokeWidth = sw,
                    cap = StrokeCap.Round
                )
            }
            IconKind.Phone -> {
                drawRoundRect(
                    color = tint,
                    topLeft = Offset(w * 0.26f, h * 0.12f),
                    size = Size(w * 0.48f, h * 0.76f),
                    cornerRadius = CornerRadius(w * 0.09f, w * 0.09f),
                    style = stroke
                )
                drawCircle(color = tint, radius = sw * 0.55f, center = Offset(w * 0.5f, h * 0.76f))
            }
            IconKind.File -> {
                val p = Path().apply {
                    moveTo(w * 0.24f, h * 0.14f)
                    lineTo(w * 0.58f, h * 0.14f)
                    lineTo(w * 0.78f, h * 0.34f)
                    lineTo(w * 0.78f, h * 0.86f)
                    lineTo(w * 0.24f, h * 0.86f)
                    close()
                }
                drawPath(path = p, color = tint, style = stroke)
                drawLine(
                    color = tint,
                    start = Offset(w * 0.36f, h * 0.54f),
                    end = Offset(w * 0.66f, h * 0.54f),
                    strokeWidth = sw,
                    cap = StrokeCap.Round
                )
                drawLine(
                    color = tint,
                    start = Offset(w * 0.36f, h * 0.68f),
                    end = Offset(w * 0.56f, h * 0.68f),
                    strokeWidth = sw,
                    cap = StrokeCap.Round
                )
            }
            IconKind.Image -> {
                drawRoundRect(
                    color = tint,
                    topLeft = Offset(w * 0.14f, h * 0.18f),
                    size = Size(w * 0.72f, h * 0.64f),
                    cornerRadius = CornerRadius(w * 0.08f, w * 0.08f),
                    style = stroke
                )
                drawCircle(color = tint, radius = sw * 0.75f, center = Offset(w * 0.34f, h * 0.38f))
                val m = Path().apply {
                    moveTo(w * 0.20f, h * 0.76f)
                    lineTo(w * 0.46f, h * 0.52f)
                    lineTo(w * 0.62f, h * 0.66f)
                    lineTo(w * 0.74f, h * 0.54f)
                    lineTo(w * 0.84f, h * 0.76f)
                }
                drawPath(path = m, color = tint, style = stroke)
            }
            IconKind.Link -> {
                drawArc(
                    color = tint,
                    startAngle = 120f,
                    sweepAngle = 200f,
                    useCenter = false,
                    topLeft = Offset(w * 0.14f, h * 0.28f),
                    size = Size(w * 0.44f, h * 0.44f),
                    style = stroke
                )
                drawArc(
                    color = tint,
                    startAngle = -60f,
                    sweepAngle = 200f,
                    useCenter = false,
                    topLeft = Offset(w * 0.42f, h * 0.28f),
                    size = Size(w * 0.44f, h * 0.44f),
                    style = stroke
                )
                drawLine(
                    color = tint,
                    start = Offset(w * 0.36f, h * 0.50f),
                    end = Offset(w * 0.64f, h * 0.50f),
                    strokeWidth = sw,
                    cap = StrokeCap.Round
                )
            }
            IconKind.Folder -> {
                val p = Path().apply {
                    moveTo(w * 0.12f, h * 0.24f)
                    lineTo(w * 0.40f, h * 0.24f)
                    lineTo(w * 0.48f, h * 0.34f)
                    lineTo(w * 0.88f, h * 0.34f)
                    lineTo(w * 0.88f, h * 0.80f)
                    lineTo(w * 0.12f, h * 0.80f)
                    close()
                }
                drawPath(path = p, color = tint, style = stroke)
            }
            IconKind.Refresh -> {
                drawArc(
                    color = tint,
                    startAngle = -35f,
                    sweepAngle = 285f,
                    useCenter = false,
                    topLeft = Offset(w * 0.18f, h * 0.18f),
                    size = Size(w * 0.64f, h * 0.64f),
                    style = stroke
                )
                val arrow = Path().apply {
                    moveTo(w * 0.62f, h * 0.16f)
                    lineTo(w * 0.82f, h * 0.22f)
                    lineTo(w * 0.74f, h * 0.40f)
                }
                drawPath(path = arrow, color = tint, style = stroke)
            }
            IconKind.Sliders -> {
                for (row in 0..2) {
                    val y = h * (0.26f + row * 0.24f)
                    drawLine(
                        color = tint,
                        start = Offset(w * 0.16f, y),
                        end = Offset(w * 0.84f, y),
                        strokeWidth = sw,
                        cap = StrokeCap.Round
                    )
                    val knobX = if (row == 1) w * 0.64f else w * 0.36f
                    drawCircle(color = tint, radius = sw * 1.15f, center = Offset(knobX, y))
                }
            }
            IconKind.Download -> {
                drawLine(
                    color = tint,
                    start = Offset(w * 0.5f, h * 0.16f),
                    end = Offset(w * 0.5f, h * 0.66f),
                    strokeWidth = sw,
                    cap = StrokeCap.Round
                )
                val arrow = Path().apply {
                    moveTo(w * 0.32f, h * 0.50f)
                    lineTo(w * 0.50f, h * 0.68f)
                    lineTo(w * 0.68f, h * 0.50f)
                }
                drawPath(path = arrow, color = tint, style = stroke)
                drawLine(
                    color = tint,
                    start = Offset(w * 0.22f, h * 0.84f),
                    end = Offset(w * 0.78f, h * 0.84f),
                    strokeWidth = sw,
                    cap = StrokeCap.Round
                )
            }
            IconKind.Upload -> {
                drawLine(
                    color = tint,
                    start = Offset(w * 0.5f, h * 0.68f),
                    end = Offset(w * 0.5f, h * 0.18f),
                    strokeWidth = sw,
                    cap = StrokeCap.Round
                )
                val arrow = Path().apply {
                    moveTo(w * 0.32f, h * 0.36f)
                    lineTo(w * 0.50f, h * 0.18f)
                    lineTo(w * 0.68f, h * 0.36f)
                }
                drawPath(path = arrow, color = tint, style = stroke)
                drawLine(
                    color = tint,
                    start = Offset(w * 0.22f, h * 0.84f),
                    end = Offset(w * 0.78f, h * 0.84f),
                    strokeWidth = sw,
                    cap = StrokeCap.Round
                )
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
