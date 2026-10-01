package com.ghostlock.app.ui.wireless

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
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircleOutline
import androidx.compose.material.icons.rounded.RemoveCircleOutline
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghostlock.app.R
import com.ghostlock.app.domain.model.LogTone
import com.ghostlock.app.domain.usecase.FormatLogUseCase
import com.ghostlock.app.ui.GhostlockLogLine
import com.ghostlock.app.ui.LogPanel
import com.ghostlock.app.wireless.WirelessState
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.basic.rememberTopAppBarState
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.icon.extended.Copy
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * The wireless-debugging screen, in the app's own visual language.
 *
 * It used to be a stack of stock `TextView`/`Button` widgets -- deliberately plain, from the
 * round where this path was only a diagnostic. It is the normal way into the chain now, so it
 * uses the same miuix theme as the main screen:
 *
 *  1. a **status card** in the app's palette (amber = not paired, blue = paired, green =
 *     channel ready) with the big state icon in the corner, exactly like the activation card
 *     on the main screen;
 *  2. an **action card** with the one control that matters right now (open wireless
 *     debugging), plus connect/self-check and forget once something is paired;
 *  3. the **manual code field** only when notifications are unavailable (there is nowhere
 *     else to type the code then);
 *  4. the **identity card** (uid / endpoint / `Seccomp`), monospaced;
 *  5. the **log** in the app's log panel, same dark surface and the same tone colours as the
 *     one-click-root run, with a copy button.
 */
@Composable
internal fun WirelessScreen(
    state: WirelessState,
    notificationsAvailable: Boolean,
    onBack: () -> Unit,
    onOpen: () -> Unit,
    onConnect: () -> Unit,
    onForget: () -> Unit,
    onSubmitCode: (String) -> Unit,
) {
    val scrollBehavior = MiuixScrollBehavior(rememberTopAppBarState())
    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = stringResource(R.string.wireless_screen_title),
                scrollBehavior = scrollBehavior,
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = MiuixIcons.Back,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp)
                .padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            ChannelStatusCard(state = state)
            WirelessActionCard(
                state = state,
                onOpen = onOpen,
                onConnect = onConnect,
                onForget = onForget,
            )
            if (!notificationsAvailable) {
                ManualCodeCard(onSubmitCode = onSubmitCode)
            }
            ChannelIdentityCard(state = state)
            WirelessLogCard(log = state.log)
        }
    }
}

/** Big coloured state card: the same palette as the activation card on the main screen. */
@Composable
private fun ChannelStatusCard(state: WirelessState) {
    val dark = isSystemInDarkTheme()
    val ready = state.shellReady
    val paired = state.paired
    val cardColor = when {
        ready -> if (dark) Color(0xFF173923) else Color(0xFFDFFAE4)
        paired -> if (dark) Color(0xFF16243A) else Color(0xFFDCE9FF)
        else -> if (dark) Color(0xFF3B2715) else Color(0xFFFFF1D6)
    }
    val accent = when {
        ready -> if (dark) Color(0xFF62D783) else Color(0xFF36D167)
        paired -> if (dark) Color(0xFF7AB6FF) else Color(0xFF2563EB)
        else -> if (dark) Color(0xFFFFC56C) else Color(0xFFF5A623)
    }
    val titleRes = when {
        ready -> R.string.wireless_status_ready
        paired -> R.string.wireless_status_paired
        else -> R.string.wireless_status_unpaired
    }
    val hint = state.status.ifEmpty {
        stringResource(
            if (paired) R.string.wireless_screen_paired else R.string.wireless_screen_unpaired,
        )
    }
    Card(colors = CardDefaults.defaultColors(color = cardColor)) {
        Box(modifier = Modifier.fillMaxWidth().height(132.dp)) {
            Column(
                modifier = Modifier
                    .align(Alignment.TopStart)
                    .padding(start = 16.dp, top = 14.dp, end = 96.dp),
            ) {
                Text(
                    text = stringResource(titleRes),
                    fontSize = 22.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = MiuixTheme.colorScheme.onSurface,
                )
                Text(
                    text = hint,
                    modifier = Modifier.padding(top = 6.dp),
                    fontSize = 14.sp,
                    lineHeight = 19.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
            Icon(
                imageVector = if (paired || ready) {
                    Icons.Rounded.CheckCircleOutline
                } else {
                    Icons.Rounded.RemoveCircleOutline
                },
                contentDescription = null,
                tint = accent,
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .offset(x = 27.dp, y = 31.dp)
                    .size(110.dp),
            )
        }
    }
}

@Composable
private fun WirelessActionCard(
    state: WirelessState,
    onOpen: () -> Unit,
    onConnect: () -> Unit,
    onForget: () -> Unit,
) {
    Card(insideMargin = PaddingValues(16.dp)) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            TextButton(
                text = stringResource(R.string.wireless_open_wireless_debugging),
                onClick = onOpen,
                enabled = !state.busy,
                colors = ButtonDefaults.textButtonColorsPrimary(),
                modifier = Modifier.fillMaxWidth(),
            )
            if (state.paired) {
                TextButton(
                    text = stringResource(R.string.wireless_connect_and_verify),
                    onClick = onConnect,
                    enabled = !state.busy,
                    modifier = Modifier.fillMaxWidth(),
                )
                TextButton(
                    text = stringResource(R.string.wireless_forget),
                    onClick = onForget,
                    enabled = !state.busy,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}

/** Only shown when the system cannot post our pairing-code notification. */
@Composable
private fun ManualCodeCard(onSubmitCode: (String) -> Unit) {
    var code by remember { mutableStateOf("") }
    Card(insideMargin = PaddingValues(16.dp)) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = stringResource(R.string.wireless_manual_code_hint),
                fontSize = 14.sp,
                lineHeight = 19.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                TextField(
                    value = code,
                    onValueChange = { value -> code = value.filter(Char::isDigit).take(6) },
                    label = stringResource(R.string.wireless_pairing_code_label),
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                )
                Spacer(modifier = Modifier.width(10.dp))
                TextButton(
                    text = stringResource(R.string.wireless_manual_code_submit),
                    onClick = {
                        val submitted = code
                        code = ""
                        onSubmitCode(submitted)
                    },
                    enabled = code.length >= 6,
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                )
            }
        }
    }
}

@Composable
private fun ChannelIdentityCard(state: WirelessState) {
    if (state.identity.isEmpty() && state.endpoint.isEmpty()) return
    Card(insideMargin = PaddingValues(16.dp)) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text(
                text = stringResource(R.string.wireless_identity_title),
                fontSize = 18.sp,
                fontWeight = FontWeight.Medium,
                color = MiuixTheme.colorScheme.onSurface,
            )
            if (state.identity.isNotEmpty()) {
                IdentityItem(
                    title = stringResource(R.string.wireless_shell_identity_label),
                    value = state.identity,
                )
                IdentityItem(
                    title = stringResource(R.string.wireless_seccomp_label),
                    value = state.seccomp.toString(),
                )
            }
            if (state.endpoint.isNotEmpty()) {
                IdentityItem(
                    title = stringResource(R.string.wireless_endpoint_label),
                    value = state.endpoint,
                )
            }
        }
    }
}

@Composable
private fun IdentityItem(title: String, value: String) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = title,
            fontSize = 14.sp,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
        )
        Text(
            text = value,
            modifier = Modifier.padding(top = 2.dp),
            fontSize = 13.sp,
            fontFamily = FontFamily.Monospace,
            color = MiuixTheme.colorScheme.onSurface,
        )
    }
}

/**
 * The run log, in the app's own panel (dark surface, tone colours) so it looks like the log
 * of a one-click-root run -- plus a copy button, because this log is the evidence trail for
 * the channel.
 */
@Composable
private fun WirelessLogCard(log: List<String>) {
    val context = LocalContext.current
    val lines: List<GhostlockLogLine> = remember(log) {
        val format = FormatLogUseCase()
        log.map { raw ->
            val entry = format(raw)
            GhostlockLogLine(entry.text.trimEnd('\r', '\n'), toneColor(entry.tone))
        }
    }
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = stringResource(R.string.wireless_log_title),
                modifier = Modifier.weight(1f),
                fontSize = 16.sp,
                fontWeight = FontWeight.Medium,
                color = MiuixTheme.colorScheme.onSurface,
            )
            IconButton(
                onClick = {
                    val clipboard = context.getSystemService(android.content.ClipboardManager::class.java)
                    clipboard?.setPrimaryClip(
                        android.content.ClipData.newPlainText("ghostlock-wireless", log.joinToString("\n")),
                    )
                },
            ) {
                Icon(
                    imageVector = MiuixIcons.Copy,
                    contentDescription = stringResource(R.string.action_copy),
                    tint = MiuixTheme.colorScheme.onBackground,
                )
            }
        }
        LogPanel(
            lines = lines,
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 200.dp, max = 420.dp),
        )
    }
}

/** The log panel's palette (`GhostlockUi.lineColor`), keyed by the parsed tone. */
private fun toneColor(tone: LogTone): Int = when (tone) {
    LogTone.Error -> 0xFFFF6B6B.toInt()
    LogTone.Success -> 0xFF5FD68A.toInt()
    LogTone.Warning -> 0xFFFFC94D.toInt()
    LogTone.Progress -> 0xFF60A5FA.toInt()
    LogTone.Default -> 0xFFD1D5DB.toInt()
}
