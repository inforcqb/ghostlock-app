package com.ghostlock.app.ui.wireless

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.WindowInsetsController
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.ghostlock.app.R
import com.ghostlock.app.wireless.WirelessPairingController
import com.ghostlock.app.wireless.WirelessState
import com.ghostlock.app.wireless.WirelessStateListener
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.darkColorScheme
import top.yukonga.miuix.kmp.theme.lightColorScheme

/**
 * The wireless-debugging screen: the uid-2000 channel, without Magica, `am hang` or Shizuku.
 *
 * This class is only the host -- state, the notification permission and the system bars. The
 * screen itself is [WirelessScreen], in the app's own miuix theme, so this page and the main
 * screen finally look like one app (it used to be a stack of stock widgets on purpose, back
 * when the path was nothing but a diagnostic).
 *
 * Shape of the screen still follows the agreed UI rule: while nothing is paired there is
 * exactly ONE control ("open wireless debugging"), which jumps to the system page and arms the
 * pairing-code notification. Connect / forget, the manual code field (only when notifications
 * cannot be posted) and the identity card appear once they are relevant. The log at the bottom
 * is the evidence trail for this path.
 */
class WirelessDebuggingActivity : ComponentActivity() {

    private var state by mutableStateOf(WirelessState())

    private var notificationsAvailable by mutableStateOf(true)

    private val listener = WirelessStateListener { next -> state = next }

    private val notificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted -> onNotificationPermission(granted) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WirelessPairingController.load(this)
        notificationsAvailable = canPostNotifications()
        state = WirelessPairingController.state

        setContent {
            MiuixTheme(
                colors = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme(),
            ) {
                WirelessScreen(
                    state = state,
                    notificationsAvailable = notificationsAvailable,
                    onBack = { finish() },
                    onOpen = { onOpenWirelessDebugging() },
                    onConnect = { WirelessPairingController.connectAndVerify(this) },
                    onForget = {
                        WirelessPairingController.forget(this)
                        state = WirelessPairingController.state
                    },
                    onSubmitCode = { code -> WirelessPairingController.submitCode(this, code) },
                )
            }
        }
        setupSystemBars()
        WirelessPairingController.addListener(listener)
    }

    override fun onDestroy() {
        WirelessPairingController.removeListener(listener)
        super.onDestroy()
    }

    override fun onResume() {
        super.onResume()
        /* The pairing notification can be submitted while this screen is in the background;
         * re-render so the log and the buttons are current on return -- and re-read the
         * permission, because the user may have granted it in Settings. */
        notificationsAvailable = canPostNotifications()
        state = WirelessPairingController.state
    }

    // ------------------------------------------------------------------ actions

    private fun onOpenWirelessDebugging() {
        if (canPostNotifications()) {
            jumpAndArmPairing()
            return
        }
        notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    private fun onNotificationPermission(granted: Boolean) {
        notificationsAvailable = granted
        if (granted) {
            jumpAndArmPairing()
        } else {
            /* Without notifications there is nowhere to type the code, so the screen falls
             * back to the in-app field: the only case where a second control exists before
             * pairing. */
            WirelessPairingController.startPairing(this)
            state = WirelessPairingController.state
        }
    }

    /**
     * Jump to the wireless-debugging page, then arm the code notification.
     *
     * Order matters: the `_adb-tls-pairing` service only exists while the system's pairing
     * dialog is open, so the notification has to be waiting before the user opens that dialog.
     */
    private fun jumpAndArmPairing() {
        WirelessPairingController.openWirelessDebuggingSettings(this)
        WirelessPairingController.startPairing(this)
        state = WirelessPairingController.state
    }

    private fun canPostNotifications(): Boolean =
        checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED

    /** Same bar treatment as [com.ghostlock.app.ui.MainActivity]. */
    private fun setupSystemBars() {
        val controller = window.decorView.windowInsetsController ?: return
        val lightStatus = if (resources.getBoolean(R.bool.window_light_status_bar)) {
            WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
        } else {
            0
        }
        val lightNavigation = if (resources.getBoolean(R.bool.window_light_navigation_bar)) {
            WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS
        } else {
            0
        }
        controller.setSystemBarsAppearance(
            lightStatus or lightNavigation,
            WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or
                WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS,
        )
    }
}
