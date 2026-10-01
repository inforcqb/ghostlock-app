package com.ghostlock.app.ui.wireless

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.os.Bundle
import android.text.InputType
import android.util.TypedValue
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import com.ghostlock.app.R
import com.ghostlock.app.wireless.WirelessPairingController
import com.ghostlock.app.wireless.WirelessState
import com.ghostlock.app.wireless.WirelessStateListener

/**
 * The wireless-debugging screen: the new uid-2000 channel, without Magica, `am hang` or
 * Shizuku.
 *
 * Shape of the screen follows the agreed UI rule: while nothing is paired there is
 * exactly ONE control -- "open wireless debugging" -- which jumps to the system page and
 * arms the pairing-code notification. Everything else (connect, forget, and the manual
 * code field that only exists when notifications are unavailable) appears only once it
 * is relevant. The log below is read-only and is the evidence trail for this path.
 *
 * Plain views on purpose: this is a diagnostic screen and it must not depend on the
 * Compose/miuix UI that a later round is going to cut down anyway.
 */
class WirelessDebuggingActivity : ComponentActivity() {
    private lateinit var statusView: TextView
    private lateinit var identityView: TextView
    private lateinit var openButton: Button
    private lateinit var connectButton: Button
    private lateinit var forgetButton: Button
    private lateinit var manualHint: TextView
    private lateinit var manualRow: LinearLayout
    private lateinit var manualInput: EditText
    private lateinit var logView: TextView

    private val listener = WirelessStateListener { state -> render(state) }

    private val notificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted -> onNotificationPermission(granted) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WirelessPairingController.load(this)
        setContentView(buildContentView())
        WirelessPairingController.addListener(listener)
        render(WirelessPairingController.state)
    }

    override fun onDestroy() {
        WirelessPairingController.removeListener(listener)
        super.onDestroy()
    }

    override fun onResume() {
        super.onResume()
        /* The pairing notification can be submitted while this screen is in the
         * background; re-render so log and buttons are current on return. */
        render(WirelessPairingController.state)
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
        if (granted) {
            jumpAndArmPairing()
        } else {
            /* Without notifications there is nowhere to type the code, so the screen
             * falls back to an in-app field: the only case where a second control
             * exists before pairing. */
            WirelessPairingController.startPairing(this)
            render(WirelessPairingController.state)
        }
    }

    /**
     * Jump to the wireless-debugging page, then arm the code notification.
     *
     * Order matters: the `_adb-tls-pairing` service only exists while the system's
     * pairing dialog is open, so the notification has to be waiting before the user
     * opens that dialog.
     */
    private fun jumpAndArmPairing() {
        WirelessPairingController.openWirelessDebuggingSettings(this)
        WirelessPairingController.startPairing(this)
        render(WirelessPairingController.state)
    }

    private fun canPostNotifications(): Boolean =
        checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED

    // ------------------------------------------------------------------ rendering

    private fun render(state: WirelessState) {
        statusView.text = state.status.ifEmpty {
            getString(
                if (state.paired) R.string.wireless_status_paired
                else R.string.wireless_status_unpaired,
            )
        }
        identityView.text = if (state.identity.isEmpty()) {
            ""
        } else {
            getString(R.string.wireless_identity_format, state.identity, state.seccomp)
        }
        identityView.visibility = if (state.identity.isEmpty()) View.GONE else View.VISIBLE

        openButton.isEnabled = !state.busy

        val pairedVisibility = if (state.paired) View.VISIBLE else View.GONE
        connectButton.visibility = pairedVisibility
        connectButton.isEnabled = !state.busy
        forgetButton.visibility = pairedVisibility
        forgetButton.isEnabled = !state.busy

        val manualVisibility = if (canPostNotifications()) View.GONE else View.VISIBLE
        manualHint.visibility = manualVisibility
        manualRow.visibility = manualVisibility

        logView.text = state.log.joinToString("\n")
    }

    // ------------------------------------------------------------------ layout

    private fun buildContentView(): View {
        val root = ScrollView(this)
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(24), dp(20), dp(24))
        }
        root.addView(column)

        column.addView(
            TextView(this).apply {
                text = getString(R.string.wireless_screen_title)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
                setTypeface(typeface, Typeface.BOLD)
            },
        )

        statusView = TextView(this).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
            setPadding(0, dp(12), 0, 0)
        }
        column.addView(statusView)

        identityView = TextView(this).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setPadding(0, dp(8), 0, 0)
            typeface = Typeface.MONOSPACE
        }
        column.addView(identityView)

        openButton = Button(this).apply {
            text = getString(R.string.wireless_open_wireless_debugging)
            setOnClickListener { onOpenWirelessDebugging() }
        }
        column.addView(openButton, matchWidth(top = 16))

        connectButton = Button(this).apply {
            text = getString(R.string.wireless_connect_and_verify)
            visibility = View.GONE
            setOnClickListener { WirelessPairingController.connectAndVerify(this@WirelessDebuggingActivity) }
        }
        column.addView(connectButton, matchWidth(top = 8))

        forgetButton = Button(this).apply {
            text = getString(R.string.wireless_forget)
            visibility = View.GONE
            setOnClickListener {
                WirelessPairingController.forget(this@WirelessDebuggingActivity)
                render(WirelessPairingController.state)
            }
        }
        column.addView(forgetButton, matchWidth(top = 8))

        manualHint = TextView(this).apply {
            text = getString(R.string.wireless_manual_code_hint)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setPadding(0, dp(12), 0, 0)
            visibility = View.GONE
        }
        column.addView(manualHint)

        manualRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            visibility = View.GONE
        }
        manualInput = EditText(this).apply {
            hint = getString(R.string.wireless_pairing_code_label)
            inputType = InputType.TYPE_CLASS_NUMBER
            isSingleLine = true
        }
        manualRow.addView(
            manualInput,
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f),
        )
        manualRow.addView(
            Button(this).apply {
                text = getString(R.string.wireless_manual_code_submit)
                setOnClickListener {
                    val code = manualInput.text?.toString().orEmpty()
                    manualInput.setText("")
                    WirelessPairingController.submitCode(this@WirelessDebuggingActivity, code)
                }
            },
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { leftMargin = dp(8) },
        )
        column.addView(manualRow, matchWidth(top = 8))

        column.addView(
            TextView(this).apply {
                text = getString(R.string.wireless_log_title)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
                setPadding(0, dp(20), 0, dp(6))
            },
        )

        logView = TextView(this).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
        }
        column.addView(logView)

        return root
    }

    private fun matchWidth(top: Int): LinearLayout.LayoutParams =
        LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(top) }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}
