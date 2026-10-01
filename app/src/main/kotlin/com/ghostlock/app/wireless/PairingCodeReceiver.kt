package com.ghostlock.app.wireless

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Receives the pairing code typed into the notification's reply field and hands it to
 * [WirelessPairingController], which does the mDNS discovery and the pairing handshake
 * off the main thread.
 */
class PairingCodeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val code = WirelessNotifications.pairingCodeFrom(intent) ?: return
        WirelessPairingController.submitCode(context.applicationContext, code)
    }
}
