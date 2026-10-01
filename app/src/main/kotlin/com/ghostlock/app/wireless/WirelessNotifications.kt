package com.ghostlock.app.wireless

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.RemoteInput
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Icon
import android.util.Log
import com.ghostlock.app.R
import com.ghostlock.app.ui.wireless.WirelessDebuggingActivity

/**
 * The pairing-code input, as a notification with a direct reply.
 *
 * Why a notification instead of a dialog: the six-digit code only exists while the
 * system's "Pair device with pairing code" screen is open, so the user is inside
 * Settings when the code appears. A notification they can type into from the shade
 * means they never have to switch back to the app.
 */
object WirelessNotifications {
    const val REPLY_KEY = "com.ghostlock.app.PAIRING_CODE"
    const val ACTION_PAIRING_CODE = "com.ghostlock.app.action.PAIRING_CODE"

    private const val CHANNEL_ID = "ghostlock-wireless"
    private const val REQUEST_PAIRING_CODE = 0x61

    private const val ID_CODE_INPUT = 0x91
    private const val ID_STATUS = 0x92

    /** Whether the app may post notifications at all (API 33+ runtime permission). */
    fun canPost(context: Context): Boolean =
        context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED

    fun ensureChannel(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.wireless_channel_name),
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = context.getString(R.string.wireless_channel_description)
        }
        manager.createNotificationChannel(channel)
    }

    /**
     * Ask for the pairing code. `FLAG_MUTABLE` is required: an immutable PendingIntent
     * cannot carry a RemoteInput reply on Android 12+.
     */
    fun showCodeInput(context: Context, text: String) {
        ensureChannel(context)
        val reply = RemoteInput.Builder(REPLY_KEY)
            .setLabel(context.getString(R.string.wireless_pairing_code_label))
            .build()
        val intent = Intent(context, PairingCodeReceiver::class.java).setAction(ACTION_PAIRING_CODE)
        val pending = PendingIntent.getBroadcast(
            context,
            REQUEST_PAIRING_CODE,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
        )
        val action = Notification.Action.Builder(
            Icon.createWithResource(context, R.drawable.ic_launcher_monochrome),
            context.getString(R.string.wireless_pairing_code_action),
            pending,
        ).addRemoteInput(reply).build()
        val notification = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_monochrome)
            .setContentTitle(context.getString(R.string.wireless_pairing_code_title))
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setOngoing(true)
            .addAction(action)
            .build()
        notify(context, ID_CODE_INPUT, notification)
    }

    /** Plain progress/result notification; tapping it opens the wireless screen. */
    fun showStatus(context: Context, title: String, text: String) {
        ensureChannel(context)
        val intent = Intent(context, WirelessDebuggingActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        val pending = PendingIntent.getActivity(
            context,
            REQUEST_PAIRING_CODE + 1,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_monochrome)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(pending)
            .setAutoCancel(true)
            .build()
        notify(context, ID_STATUS, notification)
    }

    fun cancelCodeInput(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        runCatching { manager.cancel(ID_CODE_INPUT) }
    }

    fun cancelAll(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        runCatching {
            manager.cancel(ID_CODE_INPUT)
            manager.cancel(ID_STATUS)
        }
    }

    /** The code the user typed into the notification's reply field. */
    fun pairingCodeFrom(intent: Intent?): String? {
        val results = RemoteInput.getResultsFromIntent(intent ?: return null) ?: return null
        return results.getCharSequence(REPLY_KEY)?.toString()?.trim()?.takeIf { it.isNotEmpty() }
    }

    private fun notify(context: Context, id: Int, notification: Notification) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        runCatching { manager.notify(id, notification) }
            .onFailure { Log.w(WirelessAdb.TAG, "notify($id) failed: ${it.message}") }
    }
}
