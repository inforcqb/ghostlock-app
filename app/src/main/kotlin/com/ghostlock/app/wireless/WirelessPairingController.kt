package com.ghostlock.app.wireless

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.Log
import com.ghostlock.app.R
import io.github.muntashirakon.adb.AdbConnection
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Everything the wireless-debugging path knows, as one immutable snapshot.
 *
 * [shellReady] is the answer the chain actually needs: a shell whose `id` says
 * `uid=2000` and whose `/proc/self/status` says `Seccomp: 0`, because the W1 engine
 * refuses to run under a seccomp filter.
 */
data class WirelessState(
    val paired: Boolean = false,
    val busy: Boolean = false,
    val status: String = "",
    val log: List<String> = emptyList(),
    val endpoint: String = "",
    val identity: String = "",
    val shellUid: String = "",
    val seccomp: Int = -1,
    val shellReady: Boolean = false,
)

fun interface WirelessStateListener {
    fun onState(state: WirelessState)
}

/**
 * Drives the wireless-debugging channel: pair (mDNS `_adb-tls-pairing` + the code from
 * the notification), connect (mDNS `_adb-tls-connect`, TLS + AUTH with the paired key),
 * then prove the channel is usable (`id` -> uid 2000, `Seccomp: 0`).
 *
 * Deliberately free of any uid-0 machinery: pairing is what authorizes our key, so this
 * path never runs `fork`/`setresuid(1000)`/`_exit` to append to `/data/misc/adb/adb_keys`.
 *
 * State changes are delivered on the main thread, so the screen can render them directly.
 */
object WirelessPairingController {
    private const val PREFS = "ghostlock-wireless"
    private const val KEY_PAIRED = "paired"
    private const val KEY_PAIRED_AT = "paired_at"
    private const val KEY_ENDPOINT = "endpoint"

    private const val PAIRING_DISCOVERY_TIMEOUT_MS = 30_000L
    private const val CONNECT_DISCOVERY_TIMEOUT_MS = 20_000L
    private const val PAIRING_TIMEOUT_MS = 60_000L
    private const val MAX_LOG_LINES = 200

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val listeners = CopyOnWriteArrayList<WirelessStateListener>()
    private val main = Handler(Looper.getMainLooper())
    private val lock = Any()

    private var current = WirelessState()
    private var connection: AdbConnection? = null

    val state: WirelessState
        get() = synchronized(lock) { current }

    fun addListener(listener: WirelessStateListener) {
        listeners.addIfAbsent(listener)
        listener.onState(state)
    }

    fun removeListener(listener: WirelessStateListener) {
        listeners.remove(listener)
    }

    /** Read the persisted pairing so a restart does not ask for the code again. */
    fun load(context: Context) {
        val prefs = prefs(context)
        val paired = prefs.getBoolean(KEY_PAIRED, false)
        val endpoint = prefs.getString(KEY_ENDPOINT, "").orEmpty()
        mutate { it.copy(paired = paired, endpoint = endpoint) }
    }

    /**
     * Post the pairing-code notification.
     *
     * The wireless-debugging *pairing* service only exists while the system's pairing
     * dialog is open, so this is paired with a jump to that screen; the code is entered
     * from the notification shade.
     */
    fun startPairing(context: Context): Boolean {
        if (!WirelessNotifications.canPost(context)) {
            log("通知权限未授予 ⇒ 无法在通知里输入配对码，改用页面内的输入框")
            mutate { it.copy(status = context.getString(R.string.wireless_manual_code_hint)) }
            return false
        }
        WirelessNotifications.showCodeInput(
            context,
            context.getString(R.string.wireless_pairing_code_hint),
        )
        mutate { it.copy(status = context.getString(R.string.wireless_waiting_code)) }
        return true
    }

    /** Called from the notification receiver with the code the user typed. */
    fun submitCode(context: Context, code: String) {
        if (state.busy) {
            log("上一轮操作尚未结束，忽略这次配对码输入")
            return
        }
        WirelessNotifications.cancelCodeInput(context)
        log("收到配对码（${code.trim().length} 位）")
        val app = context.applicationContext
        scope.launch { pairFlow(app, code) }
    }

    /** Connect to `_adb-tls-connect` and prove uid 2000 + `Seccomp: 0`. */
    fun connectAndVerify(context: Context) {
        if (state.busy) {
            log("上一轮操作尚未结束，忽略这次连接请求")
            return
        }
        val app = context.applicationContext
        scope.launch { connectFlow(app) }
    }

    fun forget(context: Context) {
        prefs(context).edit().clear().apply()
        WirelessAdb.closeQuietly(connection)
        connection = null
        mutate {
            it.copy(
                paired = false,
                endpoint = "",
                identity = "",
                shellUid = "",
                seccomp = -1,
                shellReady = false,
                status = "",
            )
        }
        log("已清除本机的配对记录（adbd 侧的密钥仍在）")
    }

    /** Exposed for the chain: run one command on the already-verified channel. */
    fun runShell(command: String, timeoutMs: Long = 30_000L): String {
        val active = connection ?: throw IllegalStateException("无线调试通道尚未连接")
        return WirelessAdb.shell(active, command, timeoutMs)
    }

    fun close() {
        WirelessAdb.closeQuietly(connection)
        connection = null
    }

    /**
     * Jump to the system's wireless-debugging page.
     *
     * Attempts, in the order that is most likely to land on the right screen, each one
     * validated with `resolveActivity` and wrapped so a missing activity cannot crash:
     * the AOSP/OPPO component, the semantic action, the developer-options component, then
     * the developer-options action. On the PJA110 (ColorOS) only the last two resolve --
     * its Settings.apk has no wireless-debugging activity at all (checked on the device:
     * 196 `Settings$*` activities, none of them WifiDebugging/WirelessDebugging), so the
     * page lives inside developer options and the user has to scroll to it; the log says so.
     *
     * Returns which attempt worked, or null when the user has to navigate by hand.
     */
    fun openWirelessDebuggingSettings(context: Context): String? {
        val attempts = listOf(
            "component" to Intent().setComponent(
                ComponentName(
                    "com.android.settings",
                    "com.android.settings.Settings\$WifiDebuggingActivity",
                ),
            ),
            "action" to Intent("android.settings.WIRELESS_DEBUGGING_SETTINGS"),
            "development-component" to Intent().setComponent(
                ComponentName(
                    "com.android.settings",
                    "com.android.settings.Settings\$DevelopmentSettingsDashboardActivity",
                ),
            ),
            "developer-options" to Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS),
        )
        for ((label, intent) in attempts) {
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            val resolved = runCatching {
                context.packageManager.resolveActivity(intent, 0)
            }.getOrNull()
            if (resolved == null) {
                log("跳转尝试「$label」未解析到界面")
                continue
            }
            val started = runCatching { context.startActivity(intent) }.isSuccess
            if (started) {
                log("跳转无线调试成功：$label -> ${resolved.activityInfo?.name}")
                if (label.startsWith("development") || label == "developer-options") {
                    log(context.getString(R.string.wireless_jump_hint))
                }
                return label
            }
            log("跳转尝试「$label」启动失败")
        }
        log(context.getString(R.string.wireless_settings_jump_failed))
        return null
    }

    // ---------------------------------------------------------------- internals

    private fun pairFlow(context: Context, code: String) {
        mutate { it.copy(busy = true, status = context.getString(R.string.wireless_pairing_busy)) }
        try {
            log("查找 ${WirelessAdb.SERVICE_PAIRING} ...")
            val endpoint = WirelessAdb.discover(
                context,
                WirelessAdb.SERVICE_PAIRING,
                PAIRING_DISCOVERY_TIMEOUT_MS,
            )
            if (endpoint == null) {
                markFailed(context, context.getString(R.string.wireless_pair_no_service))
                return
            }
            log("配对端点 $endpoint")
            WirelessAdb.pair(context, endpoint, code, PAIRING_TIMEOUT_MS)
            savePaired(context, endpoint)
            mutate { it.copy(paired = true, endpoint = endpoint.toString()) }
            log("配对成功：adbd 已登记本应用的公钥（无需 setuid 写 adb_keys）")
            /* Release the code-input notification the moment the pairing is done: it is
             * the prompt for a code that no longer matters, and leaving it in the shade
             * was reported as "pair succeeded but the notification was never released".
             * Exactly one result notification is posted, at the end of the flow. */
            WirelessNotifications.cancelCodeInput(context)
            connectFlow(context, alreadyBusy = true)
        } catch (error: Throwable) {
            markFailed(context, "配对失败：${error::class.simpleName}: ${error.message}")
        } finally {
            mutate { it.copy(busy = false) }
        }
    }

    private fun connectFlow(context: Context, alreadyBusy: Boolean = false) {
        if (!alreadyBusy) {
            mutate {
                it.copy(busy = true, status = context.getString(R.string.wireless_connecting_busy))
            }
        } else {
            mutate { it.copy(status = context.getString(R.string.wireless_connecting_busy)) }
        }
        try {
            log("查找 ${WirelessAdb.SERVICE_CONNECT} ...")
            val endpoint = WirelessAdb.discover(
                context,
                WirelessAdb.SERVICE_CONNECT,
                CONNECT_DISCOVERY_TIMEOUT_MS,
            )
            if (endpoint == null) {
                markFailed(context, context.getString(R.string.wireless_connect_no_service))
                return
            }
            log("连接端点 $endpoint")
            val established = WirelessAdb.connect(context, endpoint)
            WirelessAdb.closeQuietly(connection)
            connection = established
            log("adb 已连接（TLS + AUTH，用的是配对登记的密钥）")

            val identity = WirelessAdb.shell(established, "id").trim()
            log("$ id\n$identity")
            val status = WirelessAdb.shell(established, "cat /proc/self/status")
            val seccomp = Regex("Seccomp:\\s*(\\d+)").find(status)?.groupValues?.get(1)?.toIntOrNull() ?: -1
            val uid = Regex("Uid:\\s*(\\d+)").find(status)?.groupValues?.get(1).orEmpty()
            log("通道身份：uid=$uid Seccomp=$seccomp")
            val ready = identity.contains("uid=2000") && seccomp == 0
            mutate {
                it.copy(
                    shellReady = ready,
                    identity = identity,
                    shellUid = uid,
                    seccomp = seccomp,
                    status = if (ready) {
                        context.getString(R.string.wireless_shell_ready, identity, seccomp)
                    } else {
                        context.getString(R.string.wireless_shell_not_ready, identity, seccomp)
                    },
                )
            }
            if (ready) {
                log("通道就绪 ✓ uid=2000 且 Seccomp: 0 ⇒ 可用来跑 W1")
                WirelessNotifications.showStatus(
                    context,
                    context.getString(R.string.wireless_ready_title),
                    context.getString(R.string.wireless_shell_ready, identity, seccomp),
                )
            } else {
                log("通道未达预期 ✗ 需要 uid=2000 且 Seccomp: 0（当前 uid=$uid Seccomp=$seccomp）")
                WirelessNotifications.showStatus(
                    context,
                    context.getString(R.string.wireless_failed_title),
                    context.getString(R.string.wireless_shell_not_ready, identity, seccomp),
                )
            }
        } catch (error: Throwable) {
            markFailed(context, "连接/自检失败：${WirelessAdb.describe(error)}")
        } finally {
            /* Nothing of this flow should stay in the shade: the prompt is cancelled when
             * the code arrives, and the flow owns exactly one result notification. */
            WirelessNotifications.cancelCodeInput(context)
            mutate { it.copy(busy = false) }
        }
    }

    private fun savePaired(context: Context, endpoint: AdbEndpoint) {
        prefs(context).edit()
            .putBoolean(KEY_PAIRED, true)
            .putLong(KEY_PAIRED_AT, System.currentTimeMillis())
            .putString(KEY_ENDPOINT, endpoint.toString())
            .apply()
    }

    private fun markFailed(context: Context, message: String) {
        log("✗ $message")
        WirelessNotifications.cancelCodeInput(context)
        mutate { it.copy(status = message) }
        if (WirelessNotifications.canPost(context)) {
            WirelessNotifications.showStatus(
                context,
                context.getString(R.string.wireless_failed_title),
                message,
            )
        }
    }

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun log(line: String) {
        Log.d(WirelessAdb.TAG, line)
        mutate { state -> state.copy(log = (state.log + line).takeLast(MAX_LOG_LINES)) }
    }

    private fun mutate(transform: (WirelessState) -> WirelessState) {
        val next = synchronized(lock) {
            current = transform(current)
            current
        }
        main.post { listeners.toList().forEach { runCatching { it.onState(next) } } }
    }
}
