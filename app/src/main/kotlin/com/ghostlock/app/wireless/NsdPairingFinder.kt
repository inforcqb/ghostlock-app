package com.ghostlock.app.wireless

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Finds the `_adb-tls-pairing._tcp` endpoint with the platform's own mDNS (`NsdManager`).
 *
 * Used as a fallback next to `adb mdns services`: the adb CLI's mDNS view is a cache that the
 * server fills asynchronously, so right after the app starts it can legitimately be empty even
 * though the pairing dialog is open. The platform resolver answers immediately in that case.
 */
object NsdPairingFinder {
    private const val SERVICE_TYPE = "_adb-tls-pairing._tcp"

    /** `host:port` of the first resolved pairing service, or null within [timeoutMs]. */
    fun find(context: Context, timeoutMs: Long): String? {
        val manager = context.getSystemService(Context.NSD_SERVICE) as? NsdManager ?: return null
        val found = AtomicReference<String?>(null)
        val latch = CountDownLatch(1)
        val listener = object : NsdManager.DiscoveryListener {
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) = latch.countDown()
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) = Unit
            override fun onDiscoveryStarted(serviceType: String) = Unit
            override fun onDiscoveryStopped(serviceType: String) = Unit
            override fun onServiceLost(serviceInfo: NsdServiceInfo) = Unit

            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                runCatching {
                    manager.resolveService(
                        serviceInfo,
                        object : NsdManager.ResolveListener {
                            override fun onResolveFailed(info: NsdServiceInfo, errorCode: Int) = Unit
                            override fun onServiceResolved(resolved: NsdServiceInfo) {
                                val host = resolved.host?.hostAddress ?: return
                                found.set("$host:${resolved.port}")
                                latch.countDown()
                            }
                        },
                    )
                }
            }
        }
        return try {
            manager.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, listener)
            if (latch.await(timeoutMs, TimeUnit.MILLISECONDS)) found.get() else null
        } catch (_: Throwable) {
            null
        } finally {
            runCatching { manager.stopServiceDiscovery(listener) }
        }
    }
}
