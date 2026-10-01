package com.ghostlock.app.wireless

import com.ghostlock.app.chain.ChainSpec
import com.ghostlock.app.chain.RootAdbResult
import com.ghostlock.app.chain.RootAdbRunner

/**
 * [RootAdbRunner] implemented on the bundled `adb` CLI.
 *
 * Chain steps 7-9 talk to the **root adbd** that steps 5/6 opened on
 * [ChainSpec.ADB_ENDPOINT]. The client for that is the same binary that carries the
 * wireless-debugging channel -- a second `adb` server, or a hand-written adb client, would
 * only repeat what the CLI already does (and the previous libadb client, with its own RSA
 * key and its `pushAdbKey` into `/data/misc/adb/adb_keys`, is gone for good: the wireless
 * **pairing** already registered our key with adbd, so nothing has to be authorized twice).
 *
 * The CLI picks the transport with `-s`, which [AdbService] does once
 * [AdbService.connectRoot] has marked the endpoint as the root serial; commands after that
 * are routed there, and the keep-alive watches that transport instead of the wireless one.
 */
object RootAdbd : RootAdbRunner {

    override suspend fun connect() {
        val connected = AdbCommand.connectRoot(
            ChainSpec.ADB_ENDPOINT,
            ChainSpec.ROOT_CONNECT_ROUNDS,
        )
        if (!connected) {
            throw IllegalStateException(
                "adb connect ${ChainSpec.ADB_ENDPOINT} 失败：adbd 没有在监听，或者我们的密钥未被接受",
            )
        }
    }

    override suspend fun exec(command: String, timeoutMs: Long): RootAdbResult {
        val result = AdbCommand.execOnRoot(command, timeoutMs = timeoutMs)
        if (result.transportFailure) {
            throw IllegalStateException("根 adbd 传输失败：${result.output.trim().take(200)}")
        }
        return RootAdbResult(result.exitCode, result.output)
    }
}
