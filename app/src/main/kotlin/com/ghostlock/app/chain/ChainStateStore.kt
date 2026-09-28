package com.ghostlock.app.chain

import android.content.Context
import android.os.SystemClock
import java.io.File

/**
 * Persisted chain progress.
 *
 * `am hang --allow-restart` (step 2/3) makes the watchdog restart system_server,
 * which takes zygote -- and this app -- down with it, so the in-memory step list
 * is lost mid-chain. The store keeps the last observed step plus a boot marker
 * (`SystemClock.elapsedRealtime()` is per boot), so the restarted app can tell
 * whether the recorded run belongs to the current boot and where it stopped.
 */
data class ChainState(
    val bootElapsedMs: Long,
    val updatedElapsedMs: Long,
    val index: Int,
    val total: Int,
    val step: String,
    val state: String,
    val detail: String,
    val finished: Boolean,
) {
    /** Human-readable one-liner for the log panel. */
    fun summary(): String =
        "第 $index/$total 步 ${step}（${state}）${if (detail.isNotBlank()) " · $detail" else ""}" +
            if (finished) " — 已完成" else " — 未完成"
}

class ChainStateStore(context: Context) {
    private val file: File get() = File(context.filesDir, "chain-state.txt")

    fun save(progress: ChainProgress, finished: Boolean = false) {
        runCatching {
            val now = SystemClock.elapsedRealtime()
            val previousBoot = load()?.get("boot")?.toLongOrNull()?.takeIf { now >= it } ?: now
            file.writeText(
                listOf(
                    "boot=$previousBoot",
                    "updated=$now",
                    "index=${progress.index}",
                    "total=${progress.total}",
                    "step=${progress.step.name}",
                    "state=${progress.state.name}",
                    "detail=${progress.detail.replace('\n', ' ').take(200)}",
                    "finished=$finished",
                ).joinToString("\n"),
            )
        }
    }

    fun load(): ChainState? = runCatching {
        if (!file.isFile) return@runCatching null
        val map = file.readLines().mapNotNull { line ->
            val i = line.indexOf('=')
            if (i <= 0) null else line.substring(0, i) to line.substring(i + 1)
        }.toMap()
        val boot = map["boot"]?.toLongOrNull() ?: return@runCatching null
        ChainState(
            bootElapsedMs = boot,
            updatedElapsedMs = map["updated"]?.toLongOrNull() ?: boot,
            index = map["index"]?.toIntOrNull() ?: 0,
            total = map["total"]?.toIntOrNull() ?: 0,
            step = map["step"].orEmpty(),
            state = map["state"].orEmpty(),
            detail = map["detail"].orEmpty(),
            finished = map["finished"] == "true",
        )
    }.getOrNull()

    /** True when the recorded run happened in this boot (elapsedRealtime only grows). */
    fun belongsToThisBoot(state: ChainState): Boolean =
        SystemClock.elapsedRealtime() >= state.bootElapsedMs

    fun clear() {
        runCatching { file.delete() }
    }
}
