package com.ghostlock.app.chain

import android.content.Context
import android.os.SystemClock
import java.io.File

/**
 * Persisted chain progress.
 *
 * `am hang --allow-restart` (step 2/3) makes the watchdog restart system_server,
 * which takes zygote -- and this app -- down with it, so the in-memory step list
 * is lost mid-chain. This keeps the last observed step plus a boot marker
 * (`SystemClock.elapsedRealtime()` is per boot), so the restarted app can tell
 * whether the recorded run belongs to the current boot and where it stopped.
 *
 * Initialised once from the Application; every call is failure-tolerant because
 * the chain must never break over bookkeeping.
 */
object ChainStateStore {
    private var file: File? = null

    fun init(context: Context) {
        file = File(context.filesDir, "chain-state.txt")
    }

    fun save(progress: ChainProgress, finished: Boolean = false) {
        val target = file ?: return
        runCatching {
            val now = SystemClock.elapsedRealtime()
            val previousBoot = load()?.bootElapsedMs?.takeIf { now >= it } ?: now
            target.writeText(
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

    /** Mark the current record finished (called when the chain returns). */
    fun markFinished() {
        val target = file ?: return
        runCatching {
            if (target.isFile) {
                target.writeText(target.readText().replace("finished=false", "finished=true"))
            }
        }
    }

    fun load(): ChainState? = runCatching {
        val target = file ?: return@runCatching null
        if (!target.isFile) return@runCatching null
        val map = target.readLines().mapNotNull { line ->
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
        runCatching { file?.delete() }
    }
}

/**
 * One recorded chain step, as read back from disk after a restart.
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
        "第 $index/$total 步 $step（$state）" +
            (if (detail.isNotBlank()) " · $detail" else "") +
            (if (finished) " — 已完成" else " — 未完成")
}
