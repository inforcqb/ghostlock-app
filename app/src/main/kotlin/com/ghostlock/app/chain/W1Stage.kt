package com.ghostlock.app.chain

import android.content.Context
import com.ghostlock.app.wireless.AdbCommand
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.File

/**
 * W1, run from the **app's own engine**.
 *
 * This is `w1.sh`'s logic (see `docs/analysis/current-chain-20260926.md` §1 and the script
 * itself, `/data/local/tmp/gl-w1/w1.sh`) with the app as the source of both the engine and
 * the profile:
 *
 *  1. push `<nativeLibraryDir>/libghostlock.so` to [ChainSpec.W1_ENGINE] when its sha256
 *     differs from the one on the device -- the device copy used to be whatever had been
 *     pushed by hand (measured 2026-10-01: the 2026-09-28 build, whose early-exit gate still
 *     printed `>=50% coverage`), which is exactly how the app kept "running W1" without the
 *     100% gate it was built with;
 *  2. write the profile this app composed for the running kernel to [ChainSpec.W1_PROFILE];
 *  3. start the engine detached with the script's environment
 *     (`GHOSTLOCK_HOME` / `GHOSTLOCK_W1_ONLY` / `GHOSTLOCK_PARK_AFTER_W1` /
 *     `GHOSTLOCK_MCAST_SOCKET=tcp6`) and `--profile` as an **absolute** path -- the loader
 *     opens that string as it is, and the engine rewrites HOME at startup;
 *  4. read [ChainSpec.W1_LOG] until it says [ChainSpec.W1_LANDED_MARKER] (measured on this
 *     handset: 11-17s), streaming the lines into the run log.
 *
 * Three things from the script's own warnings are load-bearing and kept:
 *
 *  * the engine is started with `setsid`, so the adb shell session that started it can end
 *    without taking the parked process down;
 *  * the engine writes to a **file**, never a pipe: this process must not see EPIPE/SIGPIPE,
 *    because it is not allowed to die;
 *  * the parked process is **never killed** here. A reboot is the only cleanup.
 */
class W1Stage(private val context: Context) {

    /**
     * Run W1 with [profile] (the native document for the running kernel).
     *
     * Returns true only when the landing marker was seen; a timeout or an engine that died
     * early is false, and the caller must not treat either as "permissive" -- the chain
     * confirms that separately, from `/sys/fs/selinux/enforce`.
     */
    suspend fun run(profile: ByteArray, onLog: (String) -> Unit): Boolean =
        withContext(Dispatchers.IO) {
            val engine = File(context.applicationInfo.nativeLibraryDir, LOCAL_ENGINE)
            if (!engine.isFile) {
                onLog("[!] 内置引擎缺失：${engine.absolutePath}")
                return@withContext false
            }
            val profileFile = File(context.filesDir, LOCAL_PROFILE)
            profileFile.writeBytes(profile)

            if (!DeviceSync.pushIfChanged(engine, ChainSpec.W1_ENGINE, "755", onLog)) {
                return@withContext false
            }
            if (!DeviceSync.pushIfChanged(profileFile, ChainSpec.W1_PROFILE, "644", onLog)) {
                return@withContext false
            }

            val started = AdbCommand.exec(
                ChainSpec.W1_START,
                retries = 1,
                timeoutMs = 30_000,
                onLog = onLog,
            )
            if (started.transportFailure) {
                onLog("[!] W1 启动命令没有真正执行：${started.output.trim().take(200)}")
                return@withContext false
            }
            onLog("[*] W1 已启动（引擎 ${ChainSpec.W1_ENGINE}，日志 ${ChainSpec.W1_LOG}）")
            await(onLog)
        }

    /** Stream the engine's log until the landing marker, a deadline, or an early death. */
    private suspend fun await(onLog: (String) -> Unit): Boolean {
        val started = System.currentTimeMillis()
        var shown = 0
        var round = 0
        var lastText = ""
        while (System.currentTimeMillis() - started < ChainSpec.W1_DEADLINE_MS) {
            round++
            val read = AdbCommand.exec(
                "cat ${ChainSpec.W1_LOG} 2>/dev/null",
                retries = 2,
                timeoutMs = 20_000,
                onLog = null,
            )
            val text = if (read.transportFailure) lastText else read.output
            if (!read.transportFailure) lastText = text
            shown = emitNewLines(text, shown, onLog)
            if (text.contains(ChainSpec.W1_LANDED_MARKER)) {
                onLog("[+] W1 落地：${ChainSpec.W1_LANDED_MARKER}（engine 保持 park，绝不清掉）")
                return true
            }
            val elapsed = System.currentTimeMillis() - started
            /* An engine that is gone before it could land (a rejected profile, a failed
             * spray) must fail the step instead of burning the whole deadline. */
            if (elapsed >= ChainSpec.W1_EARLY_EXIT_MS && round % 3 == 0) {
                val alive = AdbCommand.exec(
                    "pidof ${ChainSpec.W1_ENGINE_COMM}",
                    retries = 1,
                    timeoutMs = 10_000,
                    onLog = null,
                )
                if (!alive.transportFailure && alive.output.isBlank()) {
                    onLog("[!] 引擎已退出且没有落地（${elapsed / 1000}s）：${tailOf(text)}")
                    return false
                }
            }
            delay(ChainSpec.W1_POLL_MS)
        }
        onLog("[!] ${ChainSpec.W1_DEADLINE_MS / 1000}s 内没等到「${ChainSpec.W1_LANDED_MARKER}」")
        tailOf(lastText).takeIf { it.isNotEmpty() }?.let { onLog("[!] 引擎日志尾部：$it") }
        return false
    }

    /** Log whatever the engine appended since the last read (complete lines only). */
    private fun emitNewLines(text: String, shown: Int, onLog: (String) -> Unit): Int {
        val cut = text.lastIndexOf('\n') + 1
        if (cut <= shown) return shown
        text.substring(shown, cut).lineSequence()
            .filter { it.isNotBlank() }
            .forEach(onLog)
        return cut
    }

    private fun tailOf(text: String): String =
        text.lineSequence().filter { it.isNotBlank() }.toList().takeLast(4)
            .joinToString(" | ").take(400)

    companion object {
        /** The app's own engine: the same binary the local (non-chain) run uses. */
        const val LOCAL_ENGINE = "libghostlock.so"

        /** Local file the composed profile is written to before it is pushed. */
        const val LOCAL_PROFILE = "gl-profile.bin"
    }
}
