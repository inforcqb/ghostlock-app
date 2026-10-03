package com.ghostlock.app.data

import com.ghostlock.app.BuildConfig
import com.ghostlock.app.chain.DeviceSync
import com.ghostlock.app.chain.RootAdbRunner
import com.ghostlock.app.chain.W1Stage
import com.ghostlock.app.wireless.RootAdbd
import com.ghostlock.app.wireless.AdbCommand
import com.ghostlock.app.wireless.WIRELESS_TAG
import com.ghostlock.app.chain.ChainProgress
import com.ghostlock.app.chain.ChainSpec
import com.ghostlock.app.chain.ChainStateStore
import com.ghostlock.app.chain.ChainStep
import com.ghostlock.app.chain.RootChain
import com.ghostlock.app.chain.RootExec
import com.ghostlock.app.chain.ShellResult
import com.ghostlock.app.chain.StepState
import com.ghostlock.app.root.IsolatedRootShell
import com.ghostlock.app.root.COMMAND_SERVER_ATTEMPTS
import com.ghostlock.app.root.COMMAND_SERVER_RETRY_MS
import com.ghostlock.app.root.RootChannel
import com.ghostlock.app.root.RootCommand
import android.annotation.SuppressLint
import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.provider.MediaStore
import android.util.Log
import android.system.Os
import androidx.core.content.edit
import androidx.core.net.toUri
import com.ghostlock.app.domain.model.CpuPair
import com.ghostlock.app.domain.model.ChainPhase
import com.ghostlock.app.domain.model.ChainPhaseRule
import com.ghostlock.app.domain.model.DebugSettings
import com.ghostlock.app.domain.model.KernelOffsets
import com.ghostlock.app.domain.model.KernelSnapshot
import com.ghostlock.app.domain.model.OffsetCandidate
import com.ghostlock.app.data.ota.OtaPayloadExtractor
import com.ghostlock.app.domain.model.OffsetImportResult
import com.ghostlock.app.domain.model.ParseResult
import com.ghostlock.app.domain.repository.GhostlockRepository
import com.ghostlock.app.domain.repository.ProfileConfigController
import com.ghostlock.app.domain.usecase.OffsetMatching
import com.ghostlock.app.domain.model.WirelessChannelStatus
import com.ghostlock.app.wireless.WirelessPairingController
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/** Android implementation of the domain repository. All platform I/O lives here. */
class AndroidGhostlockRepository(context: Context) : GhostlockRepository {
    private companion object {
        const val OffsetsFileName = "offsets.conf"

        /**
         * How often the display may re-read the phase facts.
         *
         * `snapshot()` runs on every resume and on every wireless state change, while the two
         * facts it needs only change when W1 lands or the device reboots -- so the read is
         * throttled instead of following the UI.
         */
        const val PHASE_REFRESH_MS = 20_000L
        const val LegacyOffsetsFileName = "offsets.json"
        const val ExtractBinaryName = "libextract.so"
        const val DefaultDebugLocation = "Download/ghostlock-debug-log"
        const val PrefDebugExportEnabled = "debug_export_enabled"
        const val PrefDebugExportLocation = "debug_export_location"
        const val PrefDebugKernelLogEnabled = "debug_kernel_log_enabled"

        /* U01-S14: per-run KernelSU log name; the resolved path travels to
         * the native process via GHOSTLOCK_KSU_LOG. */
        fun ksuLogName(runStamp: Long) = "ghostlock-ksu-$runStamp.log"

        const val BuiltinDirectory = "kernel_profiles"

        /* Every run's stdout/stderr is redirected here (export or not), so the
         * previous run can be inspected on the next start-up. */
        const val NativeLogFileName = ".ghostlock_native.log"
        const val LastRunFileName = ".ghostlock_last_run"
        const val W3SeccompFailureMarker = "W3 seccomp clear failed"

        /* The uid-0 command plane's staging contract (see `prepareCommandPlane` and
         * `RootShellService`'s COMMAND_SERVER_* constants). */
        const val CommandPlaneTokenName = "token"
        const val CommandPlanePortName = "port"
    }

    private val appContext = context.applicationContext
    private val filesDir: File = appContext.filesDir
    private val preferences get() =
        appContext.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE)
    private val offsetsFile get() = File(filesDir, OffsetsFileName)
    private val builtinProfiles = BuiltinProfileCatalog(appContext)
    private val assetConfigLoader = AssetConfigLoader(appContext)
    private val profileController = AndroidProfileConfigController(
        appContext,
        filesDir,
        offsetsFile,
        preferences,
    )
    private val cpuPairs = mutableListOf<CpuPair>()
    private val cpuPairLabels = mutableListOf<String>()
    private var selectedCpuPair = 0
    private var safeModeEnabled = false
    private var pendingParsedEntries: ValueList? = null

    /**
     * Last phase the device reported (SELinux + `Seccomp`, see [chainPhase]).
     *
     * It survives a failed read on purpose: after `am hang --allow-restart` the app instance is
     * brand new and the channel may not be up yet when the first refresh runs, and showing
     * PART1 at that moment would hide exactly the half the run is about to work in.
     */
    @Volatile
    private var lastChainPhase: ChainPhase = ChainPhase.PART1

    /** Serialises the phase read and remembers when it last ran; see [chainPhase]. */
    private val phaseGate = Mutex()

    @Volatile
    private var lastPhaseReadAt = 0L

    /**
     * Holds the binding to this app's isolated uid-0 root service (`bindIsolatedService`).
     * It is created here and deliberately never released: unbinding destroys the isolated
     * process, and with it the uid-0 shell channel the later chain steps talk to.
     */
    private val isolatedRootShell = IsolatedRootShell(appContext)

    init {
        buildCpuPairs()
        restoreCpuPair()
        dropLegacyOffsetsCache()
    }

    /** The old JSON offsets cache is not compatible and is discarded. */
    private fun dropLegacyOffsetsCache() {
        runCatching { File(filesDir, LegacyOffsetsFileName).delete() }
    }

    override suspend fun snapshot(): KernelSnapshot {
        val release = System.getProperty("os.version", "unknown").orEmpty()
        return KernelSnapshot(
            deviceName = resolveDeviceName(),
            kernelRelease = release,
            socName = resolveSocName(),
            kernelSupported = isKernelSupported(),
            cpuPairs = cpuPairs.toList(),
            cpuPairLabels = cpuPairLabels.toList(),
            selectedCpuPair = selectedCpuPair,
            safeModeEnabled = safeModeEnabled,
            wirelessStatus = wirelessChannelStatus(),
            chainPhase = chainPhase(),
        )
    }

    /**
     * The half of the exploit path this boot is in, from the two live facts that define the
     * split: SELinux and the shell's `Seccomp` (see [ChainPhaseRule]).
     *
     * This runs on the **display** path (`snapshot()` on every resume and on every wireless
     * state change), which dictates all three of its properties:
     *
     *  * it **never** logs through the default sink. `AdbCommand.setLogger(::log)` points that
     *    sink at the wireless state's log list, and the wireless listener calls
     *    `refreshAccessStatus()` -- so a logged read here re-enters `snapshot()` and the app
     *    spams `cat /sys/fs/selinux/enforce` forever (measured after a pairing on 2026-10-01);
     *  * it reads both facts in **one** command ([ChainSpec.READ_PHASE]) and at most once per
     *    [PHASE_REFRESH_MS];
     *  * a failed read (or no pairing at all) keeps [lastChainPhase]: the facts only change on
     *    a reboot or when W1 lands, and on a reboot this process is gone anyway -- except for
     *    the part-2 case, which [rememberedPart2Phase] recovers from the chain's own record.
     */
    private suspend fun chainPhase(): ChainPhase {
        if (!WirelessPairingController.state.paired) return rememberedPart2Phase()
        if (SystemClock.elapsedRealtime() - lastPhaseReadAt < PHASE_REFRESH_MS) return lastChainPhase
        return phaseGate.withLock {
            if (SystemClock.elapsedRealtime() - lastPhaseReadAt < PHASE_REFRESH_MS) {
                return@withLock lastChainPhase
            }
            lastPhaseReadAt = SystemClock.elapsedRealtime()
            val read = runCatching {
                AdbCommand.exec(
                    ChainSpec.READ_PHASE,
                    retries = 1,
                    timeoutMs = 10_000,
                    onLog = {},
                )
            }.getOrNull()?.takeIf { !it.transportFailure } ?: return@withLock rememberedPart2Phase()
            val lines = read.output.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
            val enforce = lines.firstOrNull().orEmpty()
            val seccomp = lines.firstOrNull { it.startsWith("Seccomp:") }
                ?.substringAfter(':')
                ?.trim()
                .orEmpty()
            val phase = ChainPhaseRule.of(enforce, seccomp)
            /* One line per transition, on the logcat tag of the wireless flow: the phase is a
             * display decision, but "why does it say Part 1?" is a question a log should
             * answer -- with the two facts it was derived from. */
            if (phase != lastChainPhase) {
                Log.i(
                    WIRELESS_TAG,
                    "chain phase -> $phase（enforce=$enforce, Seccomp=$seccomp）",
                )
            }
            lastChainPhase = phase
            phase
        }
    }

    /**
     * The phase when the device cannot be asked: the chain's own record of this boot's run.
     *
     * After `am hang --allow-restart` the framework restarts this app, so the wireless channel
     * can be gone exactly when the UI has to say which half it is showing -- and the default
     * ([ChainPhase.PART1]) would then hide every part-2 step, including the 「Part 2 已就绪」
     * prompt, on a device that is in part 2. [ChainStateStore] is written before each step and
     * survived that restart, and [resumedPart2] is exactly the question "is that record a
     * part-2 run of this boot?".
     *
     * Only a positive part-2 answer is taken from the record: anything else keeps
     * [lastChainPhase], so a stale record can never turn a fresh boot into part 2 here. The
     * chain's own entry check re-reads the live facts and does not trust this at all.
     */
    private fun rememberedPart2Phase(): ChainPhase =
        if (resumedPart2()) ChainPhase.PART2 else lastChainPhase

    /**
     * The access channel, as the UI shows it: the wireless-debugging shell the chain runs
     * its uid-2000 steps on. Pairing is the standing dependency; a verified channel only
     * exists after a successful connect + self-check.
     */
    private fun wirelessChannelStatus(): WirelessChannelStatus {
        val state = WirelessPairingController.state
        return when {
            state.shellReady -> WirelessChannelStatus.READY
            state.paired -> WirelessChannelStatus.PAIRED
            else -> WirelessChannelStatus.NOT_PAIRED
        }
    }

    override fun selectCpuPair(index: Int) {
        if (index !in cpuPairs.indices) return
        selectedCpuPair = index
        appContext.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE)
            .edit {
                putString("cpu_pair", cpuPairs[index].toString())
            }
    }

    override fun setSafeModeEnabled(enabled: Boolean) {
        safeModeEnabled = enabled
    }

    override fun profileController(): ProfileConfigController = profileController

    /* debug-ui: preferences for the hidden debug screen. */
    override suspend fun debugSettings(): DebugSettings = DebugSettings(
        exportEnabled = preferences.getBoolean(PrefDebugExportEnabled, true),
        exportLocation = normalizeDebugLocation(preferences.getString(PrefDebugExportLocation, null)),
        kernelLogEnabled = preferences.getBoolean(PrefDebugKernelLogEnabled, true),
    )

    override fun setDebugExportEnabled(enabled: Boolean) {
        preferences.edit { putBoolean(PrefDebugExportEnabled, enabled) }
    }

    override fun setDebugExportLocation(location: String) {
        preferences.edit { putString(PrefDebugExportLocation, normalizeDebugLocation(location)) }
    }

    override fun setDebugKernelLogEnabled(enabled: Boolean) {
        preferences.edit { putBoolean(PrefDebugKernelLogEnabled, enabled) }
    }

    private fun normalizeDebugLocation(value: String?): String {
        val cleaned = value.orEmpty().trim().trim('/').replace(Regex("/{2,}"), "/")
        val safe = cleaned.takeIf { candidate ->
            candidate.isNotEmpty() && candidate.split('/').none { it == ".." || it == "." }
        }
        return safe ?: DefaultDebugLocation
    }

    /* Profile configuration now lives in AndroidProfileConfigController: the
     * repository only wires it and forwards the native document. */

    override suspend fun exportCandidates(): List<OffsetCandidate> {
        val entries = readOffsetsFile(offsetsFile) ?: return emptyList()
        val current = System.getProperty("os.version", "")
        return entries.asSequence()
            .mapNotNull { it.asValueMap() }
            .map { entry -> (entry["release"] as? String).orEmpty() to entry }
            .filter { (release, entry) ->
                release.isNotEmpty() &&
                        !(builtinProfiles.builtin.containsKey(release) && matchesBuiltin(entry))
            }
            .distinctBy { it.first }
            .sortedWith(compareBy<Pair<String, ValueMap>> { if (it.first == current) 0 else 1 }.thenBy { it.first })
            .map { (release, entry) -> OffsetCandidate(release, HoconSupport.render(entry)) }
            .toList()
    }

    override suspend fun importOffsets(documents: Map<String, String>): OffsetImportResult =
        mergeImported(documents, overwrite = false)

    override suspend fun confirmImport(documents: Map<String, String>): OffsetImportResult =
        mergeImported(documents, overwrite = true)

    private class MissingIncludesException(val files: List<String>) : Exception()

    private fun mergeImported(documents: Map<String, String>, overwrite: Boolean): OffsetImportResult {
        return try {
            val imported = parseImportDocuments(documents)
                ?: return OffsetImportResult.Failed("not a valid profile document")
            val existing = readOffsetsFile(offsetsFile) ?: ValueList()
            val fresh = ValueList()
            val skipped = mutableListOf<String>()
            val differingBuiltins = mutableListOf<String>()
            for (entry in imported.mapNotNull { it.asValueMap() }) {
                val release = (entry["release"] as? String).orEmpty()
                if (release.isEmpty()) continue
                if (release in builtinProfiles.builtin) {
                    if (matchesBuiltin(entry)) {
                        skipped += release
                    } else {
                        differingBuiltins += release
                        fresh.add(entry)
                    }
                } else {
                    fresh.add(entry)
                }
            }
            if (fresh.isEmpty()) return OffsetImportResult.AlreadyPresent

            val overlaps = overlappingReleases(existing, fresh)
            val replaced = (overlaps + differingBuiltins).distinct()
            if (!overwrite && replaced.isNotEmpty()) {
                return OffsetImportResult.RequiresOverwrite(replaced)
            }
            mergeAndSave(existing, fresh, overwrite)
            OffsetImportResult.Imported(freshReleases(fresh))
        } catch (error: CancellationException) {
            throw error
        } catch (error: MissingIncludesException) {
            OffsetImportResult.MissingIncludes(error.files)
        } catch (error: Exception) {
            OffsetImportResult.Failed(error.message ?: "import failed")
        }
    }

    /**
     * Parses every picked document. Includes resolve against the picked files
     * first (by full name or base name), then the bundled assets; anything
     * unresolvable is reported so the user can pick the dependency as well.
     * Only objects carrying a `release` become entries (shared files selected
     * by accident are skipped).
     */
    private fun parseImportDocuments(documents: Map<String, String>): ValueList? {
        val byName = HashMap<String, String>()
        documents.forEach { (name, text) ->
            byName[name] = text
            byName[name.substringAfterLast('/')] = text
        }
        val missing = linkedSetOf<String>()
        val entries = ValueList()
        documents.forEach { (_, text) ->
            val expanded = expandImportIncludes(text, byName, missing, linkedSetOf())
            when (val value = HoconSupport.parseValue(expanded)) {
                is Map<*, *> -> value.asValueMap()
                    ?.takeIf { it.containsKey("release") }
                    ?.let(entries::add)

                is List<*> -> value.forEach { item ->
                    item.asValueMap()?.takeIf { it.containsKey("release") }?.let(entries::add)
                }
            }
        }
        if (missing.isNotEmpty()) throw MissingIncludesException(missing.toList())
        return entries.takeIf { it.isNotEmpty() }
    }

    private fun expandImportIncludes(
        text: String,
        byName: Map<String, String>,
        missing: MutableSet<String>,
        visiting: MutableSet<String>,
    ): String {
        if (!text.contains("include ")) return text
        val expanded = StringBuilder()
        for (line in text.lineSequence()) {
            val trimmed = line.trim()
            if (trimmed.startsWith("include ")) {
                val target = trimmed.removePrefix("include ").trim().trim('"')
                val key = target.substringAfterLast('/')
                val local = byName[key]
                if (local != null) {
                    if (visiting.add(key)) {
                        expanded.append(expandImportIncludes(local, byName, missing, visiting))
                        visiting.remove(key)
                    }
                } else {
                    val asset = assetConfigLoader.load("$BuiltinDirectory/$target")
                    if (asset.isBlank()) missing += target else expanded.append(asset)
                }
            } else {
                expanded.append(line)
            }
            expanded.append('\n')
        }
        return expanded.toString()
    }

    override suspend fun parseSource(input: String, xblPath: String?, overwrite: Boolean, onLog: (String) -> Unit): ParseResult {
        val parsedFile = File(filesDir, "offsets_parse.tmp")
        var tempBootFile: File? = null
        var tempXblFile: File? = null
        return try {
            if (overwrite) {
                val pending = pendingParsedEntries
                if (pending != null) {
                    pendingParsedEntries = null
                    val existing = readOffsetsFile(offsetsFile) ?: ValueList()
                    mergeAndSave(existing, pending, overwrite = true)
                    return ParseResult.Parsed(freshReleases(pending))
                }
            }
            val binary = File(appContext.applicationInfo.nativeLibraryDir, ExtractBinaryName)
            if (!binary.isFile) return ParseResult.Failed(1, "missing native binary: ${binary.absolutePath}")

            /* Remote OTA URLs are resolved by the pure-Kotlin extractor so the
             * Android binary ships without the http stack; local files keep
             * going straight to the Rust extractor. */
            val isRemoteUrl = input.startsWith("http://", ignoreCase = true) ||
                input.startsWith("https://", ignoreCase = true)
            val (effectiveInput, effectiveXblPath) = if (isRemoteUrl) {
                val extracted = OtaPayloadExtractor.extractPartitions(
                    url = input,
                    workDir = filesDir,
                    onLog = onLog,
                )
                tempBootFile = extracted.bootFile
                tempXblFile = extracted.xblConfigFile
                Pair(extracted.bootFile.absolutePath, extracted.xblConfigFile?.absolutePath ?: xblPath)
            } else {
                Pair(input, xblPath)
            }

            parsedFile.delete()
            val args = buildList {
                add(effectiveInput)
                if (effectiveXblPath != null) {
                    add("--xbl-config")
                    add(effectiveXblPath)
                }
                addAll(listOf("--format", "json", "--out", parsedFile.absolutePath, "--work-dir", filesDir.absolutePath))
            }
            onLog("extract: $effectiveInput")
            val code = runProcess(
                ProcessBuilder(listOf(binary.absolutePath) + args)
                    .directory(filesDir)
                    .redirectErrorStream(true)
                    .apply {
                        environment()["GHOSTLOCK_HOME"] = filesDir.absolutePath
                        environment()["TMPDIR"] = filesDir.absolutePath
                        environment()["HOME"] = filesDir.absolutePath
                    },
                onLog = onLog,
                timeoutSeconds = 1800,
            )
            onLog("extract exit code=$code")
            if (code != 0 || !parsedFile.isFile) return ParseResult.Failed(code)
            val fresh = parseEntries(parsedFile.readText()) ?: return ParseResult.Failed(code, "invalid extractor output")
            val existing = readOffsetsFile(offsetsFile) ?: ValueList()
            val filtered = ValueList()
            val skipped = mutableListOf<String>()
            val differingBuiltins = mutableListOf<String>()
            for (entry in fresh.mapNotNull { it.asValueMap() }) {
                val release = (entry["release"] as? String).orEmpty()
                if (release in builtinProfiles.builtin) {
                    if (matchesBuiltin(entry)) skipped += release
                    else {
                        differingBuiltins += release
                        filtered.add(entry)
                    }
                } else {
                    filtered.add(entry)
                }
            }
            if (filtered.isEmpty()) return ParseResult.AlreadyPresent
            val replaced = if (overwrite) emptyList() else differingBuiltins.distinct()
            if (replaced.isNotEmpty()) {
                pendingParsedEntries = filtered
                return ParseResult.RequiresOverwrite(replaced)
            }
            mergeAndSave(existing, filtered, overwrite = true)
            ParseResult.Parsed(freshReleases(filtered))
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            ParseResult.Failed(1, error.message)
        } finally {
            parsedFile.delete()
            tempBootFile?.delete()
            tempXblFile?.delete()
        }
    }

    override suspend fun runExploit(pair: CpuPair, onLog: (String) -> Unit): Int =
        withDebugAttackLog("direct", onLog) { archivedLog, debugDir ->
            runExploitBinary(pair, "libghostlock.so", archivedLog, debugDir)
        }.also { code -> recordLastRun(code) }

    /**
     * Run the frozen root chain -- see `docs/analysis/root-chain-integration.md`.
     *
     * Order, identities and commands are exactly the verified ones:
     *   W1 (wireless-debugging channel, uid 2000) -> the root service's uid-0 shell channel ->
     *   `runcon u:r:adbd:s0 setprop service.adb.tcp.port 5555` and
     *   `runcon u:r:usbd:s0 setprop ctl.restart adbd` (domain borrows work only while SELinux is
     *   permissive, which is why they sit between W1 and `ksud late-load`) -> adb over loopback
     *   to the root adbd (uid 0, `CapEff 0x1ffffffffff`) -> `rmmod oplus_security_guard` ->
     *   `/data/adb/ksud late-load`.
     *
     * The commands come from `docs/analysis/current-chain-20260926.md` §1 and must stay verbatim
     * (that document's §3 blacklists the "simplified" variants). Nothing here cleans up: the
     * verified chain leaves the adb gate open and the W1 park in place.
     */
    override suspend fun runRootChain(
        pair: CpuPair,
        onLog: (String) -> Unit,
        onProgress: (ChainProgress) -> Unit,
    ): Boolean {
        val release = System.getProperty("os.version", "").orEmpty()
        val config = profileController.load(release, pair)
        val profileBlob = profileController.nativeDocument(config)
        if (!config.hasProfile || profileBlob == null) {
            onLog("error: profile is unavailable for $release")
            return false
        }
        if (config.invalidPaths.isNotEmpty()) {
            onLog(
                "error: profile has ${config.invalidPaths.size} invalid field(s): " +
                    config.invalidPaths.take(6).joinToString(),
            )
            return false
        }
        /* The chain's uid-2000 steps run over the wireless-debugging channel now. Pairing is
         * the standing authorization, so the connection may simply not exist yet when the
         * user taps one-click root: make sure the channel is up before the first step, and
         * stop with a clear message instead of failing inside step 1.
         *
         * UNLESS THIS IS A PART-2 RESUME (see [resumedPart2]): the relaunch after
         * `am hang --allow-restart` restarted the framework, and the half of the chain that
         * is left -- Magica's uid-0 channel, the security module, `ksud late-load` -- does not
         * need the wireless channel at all. Refusing to start there would strand a device
         * whose adbd never came back as a root adbd. */
        val part2Resume = resumedPart2()
        if (part2Resume) {
            onLog(
                "[*] 续跑 PART 2（上一次记录：${ChainStateStore.load()?.summary() ?: "无"}）—— " +
                    "不要求 uid-2000 通道；本阶段的命令由 uid-0 命令面执行",
            )
        } else if (!WirelessPairingController.ensureChannel(appContext, onLog)) {
            onLog("error: 无线调试通道不可用 —— 请先在「无线调试」里完成配对与连接")
            return false
        }
        /* Device tooling the chain and the cleanup steps expect in ${ChainSpec.DEVICE_DIR}:
         * `kread_min.ko` and `fix-selinux.sh` used to be copied there by hand. Pushed from
         * `assets/device/` now (sha256-compared, so repeat runs are silent). Non-fatal: a
         * missing tool must not stop W1 -> Magica -> adbd gate -> ksud. */
        DeviceSync.pushBundled(appContext, onLog)
        /* The app's own `ksud` (GPL-3.0, from the installed KernelSU/ReSukiSU/KowSU) goes to
         * the device next to the engine: step 8b calls it by absolute path as
         * `ksud resetprop …`, so nothing depends on the shell's PATH. When the push fails the
         * chain falls back to the device's own installation. */
        val ksud = if (DeviceSync.pushKsud(appContext, onLog)) {
            ChainSpec.KSUD
        } else {
            onLog("[*] 用设备上的 ${ChainSpec.KSUD_FALLBACK}（内置 ksud 没能推送）")
            ChainSpec.KSUD_FALLBACK
        }
        /* The uid-0 channel is the binder to the isolated root service -- the same binder that
         * starts it. It carries four fixed intents (`identity` / gate / adbd restart /
         * listeners) and no command string, which is why the command plane below is a
         * separate transport. The old socket server (`/data/local/tmp/gl-w1` + `rshell.sock`)
         * needed hand-creation and the app-data-dir variant needed two chmods plus permissive
         * SELinux, and neither worked on every device (the user's report). */
        val channel = RootChannel { isolatedRootShell.serviceOrNull() }
        /* The *other* uid-0 plane: the command server (`gl_server`, 127.0.0.1:5038) that the
         * isolated process starts in [IsolatedRootShell.launch], and the transport part 2
         * falls back to when the root adbd is not there. Staged before the launch, because the
         * server reads its token while it starts. */
        prepareCommandPlane(onLog)
        /* Steps 7-9 run on the bundled adb CLI against the root adbd: the app has no adb
         * client of its own any more (libadb, and with it the whole adb public-key story,
         * is gone -- the wireless pairing already authorized our key). */
        val adb: RootAdbRunner = RootAdbd
        val w1Stage = W1Stage(appContext)
        val chain = RootChain(
            /* The timeout the chain passes in is forwarded: dropping it is how a stalled
             * call hung the whole run forever. */
            shell = { command, timeoutMs ->
                WirelessPairingController.execChainCommand(command, timeoutMs, onLog)
            },
            /* W1 is the app's own engine now: [W1Stage] pushes `libghostlock.so` and the
             * profile the app just composed, starts the engine detached with the runbook's
             * environment, and watches its log for the landing marker. It no longer depends
             * on whatever `ghostlock` happens to sit in /data/local/tmp. */
            w1 = { log -> w1Stage.run(profileBlob, log) },
            /* The uid-0 channel is this app's own service now, started by binding it as an
             * isolated service from THIS process (an isolated service may only be bound by
             * the app that declares it, so it cannot be done from the Shizuku user
             * service). It used to be `am start` on an external app that is not installed. */
            rootShell = { isolatedRootShell.launch(onLog) },
            channel = channel,
            adb = adb,
            /* The uid-0 command plane: one line in, output and an exit code out (see
             * `root/RootCommand.kt` and `jni/gl_server.cpp`). It is what lets part 2 finish
             * without a root adbd, and `RootCommand.exec` never throws for a command that
             * ran -- a *failure to run* is the IllegalStateException the chain relies on to
             * fall over from the adb transport. */
            root = RootExec { command, timeoutMs, domain ->
                val result = RootCommand.exec(
                    command = command,
                    timeoutMs = timeoutMs.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
                    domain = domain,
                )
                result.failed?.let {
                    throw IllegalStateException("uid-0 命令面执行失败（命令没有运行）：$it")
                }
                ShellResult(result.exitCode, result.output)
            },
            ksud = ksud,
            onLog = onLog,
            onProgress = onProgress,
        )
        return try {
            chain.run()
        } finally {
            channel.close()
        }
    }

    /**
     * Stage the uid-0 command plane's token, and hand `RootCommand` the port.
     *
     * Two copies of one secret on purpose: `<filesDir>/token` for [RootCommand] in this
     * process, and [ChainSpec.COMMAND_PLANE_TOKEN] on the device for the server inside the
     * isolated process (which has no business reading the app's private directory on an
     * enforcing boot).
     *
     * **No token means no plane, never an open plane.** The server refuses to serve without one
     * (`gl_server.cpp`, fail closed), because its listener is on loopback and every app on the
     * device can reach loopback. So a staging failure is *retried* here -- three pushes, a second
     * apart -- and if it still fails the run simply keeps using the root adbd, with a log line
     * that says so; the next chain attempt stages it again.
     */
    private suspend fun prepareCommandPlane(onLog: (String) -> Unit): Int {
        RootCommand.attach(filesDir)
        val port = ChainSpec.COMMAND_PLANE_PORT
        val token = runCatching {
            val existing = File(filesDir, CommandPlaneTokenName).readText().trim()
            /* Reuse a good token: the *server* may still be running from an earlier part of the
             * run and holding the old one. */
            if (existing.length >= 32) existing else newToken()
        }.getOrElse { newToken() }
        val local = runCatching {
            File(filesDir, CommandPlaneTokenName).writeText(token, StandardCharsets.UTF_8)
            File(filesDir, CommandPlanePortName).writeText("$port\n", StandardCharsets.UTF_8)
            true
        }.getOrDefault(false)
        /* Three pushes, a second apart: the first one loses to a busy adb server or to the
         * isolated process still reading the old file, and a missing token now costs the whole
         * fallback transport (the server fails closed). */
        var pushed = false
        for (attempt in 1..COMMAND_SERVER_ATTEMPTS) {
            pushed = runCatching {
                DeviceSync.pushText(appContext, ChainSpec.COMMAND_PLANE_TOKEN, "$token\n", "644", onLog)
            }.getOrDefault(false)
            if (pushed) break
            if (attempt < COMMAND_SERVER_ATTEMPTS) {
                onLog("[*] token 推送失败（第 $attempt/$COMMAND_SERVER_ATTEMPTS 次）⇒ 重试")
                delay(COMMAND_SERVER_RETRY_MS)
            }
        }
        onLog(
            "[*] uid-0 命令面暂存：port=$port token=${token.take(6)}…（本机文件 ${if (local) "ok" else "失败"}，" +
                "设备侧 ${if (pushed) "已推送" else "没推送 ⇒ 命令面会拒绝所有连接（fail closed），本次只走 adb"}" +
                "）",
        )
        return port
    }

    private fun newToken(): String {
        val bytes = ByteArray(24)
        SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { byte -> byte.toUByte().toString(16).padStart(2, '0') }
    }

    /**
     * Is this run the second half of a chain that `am hang --allow-restart` interrupted?
     *
     * The framework restart takes this app with it, so the only witness that survives is the
     * app's own record ([ChainStateStore]): a run from **this boot**, not finished, whose last
     * step is at or past [ChainStep.AM_HANG] means part 1 is done and the device is permissive
     * with a parked engine. That is the one case where the chain must not require the
     * uid-2000 channel before it starts.
     *
     * Pure file I/O on purpose: this runs before anything is connected, and it must not touch
     * the device (the wireless read that would confirm it needs the very channel we are
     * trying to make optional).
     */
    private fun resumedPart2(): Boolean = runCatching {
        val state = ChainStateStore.load() ?: return@runCatching false
        if (state.finished || !ChainStateStore.belongsToThisBoot(state)) return@runCatching false
        if (state.state == StepState.FAILED.name) return@runCatching false
        val step = runCatching { ChainStep.valueOf(state.step) }.getOrNull()
            ?: return@runCatching false
        /* The restart happens *while* AM_HANG runs, so the record it leaves behind is
         * `AM_HANG / RUNNING` -- that, and every part-2 step, means part 1 is behind us.
         * PREFLIGHT / MANAGER_INSTALL / W1 are part 1. */
        step == ChainStep.AM_HANG || step.phase == ChainPhase.PART2
    }.getOrDefault(false)

    private suspend fun recordLastRun(code: Int) = withContext(Dispatchers.IO) {
        runCatching {
            File(filesDir, LastRunFileName).writeText(
                "$code ${System.currentTimeMillis()}\n",
                StandardCharsets.UTF_8,
            )
        }
    }

    private suspend fun withDebugAttackLog(
        entry: String,
        onLog: (String) -> Unit,
        run: suspend ((String) -> Unit, String?) -> Int,
    ): Int {
        val settings = debugSettings()
        if (!settings.exportEnabled) return run(onLog, null)
        val archive = DebugAttackLog.open(appContext, entry, settings.exportLocation)
        if (archive == null) {
            onLog("warning: cannot create ${settings.exportLocation} debug log")
            return run(onLog, null)
        }
        val archivedLog: (String) -> Unit = { line ->
            runCatching { archive.append(line) }
            onLog(line)
        }
        return try {
            archivedLog("debug log: ${archive.folderPath}/${archive.displayName}")
            archivedLog("debug dump dir: ${archive.folderFile.absolutePath}")
            run(archivedLog, if (settings.kernelLogEnabled) archive.folderFile.absolutePath else null)
        } finally {
            runCatching { archive.close() }
        }
    }

    private suspend fun runExploitBinary(
        pair: CpuPair,
        binaryName: String,
        onLog: (String) -> Unit,
        debugDir: String?,
    ): Int {
        val workDir = filesDir
        return try {
            val binary = File(appContext.applicationInfo.nativeLibraryDir, binaryName)
            require(binary.isFile) { "missing native binary: ${binary.absolutePath}" }
            if (prepareKsud(workDir, onLog) != null) onLog("ksud ready") else onLog("warning: ksud not found")
            // U01-S14: a per-run KernelSU log path so a previous run's markers
            // can never satisfy the handoff probe; passed to the native process.
            val ksuLog = File(workDir, ksuLogName(System.currentTimeMillis()))
            val nativeLog = File(workDir, NativeLogFileName)
            nativeLog.writeText("")
            val activeProfile = File(workDir, "active-profile.bin")
            val release = System.getProperty("os.version", "").orEmpty()
            val config = profileController.load(release, pair)
            if (config.invalidPaths.isNotEmpty()) {
                error(
                    "profile has ${config.invalidPaths.size} invalid field(s): " +
                        config.invalidPaths.take(6).joinToString(),
                )
            }
            val profileBlob = profileController.nativeDocument(config)
                ?: error("profile is unavailable for $release")
            activeProfile.writeBytes(profileBlob)
            val ksuOffset = AtomicLong()
            val nativeOffset = AtomicLong()
            val tailer = Thread {
                try {
                    while (!Thread.currentThread().isInterrupted) {
                        tailKsuLog(nativeLog, nativeOffset, onLog)
                        tailKsuLog(ksuLog, ksuOffset, onLog)
                        Thread.sleep(200)
                    }
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }.apply {
                name = "ksu-log-tailer"
                isDaemon = true
                start()
            }
            val command = ProcessBuilder(
                binary.absolutePath, "--profile", activeProfile.absolutePath,
            )
                .directory(workDir)
                .redirectErrorStream(true)
                .redirectOutput(nativeLog)
                .apply {
                    environment()["GHOSTLOCK_HOME"] = workDir.absolutePath
                    environment()["TMPDIR"] = workDir.absolutePath
                    environment()["HOME"] = workDir.absolutePath
                    environment()["GHOSTLOCK_KSU_LOG"] = ksuLog.absolutePath
                    if (BuildConfig.DEBUG) environment()["GHOSTLOCK_VERBOSE_DEBUG"] = "1"
                    if (!debugDir.isNullOrEmpty()) environment()["GHOSTLOCK_DEBUG_DIR"] = debugDir
                    if (pair.primary != 0 || pair.consumer != 1) {
                        environment()["GHOSTLOCK_CORE"] = pair.primary.toString()
                        environment()["GHOSTLOCK_CONSUMER_CORE"] = pair.consumer.toString()
                    }
                    if (safeModeEnabled) environment()["GHOSTLOCK_DISABLE_MODULES"] = "1"
                }
            try {
                runProcess(command, onLog = {}, captureOutput = false)
            } finally {
                withContext(Dispatchers.IO) {
                    tailer.interrupt()
                    tailer.join(1000)
                    tailKsuLog(nativeLog, nativeOffset, onLog)
                    tailKsuLog(ksuLog, ksuOffset, onLog)
                }
            }
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            onLog("error: ${error::class.simpleName}: ${error.message}")
            1
        }
    }

    override suspend fun readDocument(uri: String): String = appContext.contentResolver
        .openInputStream(uri.toUri())
        ?.bufferedReader()
        ?.use { it.readText() }
        ?: throw IOException("cannot open $uri")

    override suspend fun cacheDocument(uri: String, fileName: String): String {
        val target = File(filesDir, fileName)
        appContext.contentResolver.openInputStream(uri.toUri())?.use { input ->
            target.outputStream().use(input::copyTo)
        } ?: throw IOException("cannot open $uri")
        return target.absolutePath
    }

    override suspend fun publishOffsets(candidate: OffsetCandidate): String {
        val safeRelease = candidate.release.replace(Regex("[^A-Za-z0-9._-]"), "_")
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, "offsets-$safeRelease.conf")
            put(MediaStore.Downloads.MIME_TYPE, "text/plain")
        }
        val uri = appContext.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            ?: throw IOException("cannot create download entry")
        appContext.contentResolver.openOutputStream(uri)?.use { output ->
            output.write(candidate.document.toByteArray(StandardCharsets.UTF_8))
        } ?: throw IOException("cannot open download entry")
        return uri.toString()
    }

    override fun close() {
        synchronized(processes) {
            processes.forEach(Process::destroyForcibly)
            processes.clear()
        }
    }

    /**
     * Stored documents are HOCON. The rust extractor report (legacy JSON) is
     * read through the same parser, which is the only JSON-compatible entry
     * besides importing a picked legacy offsets.json.
     */
    private fun parseEntries(text: String): ValueList? {
        if (text.isBlank()) return null
        return try {
            when (val value = HoconSupport.parseValue(text)) {
                is List<*> -> value.asValueList()
                is Map<*, *> -> ValueList().apply { value.asValueMap()?.let(::add) }
                else -> null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun readOffsetsFile(file: File): ValueList? = if (file.isFile) parseEntries(file.readText()) else null

    private fun overlappingReleases(existing: List<*>, imported: List<*>): List<String> {
        val known = existing.mapNotNull { (it.asValueMap()?.get("release") as? String) }.toSet()
        return imported.mapNotNull { (it.asValueMap()?.get("release") as? String) }
            .filter { it in known }
            .distinct()
    }

    private fun mergeAndSave(existing: List<*>, imported: List<*>, overwrite: Boolean) {
        val importedByRelease = imported.mapNotNull { it.asValueMap() }
            .associateBy { (it["release"] as? String).orEmpty() }
        val known = existing.mapNotNull { (it.asValueMap()?.get("release") as? String) }.toSet()
        val merged = ValueList()
        existing.forEach { raw ->
            val entry = raw.asValueMap() ?: return@forEach
            val release = (entry["release"] as? String).orEmpty()
            if (overwrite && release in importedByRelease) return@forEach
            merged.add(entry)
        }
        imported.forEach { raw ->
            val entry = raw.asValueMap() ?: return@forEach
            val release = (entry["release"] as? String).orEmpty()
            if (!overwrite && release in known) return@forEach
            merged.add(entry)
        }
        offsetsFile.writeText(HoconSupport.render(merged), StandardCharsets.UTF_8)
    }

    private fun freshReleases(entries: List<*>): List<String> =
        entries.mapNotNull { (it.asValueMap()?.get("release") as? String) }.distinct()

    private fun matchesBuiltin(entry: ValueMap): Boolean =
        OffsetMatching.matchesBuiltin(toKernelOffsets(entry), builtinProfiles.builtin)

    private fun toKernelOffsets(entry: ValueMap): KernelOffsets {
        /* Remote/main-era offsets are normalised before comparison. */
        LegacyProfileConverter.convertValue(entry)
        return KernelOffsets(
            release = (entry["release"] as? String).orEmpty(),
            scalars = scalarFields.associateWith { scalarValue(entry, it) },
            symbols = namespacedFields(entry, "offset"),
            structFields = namespacedFields(entry, "task_struct") +
                namespacedFields(entry, "cred") +
                namespacedFields(entry, "kernelsnitch"),
        )
    }

    /** Namespace fields, keyed as `namespace.field` to match the catalogue. */
    private fun namespacedFields(entry: ValueMap, namespace: String): Map<String, Long?> {
        val group = entry[namespace].asValueMap() ?: return emptyMap()
        return group.entries.associate { (field, value) ->
            "$namespace.$field" to (value as? Number)?.toLong()
        }
    }

    /** Reads a numeric field, following route branches and legacy flat keys. */
    private fun scalarValue(entry: ValueMap, field: String): Long? {
        val candidates = when {
            field == "compact_waiter" -> listOf(
                "route.tcp_zerocopy.compact_waiter",
                "fallback.route.tcp_zerocopy.compact_waiter",
                "compact_waiter",
            )

            field == "pselect_waiter_shift" -> listOf(
                "route.select_stack.waiter_shift",
                "fallback.route.select_stack.waiter_shift",
                "pselect_waiter_shift",
            )

            field.startsWith("mcast.") -> {
                val suffix = field.removePrefix("mcast.")
                listOf(
                    "route.multicast_waiter.$suffix",
                    "fallback.route.multicast_waiter.$suffix",
                    "mcast.$suffix",
                    "mcast_$suffix",
                )
            }

            else -> listOf(field, field.replace('.', '_'))
        }
        for (candidate in candidates) {
            nestedValue(entry, candidate)?.let { return it }
        }
        return null
    }

    private fun nestedValue(entry: ValueMap, path: String): Long? =
        (entry.getValueAt(path) as? Number)?.toLong()

    private val scalarFields = listOf(
        "kernel_major", "recommend_shizuku", "kernel_phys_load",
        "pselect_waiter_shift", "mcast.waiter_off", "mcast.buffer_size",
        "mcast.task_offset", "mcast.lock_offset", "mcast.fake_lock_offset",
        "mcast.fake_task_offset", "mcast.lock_slots_offset", "mcast.lock_slot_count",
        "mcast.lock_slot_stride",
        "kernelsnitch.collisions", "compact_waiter", "kernelsnitch.mm_struct_sz",
        "cred.copy_size", "cred.usage_offset", "cred.usage_value",
        "cred.caps_offset", "cred.caps_count", "cred.caps_value", "cred.ref_count",
        "cred.ref0_offset", "cred.ref1_offset", "cred.ref2_offset", "cred.ref3_offset",
        "cred.ref0_image", "cred.ref1_image", "cred.ref2_image", "cred.ref3_image",
    )

    private fun isKernelSupported(): Boolean {
        val version = System.getProperty("os.version", "").orEmpty()
        return version in builtinProfiles.unames || importedOffsetsMatch(version)
    }

    private fun importedOffsetsMatch(version: String): Boolean {
        val entries = readOffsetsFile(offsetsFile) ?: return false
        return entries.any { (it.asValueMap()?.get("release") as? String) == version }
    }

    private fun buildCpuPairs() {
        cpuPairs.clear()
        cpuPairLabels.clear()
        val online = parseCpuList(readSysFile("/sys/devices/system/cpu/online"))
        online.groupBy { readMaxFreq(it) }
            .filterKeys { it > 0 }
            .toSortedMap(compareByDescending { it })
            .forEach { (freq, cluster) ->
                cluster.sorted().chunked(2).filter { it.size == 2 }.forEach { pair ->
                    cpuPairs += CpuPair(pair[0], pair[1])
                    cpuPairLabels += "${pair[0]},${pair[1]} · ${formatFreq(freq)}"
                }
            }
        if (CpuPair(0, 1) !in cpuPairs) {
            cpuPairs += CpuPair(0, 1)
            val freq = readMaxFreq(0)
            cpuPairLabels += "0,1" + if (freq > 0) " · ${formatFreq(freq)}" else ""
        }
    }

    private fun restoreCpuPair() {
        val saved = appContext.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE)
            .getString("cpu_pair", null) ?: return
        val pair = saved.split(',').mapNotNull { it.trim().toIntOrNull() }
        if (pair.size == 2) cpuPairs.indexOf(CpuPair(pair[0], pair[1])).takeIf { it >= 0 }?.let { selectedCpuPair = it }
    }

    private fun parseCpuList(value: String): List<Int> = value.split(',').flatMap { part ->
        val range = part.trim().split('-').mapNotNull { it.toIntOrNull() }
        when (range.size) {
            1 -> range
            2 -> (range[0]..range[1]).toList()
            else -> emptyList()
        }
    }

    private fun readMaxFreq(cpu: Int): Long = readSysFile("/sys/devices/system/cpu/cpu$cpu/cpufreq/cpuinfo_max_freq").toLongOrNull() ?: -1L

    private fun formatFreq(khz: Long): String =
        if (khz >= 1_000_000L) "%.2f GHz".format(Locale.ROOT, khz / 1_000_000.0) else "%.0f MHz".format(Locale.ROOT, khz / 1000.0)

    private fun readSysFile(path: String): String = File(path).takeIf { it.isFile }?.useLines { it.firstOrNull()?.trim().orEmpty() } ?: ""

    @SuppressLint("PrivateApi")
    private fun systemProperty(key: String): String = try {
        val properties = Class.forName("android.os.SystemProperties")
        properties.getMethod("get", String::class.java).invoke(null, key) as? String ?: ""
    } catch (_: Throwable) {
        ""
    }

    private fun validDeviceName(value: String?): String? =
        value?.trim()?.takeIf { it.isNotEmpty() && !it.contains("unknown", true) && !it.contains("null", true) }

    private fun resolveDeviceName(): String {
        val manufacturer = Build.MANUFACTURER.orEmpty()
        val marketName = when (manufacturer.lowercase(Locale.ROOT)) {
            "xiaomi" -> firstValidProperty("ro.product.marketname")
            "oppo", "oneplus", "realme", "oplus" -> {
                val cn = Locale.getDefault().country.equals("CN", true)
                firstValidProperty(
                    *(if (cn) arrayOf(
                        "ro.vendor.oplus.market.name",
                        "ro.vendor.oplus.market.enname"
                    ) else arrayOf("ro.vendor.oplus.market.enname", "ro.vendor.oplus.market.name"))
                )
            }

            "vivo" -> firstValidProperty("ro.vivo.market.name")
            "honor", "huawei" -> firstValidProperty("ro.config.marketing_name")
            "zte", "nubia" -> firstValidProperty("ro.vendor.product.ztename")
            else -> null
        }
        return marketName ?: listOfNotNull(
            manufacturer,
            Build.BRAND.orEmpty().takeIf { !it.equals(manufacturer, true) },
            Build.MODEL.orEmpty()
        )
            .filter { it.isNotBlank() }
            .joinToString(" ")
    }

    private fun resolveSocName(): String = listOf(
        systemProperty("ro.soc.manufacturer"),
        systemProperty("ro.soc.model"),
    )
        .mapNotNull(::validDeviceName)
        .joinToString(" ")
        .ifBlank { "unknown" }

    private fun firstValidProperty(vararg keys: String): String? =
        keys.asSequence().firstNotNullOfOrNull { validDeviceName(systemProperty(it)) }

    private fun prepareKsud(workDir: File, onLog: (String) -> Unit): File? {
        val packages = listOf(
            /* com.sukisu.ultra is the manager the chain installs from the app's bundled copy of
             * the latest SukiSU-Ultra release; the rest are managers a user may already have. */
            ChainSpec.KSU_MANAGER_PACKAGE,
            "me.weishu.kernelsu.pr",
            "me.weishu.kernelsu",
            "com.resukisu.resukisu",
            "com.kowx712.supermanager",
        )
        var installed = false
        for (packageName in packages) {
            val appInfo = runCatching { appContext.packageManager.getApplicationInfo(packageName, 0) }.getOrNull() ?: continue
            installed = true
            val source = File(appInfo.nativeLibraryDir, "libksud.so")
            if (!source.isFile) continue
            val output = File(workDir, "ksud")
            runCatching {
                source.inputStream().use { input -> output.outputStream().use { input.copyTo(it) } }
                runCatching { Os.chmod(output.absolutePath, 448) }
                return output
            }.onFailure { onLog("copy ksud failed: ${it.message}") }
        }
        if (!installed) onLog("KernelSU/ReSukiSU/KowSU app not installed")
        return null
    }

    private suspend fun runProcess(
        builder: ProcessBuilder,
        onLog: (String) -> Unit = {},
        timeoutSeconds: Long = 300,
        captureOutput: Boolean = true,
    ): Int = runInterruptible {
        val process = builder.start()
        synchronized(processes) { processes += process }
        val reader = if (captureOutput) Thread {
            try {
                process.inputStream.bufferedReader(StandardCharsets.UTF_8).useLines { lines -> lines.forEach(onLog) }
            } catch (_: IOException) { }
        }.apply {
            name = "process-output-reader"
            isDaemon = true
        } else null
        try {
            reader?.start()
            val finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
            if (!finished) {
                process.destroy()
                if (!process.waitFor(5, TimeUnit.SECONDS)) process.destroyForcibly()
            }
            reader?.let(::joinReader)
            if (finished) process.exitValue() else -1
        } finally {
            if (process.isAlive) process.destroyForcibly()
            reader?.interrupt()
            runCatching { process.inputStream.close() }
            reader?.let(::joinReader)
            synchronized(processes) { processes -= process }
        }
    }

    private fun joinReader(reader: Thread) {
        try {
            reader.join(3000)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private fun tailKsuLog(logFile: File, offset: AtomicLong, onLog: (String) -> Unit) {
        if (!logFile.isFile) return
        synchronized(offset) {
            runCatching {
                RandomAccessFile(logFile, "r").use { file ->
                    val position = offset.get().takeIf { it <= file.length() } ?: 0L
                    file.seek(position)
                    var lastComplete = position
                    val pending = StringBuilder()
                    while (true) {
                        val byte = file.read()
                        if (byte == -1) break
                        if (byte == '\n'.code) {
                            if (pending.isNotEmpty()) onLog(pending.toString())
                            pending.clear()
                            lastComplete = file.filePointer
                        } else {
                            pending.append(byte.toChar())
                        }
                    }
                    offset.set(lastComplete)
                }
            }
        }
    }

    private val processes = mutableSetOf<Process>()

}
