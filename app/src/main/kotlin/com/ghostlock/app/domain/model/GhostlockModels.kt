package com.ghostlock.app.domain.model

data class CpuPair(val primary: Int, val consumer: Int) {
    override fun toString(): String = "$primary,$consumer"
}

data class KernelSnapshot(
    val deviceName: String,
    val kernelRelease: String,
    val socName: String = "",
    val kernelSupported: Boolean,
    val cpuPairs: List<CpuPair>,
    val cpuPairLabels: List<String>,
    val selectedCpuPair: Int,
    val safeModeEnabled: Boolean,
    /**
     * The access channel the chain depends on: the wireless-debugging shell (uid 2000,
     * `Seccomp: 0`) reached by pairing. Shizuku used to play that role and is gone.
     */
    val wirelessStatus: WirelessChannelStatus,
    /**
     * Which half of the exploit path this boot is in -- see [ChainPhase] and [ChainPhaseRule].
     * The screen shows only the steps of that half; the preflight step is not part of the split.
     */
    val chainPhase: ChainPhase = ChainPhase.PART1,
)

enum class WirelessChannelStatus { NOT_PAIRED, PAIRED, READY }

/**
 * Which half of the exploit path the device is in.
 *
 * The path is cut in two by `am hang --allow-restart`: everything before that command runs in
 * the boot where SELinux is still Enforcing, everything after it runs in the app instance the
 * watchdog's framework restart produces. The screen shows the half the device is actually in,
 * instead of the whole path.
 */
enum class ChainPhase {
    /** Before `am hang`: W1 and the framework restart itself. */
    PART1,

    /** After `am hang`: the uid-0 channel, the adb gate, `rmmod`, `ksud late-load`. */
    PART2,
}

/**
 * The phase, read from the device's own state.
 *
 * `enforce == 0` **and** `Seccomp: 0` is the state W1 leaves behind -- permissive, and the
 * shell uid carrying no seccomp filter -- and the framework restart undoes neither, so that
 * pair means this boot is already past `am hang`. Anything else (enforcing, unreadable, a
 * non-zero seccomp) is [ChainPhase.PART1], which is also the safe default: PART1 is the half
 * whose first action, W1, establishes the state PART2 depends on.
 */
object ChainPhaseRule {
    fun of(enforce: String?, seccomp: String?): ChainPhase {
        val permissive = enforce?.trim()?.startsWith("0") == true
        val noSeccomp = seccomp?.trim() == "0"
        return if (permissive && noSeccomp) ChainPhase.PART2 else ChainPhase.PART1
    }
}

enum class LogTone { Default, Error, Success, Warning, Progress }

data class LogEntry(val text: String, val tone: LogTone)

data class OffsetCandidate(val release: String, val document: String)

/** One editable advisory execution value (PROFILE-SUGGEST-01 / profile-ui). */
data class ExecutionFieldValue(
    val path: String,
    val value: Long,
    val overridden: Boolean,
)

/** Debug-only export preferences shown by the hidden debug screen. */
data class DebugSettings(
    val exportEnabled: Boolean = true,
    val exportLocation: String = "Download/ghostlock-debug-log",
    val kernelLogEnabled: Boolean = true,
)

/** One node of the resolved profile tree: a JSON group or a numeric leaf. */
data class ProfileFieldNode(
    val path: String,
    val name: String,
    val value: Long? = null,
    /** True when this field or any descendant has an explicit override. */
    val overridden: Boolean = false,
    val children: List<ProfileFieldNode> = emptyList(),
) {
    val isGroup: Boolean get() = children.isNotEmpty()
}

/** Resolved execution view for the advanced editor (controller-owned). */
data class ProfileConfig(
    val release: String,
    val hasProfile: Boolean,
    /** Hierarchical view of every numeric leaf, override flags included. */
    val roots: List<ProfileFieldNode> = emptyList(),
    /** General (execution tuning) subset exposed by the parameters screen. */
    val general: List<ExecutionFieldValue> = emptyList(),
    /** Explicit route from the profile; null means geometry inference. */
    val route: String? = null,
    /** Declared fallback route ("none"/"<route>"); null means unset. */
    val fallbackTo: String? = null,
    /** Dotted paths whose resolved value violates the geometry rules. */
    val invalidPaths: Set<String> = emptySet(),
) {
    companion object {
        /** Routes a profile may declare ("" is the inference fallback). */
        val Routes = listOf("tcp_zerocopy", "select_stack", "multicast_waiter")

        /** Execution tuning paths the general editor exposes. */
        val GeneralPaths = listOf(
            "execution.selected_cpus.main",
            "execution.selected_cpus.consumer",
            "execution.stages.w1_attempts",
            "execution.stages.w2_attempts",
            "execution.stages.w3_attempts",
            "execution.stages.w3_chain_rounds",
            "execution.race.route_wait_ms",
            "execution.heap.prepare_max_attempts",
            "execution.routes.select_stack.enter_delay_us",
            "execution.routes.select_stack.timeout_us",
        )
    }
}

data class KernelOffsets(
    val release: String,
    val scalars: Map<String, Long?>,
    val symbols: Map<String, Long?>,
    val structFields: Map<String, Long?>,
)

sealed interface OffsetImportResult {
    data class Imported(val releases: List<String>) : OffsetImportResult
    data class RequiresOverwrite(val releases: List<String>) : OffsetImportResult
    data object AlreadyPresent : OffsetImportResult
    data class MissingIncludes(val files: List<String>) : OffsetImportResult
    data class Failed(val reason: String) : OffsetImportResult
}

sealed interface ParseResult {
    data class Parsed(val releases: List<String>) : ParseResult
    data class RequiresOverwrite(val releases: List<String>) : ParseResult
    data object AlreadyPresent : ParseResult
    data class Failed(val code: Int, val reason: String? = null) : ParseResult
}
