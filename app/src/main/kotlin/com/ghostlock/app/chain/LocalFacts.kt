package com.ghostlock.app.chain

import com.ghostlock.app.domain.model.ChainPhase
import com.ghostlock.app.domain.model.ChainPhaseRule
import java.io.File

/**
 * The two facts that decide which half of the chain this boot is in, read **from this process**.
 *
 * `Seccomp:` comes out of our own `/proc/self/status` (an app may always read that) and
 * `enforce` out of `/sys/fs/selinux/enforce`. Neither needs a channel, an adb connection or a
 * privileged helper, which is the whole point: part 2 is *defined* as permissive + Seccomp 0,
 * so a device in part 2 can be recognised -- by the UI and by the chain's preflight -- with
 * nothing running at all (user's call, 2026-10-09: part 2 must not require a shell).
 *
 * After the framework restart that part 2 follows, the `Seccomp` read is meaningful for *any*
 * process: the restart is what clears the filter, and it was measured boot-wide (all 14 sampled
 * processes reported 0). Before it -- a fresh boot -- this app reports its own filter (2) and is
 * denied selinuxfs by the untrusted_app domain, so this returns null and the caller falls back
 * to the channel, which is the only place part 1 can ask from anyway.
 *
 * An unreadable fact is never guessed at: [phase] is null then, not PART1 or PART2.
 */
object LocalFacts {

    /** `/sys/fs/selinux/enforce` as this app can read it (`"0"`/`"1"`), or null. */
    fun enforce(): String? = runCatching {
        File("/sys/fs/selinux/enforce").readText().trim().takeIf { it.isNotEmpty() }
    }.getOrNull()

    /** `Seccomp:` out of our own `/proc/self/status`, or null. */
    fun seccomp(): String? = runCatching {
        File("/proc/self/status").readText().lineSequence()
            .firstOrNull { it.startsWith("Seccomp:") }
            ?.substringAfter(':')
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
    }.getOrNull()

    /** The phase these two facts imply, or null when either could not be read. */
    fun phase(): ChainPhase? {
        val enforce = enforce() ?: return null
        val seccomp = seccomp() ?: return null
        return ChainPhaseRule.of(enforce, seccomp)
    }
}
