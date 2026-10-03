package com.ghostlock.app.chain

import android.content.Context
import com.ghostlock.app.wireless.AdbCommand
import java.io.File
import java.security.MessageDigest

/**
 * Putting files on the device, from the app's own copy of them.
 *
 * Two kinds of files are pushed this way -- the W1 engine + profile ([W1Stage]) and the
 * device tooling that used to be copied over by hand (`kread_min.ko`, `fix-selinux.sh`) --
 * and all of them share the same rules:
 *
 *  * the device copy is compared **by sha256** before anything is sent, so a second run is
 *    silent and an interrupted push cannot pass as done (the hash is read back afterwards);
 *  * `adb push` is the transport, not a device-side `cp`: `/data/app/<pkg>/lib` is not
 *    readable by uid 2000 on the PJA110 (measured 2026-10-01: `ls: No such file or
 *    directory`), so the shell cannot copy the app's files itself;
 *  * assets are staged into the app's cache first: `adb push` needs a real path, and an
 *    asset is not one.
 */
object DeviceSync {

    /** The files the chain used to expect on the device, bundled in `assets/device/`. */
    val BUNDLED = listOf(
        Bundled("device/kread_min.ko", ChainSpec.KREAD_KO, "644"),
        Bundled("device/fix-selinux.sh", ChainSpec.FIX_SELINUX, "755"),
        /* The SukiSU-Ultra manager: CI drops the latest upstream release in here on every build,
         * so the app can still install a manager on a device that cannot reach GitHub. */
        Bundled("device/sukisu-manager.apk", ChainSpec.KSU_MANAGER_APK, "644"),
    )

    /** One `assets/<assetPath>` file and where it belongs on the device. */
    data class Bundled(val assetPath: String, val remotePath: String, val mode: String)

    /**
     * Push the bundled `ksud` (`jniLibs/arm64-v8a/libksud.so`, i.e. [ChainSpec.KSUD_LIB]) to
     * [ChainSpec.KSUD].
     *
     * The chain's property step calls it by absolute path as `ksud resetprop …` -- `ksud`
     * carries `resetprop` the way busybox carries its applets -- so the app does not depend on
     * a `resetprop` being on the shell's PATH (measured 2026-10-01: a bare `resetprop` is not
     * resolvable in a plain `adb shell`, and the device only has it as a symlink inside the
     * KernelSU installation). Returns false when the push did not work, so the caller can fall
     * back to the device's own [ChainSpec.KSUD_FALLBACK].
     */
    suspend fun pushKsud(context: Context, onLog: (String) -> Unit): Boolean =
        pushNative(context, ChainSpec.KSUD_LIB, ChainSpec.KSUD, "755", onLog)

    /**
     * Push one of the app's own binaries (`nativeLibraryDir/<libName>`) to [remote].
     *
     * `nativeLibraryDir` is where the APK's `jniLibs` end up; `adb push` is the transport,
     * because uid 2000 cannot read `/data/app/<pkg>/lib` (see the class note).
     */
    suspend fun pushNative(
        context: Context,
        libName: String,
        remote: String,
        mode: String,
        onLog: (String) -> Unit,
    ): Boolean {
        val source = File(context.applicationInfo.nativeLibraryDir, libName)
        if (!source.isFile) {
            onLog("[!] 内置二进制缺失：${source.absolutePath}")
            return false
        }
        return pushIfChanged(source, remote, mode, onLog)
    }

    /**
     * Push every [BUNDLED] file that the device does not already have.
     *
     * Deliberately non-fatal for the chain: these files are tools for the later cleanup /
     * SELinux repair steps, and a missing one must not stop W1 -> Magica -> adbd gate ->
     * ksud. The result is logged either way.
     */
    suspend fun pushBundled(context: Context, onLog: (String) -> Unit): Boolean {
        var all = true
        for (file in BUNDLED) {
            val ok = pushAsset(context, file.assetPath, file.remotePath, file.mode, onLog)
            if (!ok) all = false
        }
        return all
    }

    /**
     * Put literal [content] at [remote].
     *
     * Staged in the cache and pushed like every other file: `adb push` is the only transport
     * the app has, and uid 2000 cannot write into the app's private directory.
     *
     * Currently unused -- it carried the command plane's token until the plane became
     * unauthenticated (2026-10-03) -- and kept because it is the one-liner for "push a small
     * config to the device", which the chain has needed twice already.
     */
    suspend fun pushText(
        context: Context,
        remote: String,
        content: String,
        mode: String,
        onLog: (String) -> Unit,
    ): Boolean {
        val staged = File(context.cacheDir, remote.substringAfterLast('/'))
        val wrote = runCatching {
            staged.writeText(content)
            staged.isFile && staged.length() > 0L
        }.getOrElse { error ->
            onLog("[!] 暂存 $remote 失败：${error.message}")
            false
        }
        if (!wrote) return false
        return pushIfChanged(staged, remote, mode, onLog)
    }

    /** Stage `assets/<assetPath>` in the cache and push it to [remote] (see [pushIfChanged]). */
    suspend fun pushAsset(
        context: Context,
        assetPath: String,
        remote: String,
        mode: String,
        onLog: (String) -> Unit,
    ): Boolean {
        val staged = File(context.cacheDir, assetPath.substringAfterLast('/'))
        val copied = runCatching {
            context.assets.open(assetPath).use { input ->
                staged.outputStream().use { output -> input.copyTo(output) }
            }
            staged.isFile && staged.length() > 0L
        }.getOrElse { error ->
            onLog("[!] 读取内置文件 $assetPath 失败：${error.message}")
            false
        }
        if (!copied) {
            onLog("[!] 内置文件缺失：assets/$assetPath")
            return false
        }
        return pushIfChanged(staged, remote, mode, onLog)
    }

    /**
     * Put [source] at [remote] unless the device already has the same bytes.
     *
     * Returns false when the push or the read-back did not work, so no caller ever assumes
     * a file arrived.
     */
    suspend fun pushIfChanged(
        source: File,
        remote: String,
        mode: String,
        onLog: (String) -> Unit,
    ): Boolean {
        val local = sha256(source)
        val onDevice = remoteSha(remote)
        val name = remote.substringAfterLast('/')
        if (local == onDevice) {
            onLog("[*] $name 已是最新（sha256 一致，跳过推送）")
            return true
        }
        onLog(
            "[*] 推送 ${source.name} -> $remote" +
                if (onDevice.isEmpty()) "（设备上没有）" else "（设备上是 ${onDevice.take(12)}…）",
        )
        if (!AdbCommand.push(source.absolutePath, remote, onLog)) {
            onLog("[!] 推送失败：${source.absolutePath} -> $remote")
            return false
        }
        val chmod = AdbCommand.exec("chmod $mode $remote", retries = 2, timeoutMs = 20_000, onLog = null)
        if (chmod.transportFailure) {
            onLog("[!] chmod $mode $remote 没有真正执行")
            return false
        }
        val after = remoteSha(remote)
        if (after != local) {
            onLog("[!] $remote 的 sha256 与本地不一致（本地 ${local.take(12)}…，设备 ${after.take(12)}…）")
            return false
        }
        return true
    }

    /** sha256 of a remote file, or "" when it is not there / not readable. */
    suspend fun remoteSha(path: String): String = AdbCommand.exec(
        "sha256sum $path 2>/dev/null",
        retries = 2,
        timeoutMs = 20_000,
        onLog = null,
    ).output.lineSequence()
        .map { it.trim() }
        .lastOrNull { it.isNotEmpty() }
        ?.substringBefore(' ')
        ?.trim()
        .orEmpty()

    /** sha256 of a local file. Blocking: call it off the main thread. */
    fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { stream ->
            val buffer = ByteArray(1 shl 16)
            while (true) {
                val read = stream.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
