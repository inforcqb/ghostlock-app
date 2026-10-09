package com.ghostlock.app.chain

import android.content.Context
import android.system.Os
import com.ghostlock.app.wireless.AdbCommand
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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

    /**
     * The files the chain still expects in the **shared** directory (`/data/local/tmp/gl-w1`).
     *
     * Only the manager APK is left here: `pm install -r` runs in part 1 over the uid-2000 shell,
     * which cannot read the app's private directory -- and the SELinux repair kit that used to be
     * pushed here moved into it (see [stagePrivate], user's call 2026-10-09).
     */
    val BUNDLED = listOf(
        /* The KernelSU manager: CI copies a pinned build into this asset on every build (see
         * `prebuilt/`), so the app can still install a manager on a device that cannot reach
         * GitHub. */
        Bundled("device/sukisu-manager.apk", ChainSpec.KSU_MANAGER_APK, "644"),
    )

    /** Where [stagePrivate] puts the part-2 tooling, inside the app's own `files/`. */
    const val PRIVATE_SUBDIR = "dev"

    /** One `assets/<assetPath>` file and where it belongs on the device. */
    data class Bundled(val assetPath: String, val remotePath: String, val mode: String)

    /**
     * Push every [BUNDLED] file that the device does not already have.
     *
     * Deliberately non-fatal for the chain: the manager APK is the one file that still needs the
     * shared directory, and a missing one must not stop W1 -> Magica -> adbd gate -> ksud. The
     * result is logged either way.
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
     * Stage the **part-2 tooling** in the app's own directory -- no `adb push`, no
     * `/data/local/tmp`.
     *
     * The files are already in this APK (`assets/device/…` and `jniLibs/arm64-v8a/libksud.so`), so
     * the app writes them itself; that is the only staging that works on a device that was never
     * paired, and it leaves nothing behind on the device (user's call, 2026-10-09).
     *
     * The chmods are what the executors need: part 2 runs its commands as **root** -- a root adbd
     * (which has `CAP_DAC_OVERRIDE` and needs none of this) or the uid-0 command plane, which is
     * uid 0 *without* capabilities and therefore needs ordinary DAC: traverse (`x`) on the app
     * data dir, on `files/` and on the staging dir, and read (`r`) on the files. The app owns all
     * three and can grant exactly that; nothing else in its private tree is exposed by it (listing
     * stays owner-only, and the inner directories are 0700).
     *
     * Returns false when something could not be staged; the caller logs and carries on, because
     * the repair kit is only used by the later cleanup steps.
     */
    suspend fun stagePrivate(context: Context, onLog: (String) -> Unit): Boolean =
        withContext(Dispatchers.IO) {
            val dir = File(context.filesDir, PRIVATE_SUBDIR)
            if (!dir.isDirectory && !dir.mkdirs()) {
                onLog("[!] 私有目录建不出来：${dir.absolutePath}")
                return@withContext false
            }
            var all = true
            all = copyAsset(context, "device/kread_min.ko", File(dir, "kread_min.ko"), "644", onLog) && all
            all = copyAsset(context, "device/fix-selinux.sh", File(dir, "fix-selinux.sh"), "755", onLog) && all
            all = copyNative(context, ChainSpec.KSUD_LIB, File(dir, "ksud"), "755", onLog) && all
            /* Directories last, so a partially copied set is never reachable. */
            all = chmod(context.dataDir.path, "711", onLog) && all
            all = chmod(context.filesDir.path, "711", onLog) && all
            all = chmod(dir.path, "711", onLog) && all
            ChainSpec.usePrivateDir(dir.absolutePath)
            onLog(
                "[*] part 2 工具目录（app 私有，不经 adb）：${dir.absolutePath} —— " +
                    if (all) "就绪" else "有不全的项（后面的修复步骤可能落空）",
            )
            all
        }

    /** `chmod` by `android.system.Os`, so the mode is the same one the shell would set. */
    private fun chmod(path: String, mode: String, onLog: (String) -> Unit): Boolean = runCatching {
        Os.chmod(path, mode.toInt(8))
        true
    }.getOrElse { error ->
        onLog("[!] chmod $mode $path 失败：${error.message}")
        false
    }

    /** Copy `assets/<assetPath>` into [target] (a private-directory file) and chmod it. */
    private fun copyAsset(
        context: Context,
        assetPath: String,
        target: File,
        mode: String,
        onLog: (String) -> Unit,
    ): Boolean = runCatching {
        context.assets.open(assetPath).use { input ->
            target.outputStream().use { output -> input.copyTo(output) }
        }
        target.isFile && target.length() > 0L
    }.getOrElse { error ->
        onLog("[!] 读取内置文件 $assetPath 失败：${error.message}")
        false
    }.also { ok ->
        if (!ok) onLog("[!] 内置文件缺失：assets/$assetPath")
        else chmod(target.path, mode, onLog)
    }

    /** Copy `nativeLibraryDir/<libName>` into [target] and chmod it. */
    private fun copyNative(
        context: Context,
        libName: String,
        target: File,
        mode: String,
        onLog: (String) -> Unit,
    ): Boolean {
        val source = File(context.applicationInfo.nativeLibraryDir, libName)
        if (!source.isFile) {
            onLog("[!] 内置二进制缺失：${source.absolutePath}")
            return false
        }
        val ok = runCatching {
            source.inputStream().use { input ->
                target.outputStream().use { output -> input.copyTo(output) }
            }
            target.isFile && target.length() > 0L
        }.getOrElse { error ->
            onLog("[!] 复制 $libName 失败：${error.message}")
            false
        }
        return ok && chmod(target.path, mode, onLog)
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
