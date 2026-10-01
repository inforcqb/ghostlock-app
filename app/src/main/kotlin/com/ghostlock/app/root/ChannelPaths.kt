package com.ghostlock.app.root

import android.content.Context
import android.util.Log
import java.io.File

/**
 * Where the uid-0 shell channel lives.
 *
 * It used to be `/data/local/tmp/gl-w1`, a *shared* directory that had to be created and chmodded
 * 0777 by hand before the chain ran. When it was missing, the server's `bind/listen` failed --
 * and the server cannot fix that itself: it is an isolated process, uid 0 **without any
 * capability**, so plain DAC applies and it cannot create a directory (or chmod one) that is not
 * already writable for it.
 *
 * The fix is to keep the channel inside the app's own data directory, which always exists and
 * which the app process (the owner) can prepare:
 *
 *  * `/data/data/<pkg>` and `<pkg>/files` get `+x` for others, so the isolated uid 0 can *reach*
 *    the channel without being able to list or read anything else;
 *  * `<pkg>/files/gl-channel` gets `0777`, so that capless uid 0 can create the socket and the
 *    token there, and the app itself can read the token back;
 *  * the token stays `0644` and the socket `0666` -- the same exposure the `/data/local/tmp`
 *    version had, for the same reason: the two sides are different uids (app uid vs the isolated
 *    root) and neither may chmod the other's files.
 *
 * Note that the *device-side* `rshell` wrapper can no longer reach the socket (it runs as uid
 * 2000 and cannot traverse the app's data directory). That is fine: the only client is
 * [RootChannel], which runs inside this app.
 */
object ChannelPaths {
    const val DIR_NAME = "gl-channel"

    fun dir(context: Context): File = File(context.filesDir, DIR_NAME)

    fun socket(dir: String): String = File(dir, "rshell.sock").absolutePath

    fun token(dir: String): String = File(dir, "rshell.token").absolutePath

    fun log(dir: String): String = File(dir, "rshell.log").absolutePath

    /**
     * Create and chmod the channel directory; returns its absolute path.
     *
     * Never throws: a failure here shows up as "channel is not up yet" in the chain, with the
     * reason logged, instead of killing the run.
     */
    fun prepare(context: Context, onLog: (String) -> Unit = {}): String {
        val dir = dir(context)
        val existed = dir.isDirectory
        val created = if (existed) true else dir.mkdirs()
        /* +x only on the parents: enough to reach `gl-channel`, not enough to look around. */
        listOfNotNull(context.filesDir, context.filesDir.parentFile).forEach { parent ->
            runCatching { parent.setExecutable(true, false) }
        }
        val worldWritable = runCatching {
            dir.setReadable(true, false) && dir.setWritable(true, false) &&
                dir.setExecutable(true, false)
        }.getOrDefault(false)
        if (!created) {
            onLog("[!] 通道目录无法创建：$dir —— 通道不会起来")
            Log.e(TAG, "channel dir cannot be created: $dir")
        } else if (!existed) {
            onLog("[*] 通道目录已创建：$dir（0777=$worldWritable，父目录仅 +x）")
            Log.i(TAG, "channel dir prepared: $dir world=$worldWritable")
        }
        return dir.absolutePath
    }

    private const val TAG = "GhostlockRoot"
}
