/*
 * Control plane of the isolated root service.
 *
 * Implementation: com.ghostlock.app.root.RootShellService (isolatedProcess=true,
 * useAppZygote=true).  The caller -- the app itself -- must bind it with
 * Context.bindIsolatedService(intent, BIND_AUTO_CREATE, instanceName, executor, conn),
 * which is what Magica's activity did; a plain bindService() would not put the
 * service into an isolated process.
 *
 * This interface is only the *control* plane (start / status / stop).  The command
 * plane is the uid-0 shell the service exposes over the shared UNIX socket
 * (that was an AF_UNIX socket + token; the command plane is [execShell] now), used by
 * com.ghostlock.app.root.RootChannel -- commands are a shell-level thing and do not
 * need an AIDL method each.
 *
 * Method ids: 1..3 are ours; 16777114 (0xFFFFAA) is the transaction id Shizuku
 * reserves for destroy() in its own AIDL files, and the host's existing
 * IGhostlockUserService.aidl follows the same convention.
 *
 * The adb public key is deliberately NOT part of this control plane: the
 * wireless-debugging pairing already registered the app's key with adbd, so no
 * /data/misc/adb/adb_keys write exists any more.
 */
package com.ghostlock.app.root;

interface IRootShellService {
    /** setresuid/setresgid/setgroups to uid 0.  True when this process is uid 0. */
    boolean ensureRoot() = 1;

    /**
     * Self-test of the command plane. Requires root() to have succeeded; returns true when a
     * command really ran as uid 0 through [execShell].
     */
    boolean startChannel() = 2;

    /** ensureRoot() + the adbd root patch (blocking, up to 15 s).  Off the main thread. */
    boolean adbRoot() = 3;

    /**
     * Run one short shell command **in this uid-0 process** and return its combined output.
     *
     * This is the command plane the chain uses from the uid-0 channel step on. It used to be an
     * AF_UNIX socket plus a token file, which needs a filesystem path both sides can reach --
     * and that turned out to be device-dependent (missing parent directory, SELinux label,
     * token permissions on some builds). The caller already holds this binder, so the commands
     * ride it instead: no path, no token, no directory to prepare.
     *
     * A spawn failure or a timeout is reported inside the returned text as
     * `__GHOSTLOCK_EXEC_FAILED__: <reason>`, so a caller that parses output cannot mistake it
     * for a command that ran and printed nothing.
     */
    String execShell(String command, int timeoutMs) = 4;

    /** Ask the service to stop itself. */
    void destroy() = 16777114;
}
