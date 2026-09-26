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
 * (/data/local/tmp/gl-w1/rshell.sock, token rshell.token), used by
 * com.ghostlock.app.root.RootChannel -- commands are a shell-level thing and do not
 * need an AIDL method each.
 *
 * Method ids: 1..3 are ours; 16777114 (0xFFFFAA) is the transaction id Shizuku
 * reserves for destroy() in its own AIDL files, and the host's existing
 * IGhostlockUserService.aidl follows the same convention.
 */
package com.ghostlock.app.root;

interface IRootShellService {
    /** setresuid/setresgid/setgroups to uid 0.  True when this process is uid 0. */
    boolean ensureRoot() = 1;

    /**
     * Publish the token (0644) and start the daemonised AF_UNIX shell server.
     * Requires root() to have succeeded.
     */
    boolean startChannel() = 2;

    /** ensureRoot() + the adbd root patch (blocking, up to 15 s).  Off the main thread. */
    boolean adbRoot() = 3;

    /** Ask the service to stop itself. */
    void destroy() = 16777114;
}
