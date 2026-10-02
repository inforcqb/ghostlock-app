/*
 * Control plane of the isolated root service.
 *
 * Implementation: com.ghostlock.app.root.RootShellService (isolatedProcess=true,
 * useAppZygote=true).  The caller -- the app itself -- must bind it with
 * Context.bindIsolatedService(intent, BIND_AUTO_CREATE, instanceName, executor, conn),
 * which is what Magica's activity did; a plain bindService() would not put the
 * service into an isolated process.
 *
 * This interface is the *control* plane (start / status / stop) plus the command plane,
 * [execShell], which runs one short command as uid 0 inside the isolated process.  The
 * commands themselves are the chain's business (com.ghostlock.app.root.RootChannel) and
 * do not get an AIDL method each -- and the two `runcon` steps *have* to be commands:
 * see the note on [execShell].
 *
 * Method ids: 1..4 are ours; 16777114 (0xFFFFAA) is the transaction id Shizuku
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
     *
     * ## Why the command plane is a command string and not typed native actions
     *
     * Measured on the PJA110 (2026-10-02, see docs/analysis/uid0-command-plane.md): the two
     * `runcon <domain> setprop ...` steps CANNOT be done inside this process.
     *
     *  * property_service authorises a property write against the caller's **process**
     *    context (/proc/<tgid>/attr/current), so a domain borrowed inside a running service
     *    is not what init's check sees, no matter how the borrow is done;
     *  * and borrowing it there fails outright anyway: `setcon` from a binder thread returns
     *    EACCES, because /proc/self resolves to the thread-group leader and a task may only
     *    write its own attributes.
     *
     * A child process (`fork` + `execve` of `sh -c`, exactly one command) gets its own
     * context, which is what the policy wants -- and it is the shape the verified runbook
     * used.  The child inherits this process's uid 0 and capabilities; the JVM never gets
     * involved, so nothing drops to the app uid (that is a `Runtime.exec` problem, not a
     * `fork` one).
     */
    String execShell(String command, int timeoutMs) = 4;

    /** Ask the service to stop itself. */
    void destroy() = 16777114;
}
