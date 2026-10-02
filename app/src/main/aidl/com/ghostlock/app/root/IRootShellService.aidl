/*
 * Control plane of the isolated root service.
 *
 * Implementation: com.ghostlock.app.root.RootShellService (isolatedProcess=true,
 * useAppZygote=true).  The caller -- the app itself -- must bind it with
 * Context.bindIsolatedService(intent, BIND_AUTO_CREATE, instanceName, executor, conn),
 * which is what Magica's activity did; a plain bindService() would not put the
 * service into an isolated process.
 *
 * This interface is the *control* plane (start / status / stop) plus the three privileged
 * actions of the chain's 「提权环境恢复」 phase -- identity, setprop-in-a-borrowed-domain,
 * listener probe -- used by com.ghostlock.app.root.RootChannel.  There is no shell and no
 * command string on the wire: an action that needs a new capability gets a method here and
 * an implementation in `app/src/main/jni/magica.cpp`.
 *
 * Method ids: 1..6 are ours; 16777114 (0xFFFFAA) is the transaction id Shizuku
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
     * Self-test of the command plane. Requires root() to have succeeded; returns true when
     * [channelIdentity] really reports uid 0.
     */
    boolean startChannel() = 2;

    /** ensureRoot() + the adbd root patch (blocking, up to 15 s).  Off the main thread. */
    boolean adbRoot() = 3;

    /*
     * The command plane, action by action.
     *
     * It used to be one shell string per call (`execShell`) over this same binder, and before
     * that an AF_UNIX socket plus a token file.  Both are gone: the socket needed a filesystem
     * path both sides could reach (device-dependent -- a missing parent directory, an SELinux
     * label, a token the other side cannot read), and a shell string has to be parsed and
     * executed by a capless uid 0 that cannot spawn a child with its own identity (Android
     * drops a spawned child to the app uid -- measured on the PJA110) and can be frozen by the
     * cached-app freezer.  Each action below is a syscall or one property write inside the
     * isolated process itself, so nothing is left to spawn, parse or freeze.
     *
     * A failure that means "the action never ran" is reported inside the returned text as
     * `__GHOSTLOCK_EXEC_FAILED__: <reason>`, so a caller that parses output cannot mistake it
     * for an action that ran and printed nothing.
     */

    /**
     * Who the isolated process is: uid 0 and its SELinux context, in the shape `id` prints.
     *
     * This is the chain's step-4 identity check, read from this process instead of from a
     * spawned `sh -c id`.
     */
    String channelIdentity() = 4;

    /**
     * `runcon <domain> setprop <name> <value>`, in-process: `setcon` (i.e. writing
     * /proc/self/attr/current), the property write, and the switch back to this process's own
     * domain.  The domain borrow is the point: `service.adb.tcp.port` is `adbd_config_prop`
     * and `ctl.restart` is `ctl_adbd_prop`, so the adbd gate can only be opened from the
     * `adbd` / `usbd` domain.
     *
     * The write goes through **property_service** (the platform client), never through the
     * vendored property client this library also links: the vendored one writes the property
     * area directly and init never hears about it, which is measurably why `ctl.restart adbd`
     * used to do nothing at all.
     */
    String setPropInDomain(String domain, String name, String value) = 5;

    /**
     * Wait until the kernel reports a LISTEN socket on `port`, then answer.
     *
     * This is the `ss -lnt | grep :5555` of the original chain, without the shell and without
     * a socket of our own: an isolated process may not create an IP socket at all, so the
     * answer comes from reading /proc/net/tcp{,6}.
     *
     * The answer is text on purpose, because there are three of them and only two are about
     * adbd: "listening: …", "not-listening: …" (the tables were read and hold no such entry)
     * and "unreadable: …" (they could not be read from here).  "I cannot see it" is not the
     * same statement as "it is not there", and the caller decides.
     */
    String waitForPort(int port, int timeoutMs) = 6;

    /** Ask the service to stop itself. */
    void destroy() = 16777114;
}
