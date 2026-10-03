/*
 * Control plane of the isolated root service.
 *
 * Implementation: com.ghostlock.app.root.RootShellService (isolatedProcess=true,
 * useAppZygote=true).  The caller -- the app itself -- must bind it with
 * Context.bindIsolatedService(intent, BIND_AUTO_CREATE, instanceName, executor, conn),
 * which is what Magica's activity did; a plain bindService() would not put the
 * service into an isolated process.
 *
 * This interface is the *control* plane (start / status / stop) plus four command *intents*:
 * identity, open the adb gate, restart adbd, read the listener table.  Each intent runs ONE
 * command that is fixed inside the library (`app/src/main/jni/magica.cpp`) -- **no command
 * string crosses this binder**, and there is no generic "run this" method: what the chain
 * may do to the device is exactly the four things declared here.
 *
 * Method ids: 1..7 are ours; 16777114 (0xFFFFAA) is the transaction id Shizuku
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
     * Self-test of the command plane, and then bring it up. Requires root() to have succeeded;
     * returns true when [channelIdentity] really reports uid 0.
     *
     * The command server listens on 127.0.0.1 with **no authentication** (the user's call,
     * 2026-10-03), which is why nothing is handed over here any more and why a device with no
     * adb pairing can still have a working plane -- there is no token to stage.
     *
     * Whether a listener actually came up is reported separately (the log line with `rc=`).
     */
    boolean startChannel() = 2;

    /** ensureRoot() + the adbd root patch (blocking, up to 15 s).  Off the main thread. */
    boolean adbRoot() = 3;

    /*
     * The command plane: four intents.  What each one runs is fixed in the library, so the
     * interface cannot be used to run anything else, and every one of them is executed as a
     * CHILD PROCESS of this service (`fork` + `execve("/system/bin/sh", ["sh", "-c", ...])`,
     * stdin /dev/null, stdout+stderr captured, deadline, SIGKILL on timeout).
     *
     * Why a child process and not an in-process call -- measured on the PJA110 (2026-10-02,
     * see docs/analysis/uid0-command-plane.md):
     *
     *  * property_service authorises a property write against the caller's **process**
     *    context (/proc/<tgid>/attr/current), so a domain borrowed inside a running service
     *    is never what init's check reads;
     *  * and borrowing it there fails outright anyway: `setcon` from a binder thread returns
     *    EACCES(13), because /proc/self resolves to the thread-group leader while a task may
     *    only write its OWN attributes (observed with no `avc: denied` in the log -- it never
     *    reached SELinux).
     *
     * A child is a single-threaded process of its own, so `runcon` inside it works and
     * property_service sees the context it wants.  The child inherits this service's uid 0
     * and capabilities: `fork`+`execve` does not drop the uid the way the JVM's
     * Runtime/ProcessBuilder does on this platform (measured `uid=90000(u0_i0)`).
     *
     * All four return the command's combined output.  A spawn failure, a timeout or a
     * non-zero exit is reported inside that text as `__GHOSTLOCK_EXEC_FAILED__: <reason>`,
     * so a caller cannot mistake "it never ran" (or it failed) for "it ran and printed
     * nothing".
     */

    /** `id` -- uid 0 and the SELinux context of the service process (the step-4 check). */
    String channelIdentity() = 4;

    /**
     * `runcon u:r:adbd:s0 setprop service.adb.tcp.port 5555` -- opens the adbd gate.  Only
     * the `adbd` domain may write that property (`adbd_config_prop`).
     */
    String channelOpenAdbGate() = 5;

    /**
     * `runcon u:r:usbd:s0 setprop ctl.restart adbd` -- makes init restart adbd, which is
     * what turns the gate into a listening root adbd.  `ctl_adbd_prop` belongs to `usbd`
     * alone (`plat_sepolicy.cil`).
     */
    String channelRestartAdbd() = 6;

    /**
     * `ss -lnt` -- the listener table, for the chain's poll.  Advisory by nature: whether
     * this child's /proc/net view is the one adbd listens in is not guaranteed, which is why
     * the chain treats a negative answer as "cannot confirm" and leaves the verdict to
     * `adb connect` in the app process.
     */
    String channelListeners() = 7;

    /** Ask the service to stop itself. */
    void destroy() = 16777114;
}
