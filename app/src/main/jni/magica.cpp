/*
 * ============================================================================
 * magica.cpp -- the "Magica" root service, ported into GhostLock.
 * ============================================================================
 *
 * Source: the Magica fork at `.scratch/magica-upstream`, branch `v21-adbroot-fix`
 * (upstream Magica v2.1 is Unlicense / public domain; the delta that matters here
 * is in magica.cpp, MagicaService.java and MainActivity.java).  Only the three
 * capabilities below are ported on purpose; the libsu-based RemoteProcess*,
 * ParcelFileDescriptorUtil, MainActivity and the `stub` module are NOT ported --
 * the host talks to the shell channel over the UNIX socket directly (see
 * `app/src/main/kotlin/com/ghostlock/app/root/RootChannel.kt`).
 *
 *   1. root()               -- setresuid/setresgid/setgroups to uid 0.
 *   2. adb_root()           -- su:s0 pre-check, /proc/sys/fs/suid_dumpable = 0,
 *                              resetprop ro.debuggable/ro.secure, `ctl.restart adbd`
 *                              through both __system_property_set and
 *                              /system/bin/setprop, pkill -9 adbd, bounded 15 s poll.
 *   3. start_shell_server() -- daemonised AF_UNIX root shell at the shared path.
 *
 * ---------------------------------------------------------------------------
 * WHY THE ORDER OF LOADING IS LOAD-BEARING
 * ---------------------------------------------------------------------------
 * The escalation only works while SELinux is permissive (the app's W1 stage does
 * that) and only if this library -- whose JNI_OnLoad hooks `capset` in
 * /system/lib64/libandroid_runtime.so through the vendored LSPlt -- was loaded in
 * the APP ZYGOTE, so that every isolated process forked from it inherits the
 * hook.  That is why `com.ghostlock.app.root.AppZygote` (registered as
 * android:zygotePreloadName) calls System.loadLibrary("magica2") and why the
 * service itself is declared android:useAppZygote="true".  Do not "move" the
 * loadLibrary call: /system/lib64/libandroid_runtime.so's capset is called before
 * an isolated process gets to run any of our Java code.
 * SIGSYS only gets a logging handler -- if the hook is missing, escalation fails
 * and the only trace is that line.
 *
 * ---------------------------------------------------------------------------
 * THE CHANNEL DIRECTORY (one definition, used everywhere)
 * ---------------------------------------------------------------------------
 * Everything lives in RSH_DIR below = "/data/local/tmp/gl-w1": the socket
 * `rshell.sock`, the token `rshell.token` (0644 -- the device-side client and
 * `adb shell`, uid 2000, read it), the log `rshell.log`, and HOME of the shell we
 * hand out.  The path is frozen because the host's device tooling (w1.sh, rshell,
 * cleanup-*.sh under tools/device) and the adb shell (uid 2000) already use it,
 * and because the isolated service runs under a different uid, so a
 * world-traversable directory under /data/local/tmp is the only place the two
 * sides can share.  There are no -D flags or environment overrides for it: this
 * macro is the single definition, and magica.cpp does not accept a path from the
 * caller (a caller-controlled socket path would be a local privilege hole).
 *
 * NOTHING IN THIS TREE CREATES THAT DIRECTORY, and this process cannot:
 *   * the isolated root process is uid 0 but with CapEff=0x1c0
 *     (CAP_SETUID|CAP_SETGID|CAP_SETPCAP) and CapBnd=0, i.e. NO CAP_DAC_OVERRIDE,
 *     NO CAP_DAC_READ_SEARCH, NO CAP_CHOWN, NO CAP_FOWNER -- so ordinary DAC
 *     applies to it, and it cannot create a directory under /data/local/tmp
 *     (mode 0771 shell:shell), cannot chown and cannot chmod a file it does not
 *     own;
 *   * it *can* chmod files it does own (that is how the token becomes 0644 and
 *     the socket 0666) and it can write properties through the bundled resetprop.
 * So the one-time device setup has to hand it a directory it may write:
 *     adb shell mkdir -p /data/local/tmp/gl-w1
 *     adb shell chmod 777 /data/local/tmp/gl-w1
 * rsh_ensure_dir() below detects the missing/unwritable case and says so out
 * loudly instead of pretending the channel is up.
 *
 * AF_UNIX, never AF_INET: an isolated process has NO IP sockets (measured: the
 * bundled client got as far as writing the token, then socket(AF_INET) returned
 * -1, and nothing listened, while Seccomp showed mode 2 with 3 filters).  Unix
 * sockets are allowed there, and 0666 on the node is enough for adb shell to
 * connect without any chown.  No TCP code may be added to this file.
 *
 * ---------------------------------------------------------------------------
 * LICENCES (see THIRD_PARTY_NOTICES.md in this directory for the full text)
 * ---------------------------------------------------------------------------
 * This file is a port of Magica (Unlicense).  The vendored copies carry AOSP
 * BSD-3-Clause/Apache-2.0 headers and those headers are kept intact:
 *   * `system_properties/**`  -- vendored AOSP libcutils properties fork; this is
 *     the bundled resetprop (ro.* writes) and it is why __system_property_set is
 *     redirected to the platform client; the quoted headers must not be removed.
 *   * `android_filesystem_config.h` -- AOSP Apache-2.0 (the AID_* constants).
 *   * `lsplt/syscall.hpp` -- Google BSD-3-Clause.
 *   * `logging.h` -- Magica's own header (Unlicense), TAG retargeted here.
 * `lsplt/**` (other than syscall.hpp) carries NO licence header at all: upstream
 * LSPlt is an LSPosed project and its licence has not been settled for this tree.
 *   TODO(licence): settle the LSPlt licensing (or replace it with a self-written
 *   PLT/GOT patcher) before this app is redistributed.  It is used here for
 *   exactly one hook -- `capset` in libandroid_runtime.so.
 */

#include <jni.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <linux/capability.h>
#include <lsplt.hpp>
#include <api/system_properties.h>
#include <sys/xattr.h>
#include "logging.h"
#include "android_filesystem_config.h"

#define arraysize(array) (sizeof(array)/sizeof(array[0]))

/* The one and only definition of the shared channel directory (see the header
 * comment: the host's device tooling and uid 2000 both depend on this path). */
#define RSH_DIR "/data/local/tmp/gl-w1"
#define RSH_SOCK_PATH RSH_DIR "/rshell.sock"
#define RSH_TOKEN_PATH RSH_DIR "/rshell.token"
#define RSH_LOG_PATH RSH_DIR "/rshell.log"

static int skip_capset(cap_user_header_t header __unused, cap_user_data_t data __unused) {
    LOGD("Skip capset");
    return 0;
}

static jboolean root(JNIEnv *env  __unused, jobject thiz __unused) {
    if (setresuid(AID_ROOT, AID_ROOT, AID_ROOT)) {
        PLOGE("setresuid");
        return false;
    } else if (geteuid() == AID_ROOT) {
        LOGI("We Are Root!!!");
        if (setresgid(AID_ROOT, AID_ROOT, AID_ROOT)) {
            PLOGE("setresgid");
        }
        gid_t groups[] = {AID_SYSTEM, AID_ADB, AID_LOG, AID_INPUT, AID_INET,
                          AID_NET_BT, AID_NET_BT_ADMIN, AID_SDCARD_R, AID_SDCARD_RW,
                          AID_NET_BW_STATS, AID_READPROC, AID_UHID, AID_EXT_DATA_RW,
                          AID_EXT_OBB_RW, AID_READTRACEFS};
        if (setgroups(arraysize(groups), groups)) {
            PLOGE("setgroups");
        }
        return true;
    } else {
        return false;
    }
}

static void resetprop(const char *name, const char *value) {
    auto pi = const_cast<prop_info *>(__system_property_find(name));
    if (pi != nullptr && strncmp(name, "ro.", strlen("ro.")) == 0) {
        __system_property_delete(name, false);
        pi = nullptr;
    }
    int ret;
    if (pi != nullptr) {
        ret = __system_property_update(pi, value, strlen(value));
        LOGD("resetprop: update prop [%s]: [%s]", name, value);
    } else {
        ret = __system_property_add(name, strlen(name), value, strlen(value));
        LOGD("resetprop: create prop [%s]: [%s]", name, value);
    }
    if (ret) {
        LOGW("resetprop: set prop error");
    }
}

/*
 * adb_root(): upstream's flow plus one added line.
 *
 * The added line is the requested
 *     echo 0 > /proc/sys/fs/suid_dumpable
 * (written directly here, the value and errno are logged) on the theory that adbd
 * treats that sysctl as "this is a debug build" and then keeps root.
 *
 * Kept from upstream: the su:s0 pre-check, resetprop("ro.debuggable","1"),
 * resetprop("ro.secure","0"), the bundled __system_property_set("ctl.restart"),
 * and restoring the two props once adbd is root.
 *
 * Two deliberate deviations, both because of what was measured on this handset:
 *   - /system/bin/setprop ctl.restart adbd is issued as well: the bundled client's
 *     ctl write was observed to have no effect (adbd kept its pid, the adb shell
 *     never dropped), while the platform client definitely reaches init;
 *   - the wait is bounded (15 s).  Upstream's loop had no exit condition at all,
 *     and with the activity calling this on the UI thread that is what froze the
 *     app.  Here the caller is expected to use the AIDL method off the main
 *     thread as well (this is a blocking binder call).
 *
 * service.adb.root is never set here: on a build whose adbd cannot run as root it
 * makes adbd exit on start, init restart-loops it, and adb is then dead while
 * Settings still shows USB debugging as enabled.
 *
 * NOTE the property writes presuppose SELinux is already permissive (W1): the
 * `ctl.restart` write needs the usbd domain (or permissive) to reach init.
 */
static jboolean adb_root(JNIEnv *env  __unused, jobject thiz __unused) {
    char old_pid[32] = {};
    char pid[32] = {};
    char path[32] = {};
    struct stat st{};
    char selinux_context[64] = {};

    __system_properties_init();
    __system_property_get("init.svc_debug_pid.adbd", old_pid);
    if (old_pid[0] == '\0') {
        LOGW("adb root: adbd is not running (init.svc_debug_pid.adbd empty)");
    } else {
        snprintf(path, sizeof(path), "/proc/%s", old_pid);
        getxattr(path, "security.selinux", selinux_context, sizeof(selinux_context));
        LOGI("adb root: adbd pid=%s selinux=%s", old_pid, selinux_context);
        if (strncmp(selinux_context, "u:r:su:s0", strlen("u:r:su:s0")) == 0) {
            return true;
        }
    }

    /* the added line */
    {
        const int fd = open("/proc/sys/fs/suid_dumpable", O_WRONLY);
        if (fd < 0) {
            LOGW("adb root: cannot open /proc/sys/fs/suid_dumpable: %s",
                 strerror(errno));
        } else {
            const ssize_t w = write(fd, "0\n", 2);
            LOGI("adb root: suid_dumpable <- 0 (wrote %zd, errno=%d)", w, errno);
            close(fd);
        }
    }

    resetprop("ro.debuggable", "1");
    resetprop("ro.secure", "0");
    __system_property_set("ctl.restart", "adbd");
    system("/system/bin/setprop ctl.restart adbd");

    // ctl.restart does not fire on this handset: measured twice, with both the
    // bundled client and /system/bin/setprop, while adbd kept its pid.  Restart it the
    // way adbd does it for "adb root" itself: kill it and let init respawn the service
    // (adbd.rc has no oneshot flag).
    LOGI("adb root: pkill -9 adbd (init respawns it)");
    system("/system/bin/pkill -9 adbd");

    struct timespec t0{}, now{};
    clock_gettime(CLOCK_MONOTONIC, &t0);
    while (true) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        const long waited_ms = (now.tv_sec - t0.tv_sec) * 1000L +
                               (now.tv_nsec - t0.tv_nsec) / 1000000L;
        if (waited_ms > 15000) {
            LOGW("adb root: gave up after %ld ms (adbd pid=%s, ro.debuggable=1 left "
                 "in place)", waited_ms, pid);
            return false;
        }
        __system_property_get("init.svc_debug_pid.adbd", pid);
        if (pid[0] == '\0' || strcmp(pid, old_pid) == 0) { usleep(10000); continue; }
        snprintf(path, sizeof(path), "/proc/%s", pid);
        getxattr(path, "security.selinux", selinux_context, sizeof(selinux_context));
        if (stat(path, &st) != 0) { usleep(10000); continue; }
        LOGI("adb root: new adbd pid=%s uid=%d selinux=%s", pid, (int) st.st_uid,
             selinux_context);
        if (st.st_uid == AID_SHELL) {
            LOGW("adb root: adbd dropped privileges (uid=%d) -- no root adbd on this "
                 "build", (int) st.st_uid);
            return false;
        } else if (strncmp(selinux_context, "u:r:su:s0", strlen("u:r:su:s0")) == 0) {
            LOGI("adb root: adbd running as root (selinux=%s)", selinux_context);
            resetprop("ro.debuggable", "0");
            resetprop("ro.secure", "1");
            return true;
        } else {
            usleep(10000);
        }
    }
}

static void signal_handler(int sig) {
    if (sig != SIGSYS) return;
    LOGW("received signal: SIGSYS, setresuid fail");
}

/* ---- root shell server ----------------------------------------------------
 *
 * Exposes the uid-0 shell this service already owns to anything that can reach
 * the shared UNIX socket, so the host app (or `adb shell`, uid 2000, which has no
 * root) can open a real root shell without any kernel write -- which matters on
 * this handset, where the OPPO guard module intercepts credential writes but has
 * never objected to anything Magica does (its root is a userspace one).
 *
 * The client side is RootChannel.kt in the app and `sh <RSH_DIR>/rshell` on the
 * device; both read the token out of RSH_TOKEN_PATH and present it as the first
 * line on the socket.  Paths, modes and the token contract are described in the
 * file header comment above.
 *
 * The server daemonises (double fork + setsid) so it keeps running after the app
 * is gone, and requires the token as the first line so other apps on the phone
 * cannot just connect.  Caveat: the token file is world-readable (0644 -- that is
 * the contract the adb-shell client relies on) because a capless uid-0 process
 * cannot chown a socket; treat it as a prototype-grade secret.
 */

static void rsh_log(const char *format, ...) {
    const int fd = open(RSH_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    char buf[256];
    va_list ap;
    va_start(ap, format);
    const int n = vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);
    if (n > 0) (void) !write(fd, buf, (size_t) n);
    close(fd);
}

/*
 * The channel directory has to exist and be writable *before* anything else; see
 * the file header for why uid 0 without a single DAC capability cannot create it.
 * Returns false (with a log line that names the fix) when the channel cannot work.
 */
static bool rsh_ensure_dir() {
    struct stat st{};
    if (stat(RSH_DIR, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            LOGE("channel: %s exists but is not a directory (mode=%o)", RSH_DIR,
                 (unsigned) (st.st_mode & 07777));
            return false;
        }
        if (access(RSH_DIR, W_OK) != 0) {
            LOGE("channel: %s is not writable by uid %d (mode=%o uid=%d, errno=%d: %s); "
                 "run `adb shell chmod 777 %s` once -- this capless uid 0 cannot "
                 "create or chmod directories (no CAP_DAC_OVERRIDE/CAP_FOWNER)",
                 RSH_DIR, (int) geteuid(), (unsigned) (st.st_mode & 07777),
                 (int) st.st_uid, errno, strerror(errno), RSH_DIR);
            return false;
        }
        return true;
    }
    if (errno != ENOENT) {
        PLOGE("channel: stat %s", RSH_DIR);
    }
    /* Best effort only: it works when /data/local/tmp happens to be
     * world-writable, and fails with EACCES when the DAC rules apply as usual. */
    if (mkdir(RSH_DIR, 0777) == 0) {
        LOGI("channel: created %s (mode 0777)", RSH_DIR);
        return true;
    }
    LOGE("channel: %s is missing and cannot be created (%d: %s); the one-time device "
         "setup must do it: `adb shell mkdir -p %s && adb shell chmod 777 %s`",
         RSH_DIR, errno, strerror(errno), RSH_DIR, RSH_DIR);
    return false;
}

static void rsh_make_token(char *out, size_t cap) {
    const int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    unsigned char raw[16] = {};
    if (fd >= 0) {
        (void) !read(fd, raw, sizeof(raw));
        close(fd);
    }
    size_t n = 0;
    for (size_t i = 0; i < sizeof(raw) && n + 3 < cap; i++) {
        n += (size_t) snprintf(out + n, cap - n, "%02x", raw[i]);
    }
    out[n] = '\0';
}

/*
 * Borrow the token the device setup may have pre-created (that is the documented
 * contract: if rshell.token exists, its content is the token, and the client
 * reads the very same file), else keep ours.
 *
 *   1  = read from the file
 *   0  = no file yet; the caller publishes `fallback`
 *  -1  = the file exists but we cannot read a token out of it -- the caller MUST
 *        refuse to start the server: it would listen behind a token that neither
 *        side can name.
 */
static int rsh_read_expected(const char *fallback, char *out, size_t cap) {
    const int fd = open(RSH_TOKEN_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            snprintf(out, cap, "%s", fallback);
            return 0;
        }
        LOGW("channel: token %s exists but cannot be opened (%d: %s)",
             RSH_TOKEN_PATH, errno, strerror(errno));
        snprintf(out, cap, "%s", fallback);
        return -1;
    }
    const ssize_t r = read(fd, out, cap - 1);
    close(fd);
    if (r <= 0) {
        out[0] = '\0';
        return -1;
    }
    out[r] = '\0';
    char *nl = strchr(out, '\n');
    if (nl) *nl = '\0';
    if (out[0] == '\0') return -1;
    return 1;
}

static void rsh_pump(int cfd, int master) {
    char buf[4096];
    for (;;) {
        struct pollfd fds[2] = {{cfd, POLLIN, 0}, {master, POLLIN, 0}};
        if (poll(fds, 2, -1) <= 0) return;
        for (int i = 0; i < 2; i++) {
            if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            const int from = fds[i].fd;
            const int to = i == 0 ? master : cfd;
            const ssize_t n = read(from, buf, sizeof(buf));
            if (n <= 0) return;
            ssize_t off = 0;
            while (off < n) {
                const ssize_t w = write(to, buf + off, (size_t) (n - off));
                if (w <= 0) return;
                off += w;
            }
        }
    }
}

static void rsh_serve_client(int cfd, const char *expected) {
    char line[128] = {};
    size_t n = 0;
    while (n + 1 < sizeof(line)) {
        const ssize_t r = read(cfd, line + n, 1);
        if (r <= 0) { close(cfd); return; }
        if (line[n] == '\n') break;
        n++;
    }
    line[n] = '\0';
    if (strcmp(line, expected) != 0) {
        rsh_log("reject: bad token\n");
        (void) !write(cfd, "bad token\n", 10);
        close(cfd);
        return;
    }
    int master = -1;
    const pid_t pid = forkpty(&master, nullptr, nullptr, nullptr);
    if (pid < 0) {
        rsh_log("forkpty failed: %s\n", strerror(errno));
        close(cfd);
        return;
    }
    if (pid == 0) {
        setenv("HOME", RSH_DIR, 1);
        setenv("TERM", "xterm", 1);
        execl("/system/bin/sh", "sh", "-i", (char *) nullptr);
        _exit(127);
    }
    rsh_log("client ok, sh pid=%d\n", (int) pid);
    rsh_pump(cfd, master);
    kill(pid, SIGHUP);
    close(master);
    close(cfd);
}

static void rsh_loop(int listen_fd, const char *expected) {
    for (;;) {
        const int cfd = accept(listen_fd, nullptr, nullptr);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            return;
        }
        const pid_t c = fork();
        if (c == 0) {
            close(listen_fd);
            rsh_serve_client(cfd, expected);
            _exit(0);
        }
        close(cfd);
        if (c < 0) continue;
        (void) waitpid(c, nullptr, WNOHANG);
    }
}

static jboolean start_shell_server(JNIEnv *env  __unused, jobject thiz  __unused) {
    if (geteuid() != AID_ROOT) {
        LOGW("shell server: not root yet");
        return false;
    }
    if (!rsh_ensure_dir()) {
        return false;
    }

    char token[64] = {};
    rsh_make_token(token, sizeof(token));

    /* Keep the token only if the caller pre-created it; otherwise publish ours. */
    char expected[64] = {};
    const int token_state = rsh_read_expected(token, expected, sizeof(expected));
    if (token_state < 0) {
        LOGE("shell server: token %s is unreadable or empty; refusing to listen "
             "behind a token neither side can name", RSH_TOKEN_PATH);
        rsh_log("refused: token unreadable\n");
        return false;
    }
    if (token_state == 0) {
        const int wfd = open(RSH_TOKEN_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (wfd < 0) {
            LOGE("shell server: cannot publish token %s (%d: %s); the device setup "
                 "must run `adb shell chmod 777 %s`", RSH_TOKEN_PATH, errno,
                 strerror(errno), RSH_DIR);
            return false;
        }
        (void) !write(wfd, token, strlen(token));
        (void) !write(wfd, "\n", 1);
        close(wfd);
    }
    /* uid 0 is the owner, so this works without CAP_CHOWN; adb shell (uid 2000)
     * can then read the token even though the writer was root.  If the file was
     * pre-created by the shell user we do not own it and this chmod fails -- that
     * is fine as long as it already is 0644, so only log it. */
    if (chmod(RSH_TOKEN_PATH, 0644) != 0) {
        LOGW("shell server: chmod 0644 %s failed (%d: %s); the token must already be "
             "readable by uid 2000", RSH_TOKEN_PATH, errno, strerror(errno));
    }

    /* AF_UNIX, not AF_INET: this service runs in an isolated process, and Android
     * blocks IP sockets there (measured: token got written, then socket() returned
     * -1 and nothing listened while Seccomp showed mode 2 with 3 filters).  Unix
     * sockets are allowed, and 0666 on the node is enough for adb shell to connect
     * without any chown. */
    const int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (lfd < 0) {
        rsh_log("socket(AF_UNIX) failed: %s\n", strerror(errno));
        LOGE("shell server: socket(AF_UNIX) failed (%d: %s)", errno, strerror(errno));
        return false;
    }
    (void) unlink(RSH_SOCK_PATH);
    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", RSH_SOCK_PATH);
    if (bind(lfd, (struct sockaddr *) &addr, sizeof(addr)) != 0 ||
        listen(lfd, 8) != 0) {
        rsh_log("bind/listen %s failed: %s\n", RSH_SOCK_PATH, strerror(errno));
        LOGE("shell server: bind/listen %s failed (%d: %s)", RSH_SOCK_PATH, errno,
             strerror(errno));
        close(lfd);
        return false;
    }
    chmod(RSH_SOCK_PATH, 0666);
    rsh_log("listening on %s (token %s)\n", RSH_SOCK_PATH, RSH_TOKEN_PATH);
    LOGI("shell server: listening on %s (token %s)", RSH_SOCK_PATH, RSH_TOKEN_PATH);

    /* Daemonise so the shell survives this process/app. */
    const pid_t mid = fork();
    if (mid < 0) {
        rsh_log("fork failed: %s\n", strerror(errno));
        return false;
    }
    if (mid > 0) {
        (void) waitpid(mid, nullptr, 0);
        return true;
    }
    (void) setsid();
    const pid_t d = fork();
    if (d < 0) _exit(1);
    if (d > 0) _exit(0);
    (void) chdir("/");
    const int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        (void) dup2(devnull, 0);
        (void) dup2(devnull, 1);
        (void) dup2(devnull, 2);
        if (devnull > 2) close(devnull);
    }
    rsh_log("daemon up, accepting on %s\n", RSH_SOCK_PATH);
    rsh_loop(lfd, expected);
    _exit(0);
}

/*
 * JNIEXPORT is not decoration: the whole library is compiled with
 * -fvisibility=hidden (that is what keeps the vendored resetprop from being
 * interposed by, or interposing, libc), so without it JNI_OnLoad would not be in
 * .dynsym and ART would never call it -- the three registrations below would then
 * be missing and every native call would throw UnsatisfiedLinkError.
 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *jvm, void *v __unused) {
    JNIEnv *env;
    jclass clazz;

    if (jvm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    /* The host service class.  This literal is the JNI lookup key: the class must
     * not be renamed or obfuscated (see app/proguard-rules.pro). */
    if ((clazz = env->FindClass("com/ghostlock/app/root/RootShellService")) == nullptr) {
        LOGE("JNI_OnLoad: FindClass com/ghostlock/app/root/RootShellService failed -- "
             "the class was renamed or obfuscated (check the R8 keeps)");
        return JNI_ERR;
    }

    JNINativeMethod methods[] = {
            {"root",              "()Z", (void *) root},
            {"adb_root",          "()Z", (void *) adb_root},
            {"start_shell_server", "()Z", (void *) start_shell_server},
    };
    if (env->RegisterNatives(clazz, methods, arraysize(methods)) < 0) {
        LOGE("JNI_OnLoad: RegisterNatives failed");
        return JNI_ERR;
    }

    signal(SIGSYS, signal_handler);

#if defined(__LP64__)
    const char *runtime_path = "/system/lib64/libandroid_runtime.so";
#else
    const char *runtime_path = "/system/lib/libandroid_runtime.so";
#endif

    struct stat st{};
    if (stat(runtime_path, &st) != 0) {
        PLOGE("stat %s", runtime_path);
    } else {
        LOGV("stat: dev=%lu, inode=%lu, path=%s",
             (unsigned long) st.st_dev, (unsigned long) st.st_ino, runtime_path);
        /* The only hook this port needs: skip the runtime's capset so the isolated
         * process keeps the caps the zygote handed it.  Installed here, in the app
         * zygote, so every isolated process inherits it. */
        if (lsplt::RegisterHook(st.st_dev, st.st_ino, "capset", (void *) skip_capset, nullptr)) {
            if (!lsplt::CommitHook()) {
                PLOGE("CommitHook failed");
            } else {
                LOGD("CommitHook success");
            }
        } else {
            PLOGE("Failed to register hook");
        }
    }

    return JNI_VERSION_1_6;
}
