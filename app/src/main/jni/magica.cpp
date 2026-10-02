/*
 * ============================================================================
 * magica.cpp -- the "Magica" root service, ported into GhostLock.
 * ============================================================================
 *
 * Source: the Magica fork at `.scratch/magica-upstream`, branch `v21-adbroot-fix`
 * (upstream Magica v2.1 is Unlicense / public domain; the delta that matters here
 * is in magica.cpp, MagicaService.java and MainActivity.java).  Only the three
 * capabilities below are ported on purpose, plus the channel actions further down;
 * the libsu-based RemoteProcess*, ParcelFileDescriptorUtil, MainActivity and the
 * `stub` module are NOT ported -- the host holds a binder to this service and calls
 * it directly (see `app/src/main/kotlin/com/ghostlock/app/root/RootChannel.kt`).
 *
 *   1. root()               -- setresuid/setresgid/setgroups to uid 0.
 *   2. adb_root()           -- su:s0 pre-check, /proc/sys/fs/suid_dumpable = 0,
 *                              resetprop ro.debuggable/ro.secure, `ctl.restart adbd`
 *                              through both __system_property_set and
 *                              /system/bin/setprop, pkill -9 adbd, bounded 15 s poll.
 *   3. channel_identity()   -- who this process is (uid 0 + its SELinux context).
 *   4. channel_set_prop_in_domain() -- `runcon <domain> setprop <n> <v>`, in-process.
 *   5. channel_wait_port()  -- is anything LISTENing on a port (read of /proc/net/tcp).
 *
 * 3-5 are the command plane: every step of the chain's "privileged environment" as a
 * syscall or one property write, in this process, with no shell and no fork.  The old
 * command plane was a daemonised AF_UNIX root shell (`start_shell_server()` below): it is
 * still compiled for reference but is no longer registered -- see JNI_OnLoad.
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
 * connect without any chown.  No TCP code may be added to this file -- not even a
 * `connect()` probe: "is adbd listening on 5555?" is answered by reading the kernel's
 * own socket table, /proc/net/tcp{,6} (channel_wait_port below), which is the table
 * `ss -lnt` prints, without needing a socket at all.
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
#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string>
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

/* The channel directory is set from Kotlin before the server starts (`set_channel_dir`), because
 * the parent directory has to exist and be writable by this capless uid 0 -- and the app's own
 * data directory is the one place that is guaranteed to exist (`/data/local/tmp/gl-w1` only does
 * after someone created it, which is exactly how "bind/listen failed" happened). The default
 * below keeps the old path for a server started without the setter. */
static char g_rsh_dir[288] = "/data/local/tmp/gl-w1";
static char g_rsh_sock_path[320];
static char g_rsh_token_path[320];
static char g_rsh_log_path[320];

static void rsh_apply_dir(void) {
    snprintf(g_rsh_sock_path, sizeof g_rsh_sock_path, "%s/rshell.sock", g_rsh_dir);
    snprintf(g_rsh_token_path, sizeof g_rsh_token_path, "%s/rshell.token", g_rsh_dir);
    snprintf(g_rsh_log_path, sizeof g_rsh_log_path, "%s/rshell.log", g_rsh_dir);
}

#define RSH_DIR g_rsh_dir
#define RSH_SOCK_PATH g_rsh_sock_path
#define RSH_TOKEN_PATH g_rsh_token_path
#define RSH_LOG_PATH g_rsh_log_path

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

/* Let the caller choose the channel directory. Called from RootShellService.startChannel() with a
 * directory the app process created and chmodded to 0777 inside its own data dir: the app owns
 * that directory and can make it reachable by this capless uid 0, which is the whole point -- a
 * missing/unwritable parent directory is exactly how "bind/listen failed" used to happen. */
static jboolean set_channel_dir(JNIEnv *env, jobject thiz __unused, jstring dir) {
    const char *value = env->GetStringUTFChars(dir, nullptr);
    if (value == nullptr) return JNI_FALSE;
    const size_t len = strlen(value);
    if (len == 0 || len >= sizeof g_rsh_dir) {
        LOGE("channel: refusing directory '%s' (len=%zu)", value, len);
        env->ReleaseStringUTFChars(dir, value);
        return JNI_FALSE;
    }
    snprintf(g_rsh_dir, sizeof g_rsh_dir, "%s", value);
    rsh_apply_dir();
    LOGI("channel: directory set to %s", g_rsh_dir);
    env->ReleaseStringUTFChars(dir, value);
    return JNI_TRUE;
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
 * ---------------------------------------------------------------------------------------------
 * Built-in channel actions: the privileged environment, without a shell and without a fork.
 *
 * The chain used to send these as command *strings* over the uid-0 channel (`id`, and the two
 * `runcon <domain> setprop …` pairs plus an `ss -lnt` poll). Spawning `/system/bin/sh` from the
 * isolated process is what made the whole thing device-dependent: the process can be frozen by
 * the cached-app freezer, and a spawned child loses the escalation on some builds. None of it is
 * needed -- every one of those commands is a syscall or a property write, and this process is the
 * uid 0 one:
 *
 *  * `id`                     -> assembled from getuid/getgid plus /proc/self/attr/current,
 *  * `runcon <domain> setprop` -> `setcon` (via /proc/self/attr/current) around a plain
 *                                 `__system_property_set`, which is exactly what `runcon`
 *                                 + `setprop` do; the domain switch is the point and it stays,
 *  * `ss -lnt | grep <port>`   -> a read of /proc/net/tcp{,6}, looking for a LISTEN
 *                                 entry on the port.  A `connect()` probe is not an
 *                                 option here (see the AF_INET note at the top).
 *
 * `setcon` needs only `dyntransition`, which is granted while SELinux is permissive -- the same
 * precondition the `runcon` subprocess had (it is the reason the frozen chain borrows the
 * `adbd`/`usbd` domains at all: `service.adb.tcp.port` is `adbd_config_prop`, `ctl.restart` is
 * `ctl_adbd_prop`). Switching back is done immediately, so the process keeps its own domain.
 *
 * THE PROPERTY WRITE MUST NOT USE THE VENDORED CLIENT.  Including <api/system_properties.h>
 * activates `hacks.h`, which carries
 *
 *     #pragma redefine_extname __system_property_set __system_property_set2
 *
 * so every `__system_property_set` *reference* in this translation unit is renamed to the
 * VENDORED AOSP client, which writes the property area directly and never talks to
 * property_service.  That is measurably why `ctl.restart adbd` "succeeded" and adbd kept its
 * pid (see the note in adb_root() below, and why that function falls back to pkill).
 * `ctl.*` is handled by init, so the write has to go through property_service: the platform
 * client, fetched out of libc's own symbol table, is the one that does.  The value is read
 * back through the platform client as well and logged, because for a capless uid 0 in a
 * borrowed domain the interesting failure is a write that returns 0 and changes nothing.
 */
static void channel_current_context(char *out, size_t cap) {
    out[0] = '\0';
    const int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    const ssize_t n = read(fd, out, cap - 1);
    close(fd);
    if (n <= 0) {
        out[0] = '\0';
        return;
    }
    out[n] = '\0';
    char *nl = strchr(out, '\n');
    if (nl) *nl = '\0';
}

static bool channel_switch_context(const char *domain) {
    const int fd = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        LOGW("channel: cannot open attr/current (%d: %s)", errno, strerror(errno));
        return false;
    }
    const ssize_t n = write(fd, domain, strlen(domain));
    const int saved_errno = errno;
    close(fd);
    if (n != (ssize_t) strlen(domain)) {
        LOGW("channel: setcon(%s) failed (%d: %s)", domain, saved_errno,
             strerror(saved_errno));
        return false;
    }
    return true;
}

/* 1) The identity the chain's self-test looks at, in the shape `id` prints. */
static jstring channel_identity(JNIEnv *env, jobject thiz __unused) {
    char context[256] = {};
    channel_current_context(context, sizeof context);
    char out[512];
    snprintf(out, sizeof out,
             "uid=%d(root) gid=%d(root) groups=%d(root) context=%s",
             (int) getuid(), (int) getgid(), (int) getgid(),
             context[0] ? context : "unknown");
    LOGI("channel identity: %s", out);
    return env->NewStringUTF(out);
}

/* ---------------------------------------------------------------------------------------------
 * The platform property client, fetched from libc by hand.
 *
 * See the note above the channel actions: this file's `__system_property_set` references are
 * renamed onto the VENDORED client by hacks.h, and the vendored client never talks to
 * property_service -- which is why `ctl.restart adbd` used to do nothing.  Going through libc's
 * own symbol table is the only way to reach the client init actually listens to.
 *
 * Resolved lazily, once, and always before a domain switch: dlopen/dlsym are loader work and
 * have no business happening in a borrowed SELinux domain.
 * ------------------------------------------------------------------------------------------- */
typedef int (*property_set_fn)(const char *, const char *);
typedef int (*property_get_fn)(const char *, char *);

static void *platform_symbol(const char *name) {
    void *libc = dlopen("libc.so", RTLD_NOW | RTLD_LOCAL);
    if (libc == nullptr) {
        LOGE("channel: dlopen(libc.so) failed: %s", dlerror());
        return nullptr;
    }
    dlerror();
    void *symbol = dlsym(libc, name);
    const char *error = dlerror();
    if (symbol == nullptr) {
        LOGE("channel: dlsym(libc.so, %s) failed: %s", name, error ? error : "unknown error");
    } else {
        LOGI("channel: %s resolved from libc at %p", name, symbol);
    }
    return symbol;
}

static property_set_fn platform_property_set(void) {
    static property_set_fn cached = (property_set_fn) platform_symbol("__system_property_set");
    return cached;
}

static property_get_fn platform_property_get(void) {
    static property_get_fn cached = (property_get_fn) platform_symbol("__system_property_get");
    return cached;
}

/* 2) `runcon <domain> setprop <name> <value>`, in-process. */
static jstring channel_set_prop_in_domain(JNIEnv *env, jobject thiz __unused,
                                          jstring domain, jstring name, jstring value) {
    const char *dom = env->GetStringUTFChars(domain, nullptr);
    const char *prop = name ? env->GetStringUTFChars(name, nullptr) : nullptr;
    const char *val = value ? env->GetStringUTFChars(value, nullptr) : nullptr;
    char result[384];
    if (dom == nullptr || prop == nullptr || val == nullptr) {
        snprintf(result, sizeof result, "__GHOSTLOCK_EXEC_FAILED__: null argument");
    } else {
        /* Both symbols are resolved first, before the domain switch (see platform_symbol). */
        const property_set_fn set_prop = platform_property_set();
        const property_get_fn get_prop = platform_property_get();
        if (set_prop == nullptr) {
            /* Deliberately no fallback to the vendored client: it would write the property area
             * and leave property_service (and therefore init, and therefore `ctl.*`) untouched,
             * which is the silent no-op this whole path exists to avoid. */
            snprintf(result, sizeof result,
                     "__GHOSTLOCK_EXEC_FAILED__: libc's __system_property_set is not "
                     "resolvable -- refusing the vendored client, which cannot reach "
                     "property_service");
        } else {
            char saved[256] = {};
            channel_current_context(saved, sizeof saved);
            const bool switched = channel_switch_context(dom);
            const int rc = set_prop(prop, val);
            if (switched && saved[0] != '\0' && !channel_switch_context(saved)) {
                LOGW("channel: could not switch back to %s (staying in %s)", saved, dom);
            }
            /* Informational only: `ctl.*` is a control message and need not be stored in the
             * area, so a read-back mismatch is not a failure -- it is a log line.  For the
             * real properties (`service.adb.tcp.port`) it is the value property_service kept. */
            char read_back[128] = {};
            if (get_prop != nullptr) get_prop(prop, read_back);
            LOGI("channel: setprop %s=%s in %s -> rc=%d read-back=\"%s\"", prop, val, dom, rc,
                 read_back);
            if (rc != 0) {
                snprintf(result, sizeof result,
                         "__GHOSTLOCK_EXEC_FAILED__: property_set(%s, %s) rc=%d in %s", prop, val,
                         rc, dom);
            } else {
                snprintf(result, sizeof result, "%s=%s (in %s) read-back=\"%s\"", prop, val, dom,
                         read_back);
            }
        }
    }
    if (dom) env->ReleaseStringUTFChars(domain, dom);
    if (prop) env->ReleaseStringUTFChars(name, prop);
    if (val) env->ReleaseStringUTFChars(value, val);
    return env->NewStringUTF(result);
}

/*
 * Is there a LISTEN socket on this port?  1 = yes, 0 = the tables were read and hold none,
 * -1 = the tables could not be read from here (`why` says why).
 *
 * The three answers are kept apart on purpose: "I cannot see it" is a different statement from
 * "it is not there", and the caller has to be able to decide which one it is looking at.
 */
static int proc_net_listen_scan(int port, char *why, size_t why_cap) {
    static const char *const tables[] = {"/proc/net/tcp", "/proc/net/tcp6"};
    bool readable = false;
    int first_errno = 0;
    for (const char *table : tables) {
        const int fd = open(table, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            if (first_errno == 0) first_errno = errno;
            continue;
        }
        readable = true;
        std::string text;
        char buffer[4096];
        for (;;) {
            const ssize_t n = read(fd, buffer, sizeof buffer);
            if (n > 0) {
                text.append(buffer, (size_t) n);
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            break;
        }
        close(fd);
        size_t start = 0;
        while (start < text.size()) {
            size_t end = text.find('\n', start);
            if (end == std::string::npos) end = text.size();
            const std::string line = text.substr(start, end - start);
            start = end + 1;
            char local[80] = {};
            char state[8] = {};
            /* Columns: `sl local_address rem_address st …`; sl and rem_address are skipped.
             * local_address is `<hex address>:<hex port>` and st == 0A is LISTEN. */
            if (sscanf(line.c_str(), "%*s %79s %*s %7s", local, state) != 2) continue;
            if (strcmp(state, "0A") != 0) continue;
            const char *colon = strrchr(local, ':');
            if (colon == nullptr) continue;
            if ((int) strtol(colon + 1, nullptr, 16) == port) return 1;
        }
    }
    if (!readable) {
        snprintf(why, why_cap, "%s (%d)", strerror(first_errno), first_errno);
        return -1;
    }
    why[0] = '\0';
    return 0;
}

/*
 * 3) The `ss -lnt | grep <port>` replacement: wait until the kernel reports a LISTEN on the port.
 *
 * A `connect()` probe is not available to this process (AF_INET sockets fail here, see the note
 * at the top of the file), so this walks /proc/net/tcp and /proc/net/tcp6 -- the tables `ss`
 * itself prints -- looking for a LISTEN entry with that port.
 *
 * The answer is a *string* and not a boolean, because "not listening" and "cannot read the
 * table" lead to different decisions upstream: "listening: …", "not-listening: …",
 * "unreadable: …".
 */
static jstring channel_wait_port(JNIEnv *env, jobject thiz __unused, jint port, jint timeout_ms) {
    const long long budget = timeout_ms > 0 ? timeout_ms : 60'000;
    struct timespec started{};
    clock_gettime(CLOCK_MONOTONIC, &started);
    const long long deadline =
            (long long) started.tv_sec * 1000LL + started.tv_nsec / 1000000LL + budget;
    char why[192] = {};
    for (;;) {
        const int found = proc_net_listen_scan((int) port, why, sizeof why);
        char out[288];
        if (found == 1) {
            snprintf(out, sizeof out, "listening: /proc/net/tcp{,6} holds a LISTEN on %d",
                     (int) port);
            LOGI("channel: wait_port %d -> %s", (int) port, out);
            return env->NewStringUTF(out);
        }
        if (found < 0) {
            snprintf(out, sizeof out, "unreadable: %s", why);
            LOGW("channel: wait_port %d -> %s", (int) port, out);
            return env->NewStringUTF(out);
        }
        struct timespec now{};
        clock_gettime(CLOCK_MONOTONIC, &now);
        const long long now_ms = (long long) now.tv_sec * 1000LL + now.tv_nsec / 1000000LL;
        if (now_ms >= deadline) {
            snprintf(out, sizeof out,
                     "not-listening: no LISTEN on %d in /proc/net/tcp{,6} after %lldms",
                     (int) port, budget);
            LOGW("channel: wait_port %d -> %s", (int) port, out);
            return env->NewStringUTF(out);
        }
        usleep(500 * 1000);
    }
}

/*
 * JNIEXPORT is not decoration: the whole library is compiled with
 * -fvisibility=hidden (that is what keeps the vendored resetprop from being
 * interposed by, or interposing, libc), so without it JNI_OnLoad would not be in
 * .dynsym and ART would never call it -- the registrations below would then be
 * missing and every native call would throw UnsatisfiedLinkError.
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

    /* Kept for the socket server above, which is compiled but not registered any more: its
     * derived paths still have to exist as strings, otherwise that dead code would dereference
     * null pointers if anyone re-enables it.  The command plane is the binder. */
    rsh_apply_dir();

    JNINativeMethod methods[] = {
            {"root",              "()Z", (void *) root},
            {"adb_root",          "()Z", (void *) adb_root},
            /* The command plane: three typed actions, in this process, as uid 0.  No shell and
             * no fork, so nothing can be lost to a spawned child (Android drops the escalated
             * uid there) and nothing can be frozen mid-command.
             * `start_shell_server` is no longer registered: its AF_UNIX path + token turned
             * out to be device-dependent, and the caller already holds this binder. */
            {"channel_identity",  "()Ljava/lang/String;", (void *) channel_identity},
            {"channel_set_prop",  "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (void *) channel_set_prop_in_domain},
            {"channel_wait_port", "(II)Ljava/lang/String;", (void *) channel_wait_port},
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
