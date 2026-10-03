/*
 * gl_server.c -- the uid-0 command server behind libmagica2.so.
 *
 * One process holds the privileged link; every other process submits commands.
 * The listener is bound on 127.0.0.1 only (never 0.0.0.0: this hands out uid-0
 * command execution) and gated by a token that the app writes into its own
 * private directory.
 *
 * Hosting
 *   primary : called from the JNI library inside the isolated uid-0 process
 *             (permissive SELinux allows bind/listen there);
 *   fallback: this same file compiled as an executable (-DGL_SERVER_MAIN) can be
 *             re-exec'd under another domain, e.g.
 *                 /system/bin/runcon u:r:system_server:s0 glserver --port 5038 --token T
 *             so a device where the isolated process cannot bind still gets a
 *             listener -- the caller falls back when gl_server_run() reports
 *             GL_ERR_BIND.
 *
 * Wire protocol (line oriented, so `nc` works by hand and Java uses the same
 * shape; length-prefixing was rejected as it cannot be driven from a terminal):
 *
 *   S->C  "GHOSTLOCK/1\n"                 banner
 *   C->S  "<token>\n"                     first line
 *   S->C  "OK\n" | "ERR token\n"          (ERR: server closes)
 *         "ERR no-token\n"                the server holds NO token -> it refuses everyone
 *
 *   FAIL CLOSED: the listener is 127.0.0.1, and on Android loopback is not a security boundary
 *   (any installed app may connect).  An empty token therefore means "nobody", not "anybody":
 *   with no token staged the server does not even start (GL_ERR_ARG), and a client that reaches
 *   a server without one is refused.  The app treats that as a retryable staging failure.
 *   then, once per command:
 *   C->S  "<command line>\n"              e.g.  rmmod oplus_security_guard
 *   S->C  <command output, verbatim>      stdout+stderr, no framing
 *         "__GL_EXIT__ <rc>\n"            always exactly one terminator
 *
 *   Directives are whole lines starting with '@'; they produce no output and
 *   apply to the NEXT command:
 *      @t <ms>            per-command timeout (default 30000)
 *      @domain <selinux>  run it as /system/bin/runcon <selinux> sh -c <cmd>
 *   Builtins:  @id      run /system/bin/id and return it
 *              @quit    close this connection
 *
 *   Every command is  fork + setgroups(0)/setresgid(0,0,0)/setresuid(0,0,0) +
 *   exec  -- a JVM-spawned child drops to the app uid (measured 90000), and a
 *   borrowed domain is never what property_service authorises, so the child has
 *   to be made root explicitly and exec on its own.
 *
 * nc usage:   printf '<token>\nid\n' | nc 127.0.0.1 5038
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

#define GL_BANNER      "GHOSTLOCK/1\n"
#define GL_EXIT_TAG    "__GL_EXIT__ "
#define GL_FAIL_TAG    "__GHOSTLOCK_EXEC_FAILED__: "
#define GL_LINE_MAX    4096
#define GL_DEF_TIMEOUT 30000
#define GL_DEF_PORT    5038

/*
 * One log line per interesting event, into logcat.
 *
 * This file is loaded into the isolated process (where stderr goes nowhere) and also builds as
 * the standalone engine server, so: logcat on Android, stderr otherwise.  Without it a failed
 * `bind` reached the caller as a bare `rc=-1`, and "-1" cannot be told from "-1" -- while
 * EADDRINUSE (a listener left behind by a previous isolated process) and EACCES (a seccomp
 * filter or a MAC denial that "Seccomp 0 + permissive" was supposed to have removed) need
 * opposite reactions.
 */
#if defined(__ANDROID__)
#include <android/log.h>
#define GL_TAG "GhostlockRoot"
#define gl_loge(...) __android_log_print(ANDROID_LOG_ERROR, GL_TAG, __VA_ARGS__)
#define gl_logw(...) __android_log_print(ANDROID_LOG_WARN, GL_TAG, __VA_ARGS__)
#define gl_logi(...) __android_log_print(ANDROID_LOG_INFO, GL_TAG, __VA_ARGS__)
#else
#define gl_loge(...) do { fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } while (0)
#define gl_logw(...) gl_loge(__VA_ARGS__)
#define gl_logi(...) gl_loge(__VA_ARGS__)
#endif

enum { GL_OK = 0, GL_ERR_BIND = -1, GL_ERR_ARG = -2 };

static long gl_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void gl_reply(int fd, const char *fmt, ...)
{
    char buf[GL_LINE_MAX];
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);
    if (n > 0) (void) !write(fd, buf, (size_t) n);
}

/* read up to a newline, no buffering (commands are small and rare) */
static int gl_read_line(int fd, char *out, size_t cap)
{
    size_t n = 0;
    for (;;) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r == 0) return n ? (int) n : -1;
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (c == '\n' || c == '\r') {
            if (n == 0) continue;               /* tolerate blank lines */
            out[n] = '\0';
            return (int) n;
        }
        if (n + 1 >= cap) { out[cap - 1] = '\0'; return (int) n; }
        out[n++] = c;
    }
}

/*
 * fork + become real root + exec.  Output is streamed to the client as it arrives,
 * with a per-command timeout that SIGKILLs the whole child.  Returns the child's
 * exit status (or -1), and sets *failed when the command could not even be
 * started -- the client sees GL_FAIL_TAG for that case so a refused setprop can
 * never look like an empty success.
 */
static int gl_run(int fd, const char *cmd, int timeout_ms,
                  const char *domain, int *failed)
{
    int p[2];
    pid_t pid;
    long deadline;
    int rc = -1, status = 0;

    *failed = 0;
    if (pipe(p) < 0) { gl_reply(fd, GL_FAIL_TAG "pipe: %s\n", strerror(errno)); *failed = 1; return -1; }

    pid = fork();
    if (pid < 0) {
        gl_reply(fd, GL_FAIL_TAG "fork: %s\n", strerror(errno));
        close(p[0]); close(p[1]); *failed = 1; return -1;
    }
    if (pid == 0) {
        close(p[0]);
        (void) dup2(p[1], 1);
        (void) dup2(p[1], 2);
        if (p[1] > 2) close(p[1]);
        /* the JVM-spawned child drops to the app uid; make this one root and keep
         * it that way across exec (real = effective = saved = 0) */
        (void) setgroups(0, NULL);
        (void) setresgid(0, 0, 0);
        (void) setresuid(0, 0, 0);
        if (domain && *domain)
            execl("/system/bin/runcon", "runcon", domain, "/system/bin/sh", "sh", "-c", cmd, (char *) NULL);
        else
            execl("/system/bin/sh", "sh", "-c", cmd, (char *) NULL);
        _exit(127);
    }
    close(p[1]);
    deadline = gl_now_ms() + (timeout_ms > 0 ? timeout_ms : GL_DEF_TIMEOUT);
    for (;;) {
        struct pollfd pfd = { .fd = p[0], .events = POLLIN };
        long left = deadline - gl_now_ms();
        char buf[4096];
        ssize_t n;
        if (left <= 0) { kill(pid, SIGKILL); break; }
        if (poll(&pfd, 1, (int) left) == 0) { kill(pid, SIGKILL); break; }
        n = read(p[0], buf, sizeof(buf));
        if (n == 0) break;
        if (n < 0) { if (errno == EINTR) continue; break; }
        if (write(fd, buf, (size_t) n) < 0) { kill(pid, SIGKILL); break; }
    }
    close(p[0]);
    (void) waitpid(pid, &status, 0);
    if (WIFEXITED(status)) rc = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) rc = 128 + WTERMSIG(status);
    return rc;
}

static void gl_serve_client(int fd, const char *token)
{
    char line[GL_LINE_MAX], domain[128] = "";
    int timeout_ms = GL_DEF_TIMEOUT;

    gl_reply(fd, GL_BANNER);
    if (gl_read_line(fd, line, sizeof(line)) <= 0) return;
    if (!token || !*token) {
        /* FAIL CLOSED, and this check is the point of the whole handshake.
         *
         * The listener is on 127.0.0.1, which on Android is NOT a security boundary: every
         * installed app may connect to loopback without any permission.  So "no token was
         * staged" must never mean "anyone may drive uid 0" -- it means nobody may.  The app
         * side treats an empty token as a *retryable staging failure* (it re-pushes the token)
         * and the chain still has the root-adbd transport, so refusing here costs a fallback,
         * while accepting would hand uid-0 command execution to any local process. */
        gl_loge("gl_server: refusing a client -- no token was staged (fail closed); "
                "the app must push the token file first");
        gl_reply(fd, "ERR no-token\n");
        return;
    }
    if (strcmp(line, token) != 0) {
        gl_logw("gl_server: refusing a client -- wrong token");
        gl_reply(fd, "ERR token\n");
        return;
    }
    gl_reply(fd, "OK\n");

    while (gl_read_line(fd, line, sizeof(line)) > 0) {
        if (strcmp(line, "@quit") == 0) return;
        if (strncmp(line, "@t ", 3) == 0) { timeout_ms = atoi(line + 3); gl_reply(fd, "OK\n"); continue; }
        if (strncmp(line, "@domain ", 8) == 0) {
            snprintf(domain, sizeof(domain), "%s", line + 8);
            gl_reply(fd, "OK\n");
            continue;
        }
        {
            const char *cmd = line;
            int failed = 0, rc;
            if (strcmp(line, "@id") == 0) cmd = "/system/bin/id";
            rc = gl_run(fd, cmd, timeout_ms, domain, &failed);
            if (!failed) gl_reply(fd, GL_EXIT_TAG "%d\n", rc);
        }
    }
}

/*
 * Bind + listen + accept loop.  Sequential on purpose: the privileged link is a
 * single resource, so one command runs at a time (same shape as the app's
 * AdbService gate).  Returns GL_ERR_BIND when the listener cannot be created --
 * the caller then re-execs this program under another domain.
 */
static int gl_listen_socket(int port)
{
    int srv, on = 1;
    struct sockaddr_in sa;
    const int use_port = port > 0 ? port : GL_DEF_PORT;

    signal(SIGPIPE, SIG_IGN);
    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        /* EACCES/EPERM here means this process still has a seccomp filter (or a MAC denial):
         * exactly the preconditions part 2 is supposed to have removed. */
        gl_loge("gl_server: socket(AF_INET) failed: %s (%d)", strerror(errno), errno);
        return -1;
    }
    (void) setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t) use_port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);      /* 127.0.0.1 only */
    if (bind(srv, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
        /* EADDRINUSE(98): a listener from an earlier isolated process still holds the port --
         * the 3-round restart can leave one behind for a moment, so this is retryable and has
         * to be readable as such; EACCES(13): the listener is not allowed here at all. */
        gl_loge("gl_server: bind 127.0.0.1:%d failed: %s (%d)", use_port, strerror(errno), errno);
        close(srv);
        return -1;
    }
    if (listen(srv, 4) != 0) {
        gl_loge("gl_server: listen(127.0.0.1:%d) failed: %s (%d)", use_port, strerror(errno),
                errno);
        close(srv);
        return -1;
    }
    gl_logi("gl_server: listening on 127.0.0.1:%d", use_port);
    return srv;
}

struct gl_accept_args { int srv; char token[256]; };

/** Who is on the other end, for the log: loopback has no other identity to show. */
static int gl_peer_uid(int fd)
{
    struct ucred cr;
    socklen_t len = sizeof(cr);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len) != 0) return -1;
    return (int) cr.uid;
}

static void *gl_accept_loop(void *arg)
{
    struct gl_accept_args *a = (struct gl_accept_args *) arg;
    for (;;) {
        int c = accept(a->srv, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR) continue;
            gl_loge("gl_server: accept failed: %s (%d)", strerror(errno), errno);
            break;
        }
        gl_logi("gl_server: client uid=%d connected", gl_peer_uid(c));
        gl_serve_client(c, a->token);
        close(c);
    }
    close(a->srv);
    free(a);
    return NULL;
}

/*
 * Start the listener without blocking the caller: the bind happens here (so the
 * caller learns whether it worked), the accept loop runs in a detached thread.
 * When the bind fails, fork a child that keeps uid 0, switches to the
 * system_server domain and re-execs the (already staged) engine in --glserver
 * mode -- runcon is the fallback for *listening*, nothing else.  Returns 0 when
 * a listener exists in either place, GL_ERR_BIND otherwise.
 */
int gl_server_start(int port, const char *token, const char *engine_path)
{
    int srv;

    if (!token || !*token) {
        /* No token staged: do NOT open a uid-0 listener at all (see gl_serve_client).  The
         * caller sees GL_ERR_ARG, the app re-stages the token and retries -- a missing token is
         * a retryable staging failure, never an escalation failure. */
        gl_loge("gl_server: refusing to start -- empty token (fail closed)");
        return GL_ERR_ARG;
    }
    srv = gl_listen_socket(port);
    if (srv >= 0) {
        struct gl_accept_args *a = (struct gl_accept_args *) calloc(1, sizeof(*a));
        pthread_t th;
        if (!a) { close(srv); return GL_ERR_BIND; }
        a->srv = srv;
        snprintf(a->token, sizeof(a->token), "%s", token ? token : "");
        if (pthread_create(&th, NULL, gl_accept_loop, a) != 0) { close(srv); free(a); return GL_ERR_BIND; }
        pthread_detach(th);
        return GL_OK;
    }
    if (engine_path && *engine_path) {
        pid_t p = fork();
        if (p == 0) {
            char ports[16];
            snprintf(ports, sizeof(ports), "%d", port > 0 ? port : GL_DEF_PORT);
            (void) setgroups(0, NULL);
            (void) setresgid(0, 0, 0);
            (void) setresuid(0, 0, 0);
            execl("/system/bin/runcon", "runcon", "u:r:system_server:s0",
                  engine_path, "--glserver", "--port", ports,
                  "--token", token ? token : "", (char *) NULL);
            _exit(127);
        }
        if (p > 0) return GL_OK;      /* the child owns the listener now */
    }
    return GL_ERR_BIND;
}

int gl_server_run(int port, const char *token)
{
    int srv;

    if (!token || !*token) {
        gl_loge("gl_server: refusing to run -- empty token (fail closed)");
        return GL_ERR_ARG;
    }
    srv = gl_listen_socket(port);

    if (srv < 0) return GL_ERR_BIND;

    for (;;) {
        int c = accept(srv, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR) continue;
            gl_loge("gl_server: accept failed: %s (%d)", strerror(errno), errno);
            break;
        }
        gl_logi("gl_server: client uid=%d connected", gl_peer_uid(c));
        gl_serve_client(c, token);
        close(c);
    }
    close(srv);
    return GL_OK;
}

#ifdef GL_SERVER_MAIN
int main(int argc, char **argv)
{
    int port = GL_DEF_PORT;
    const char *token = "";
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) token = argv[++i];
    }
    if (!*token) {
        fprintf(stderr, "glserver: --token is required -- refusing to serve uid-0 commands "
                        "without one\n");
        return 2;
    }
    return gl_server_run(port, token) == GL_OK ? 0 : 1;
}
#endif
