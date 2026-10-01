# Pipe-buffer substitution: arbitrary kernel page read/write — QEMU verification (2026-09-25)

Verified in the QEMU guest (`-M virt -cpu max -smp 4 -m 4096`, the PJA110 kernel
image, `nokaslr`), with the host cross-checking every claim against an independent
physical RAM dump (`pmemsave`).  Nothing below is inferred from the source alone.

## 1. What is proven

**Read direction** — plant `bufs[i].page` with the vmemmap view of the target page
(`struct page *p = VMEMMAP + ((phys - memstart_addr) >> 12) * 0x40`), then let the
daemon `read()` the pipe:

```
pipe shot 10 READ: X 8 0 80993f0bc0ffffff          <- bytes returned by read()
host dump of phys 0x435f9000 + 0x980 = 80993f0bc0ffffff
```

The page is the one holding `selinux_state` (its `+0x990` word is the
`0100000000000000` that the host primed with `enforcing=1` through the gdbstub), so
the returned bytes are the target page's content, byte for byte.

**Write direction** — same plant plus `flags |= PIPE_BUF_FLAG_CAN_MERGE (0x10)`,
then a merge write through the pipe lands in the target page:

```
target page +0x980 : 80993f0bc0ffffff 80474c50495045534c54...   ("GLPIPESLT" x4)
contains "GLPIPESLT": True
slot0 now: page=fffffffe000d7e40 off=0x9a0 len=0xd ops=anon flags=CAN_MERGE
```

## 2. The plant recipe (3 fields, and CAN_MERGE is mandatory)

```
bufs[i].page        = VMEMMAP + ((phys - memstart_addr) >> 12) * 0x40   (pointer write)
bufs[i].offset|len  = one 8-byte write, low u32 = offset, high u32 = len
bufs[i].flags       = PIPE_BUF_FLAG_CAN_MERGE (0x10)
```

* **`flags` is not optional.** `pipe_write()` treats a slot without CAN_MERGE as
  empty and allocates a *real* page into it, silently overwriting the planted page
  pointer (measured: the next read fell back to the daemon's own anon page).
* The value domain of the stale-waiter write primitive is **kernel pointers and
  zero**, which is exactly enough: `page` is a pointer, and `offset|len` can be a
  *page-aligned* pointer (low 32 = 0 → offset 0, high 32 ≈ 0xfffffffe → len ≈ 4 GiB).
* `offset` and `len` then drift exactly like the model predicts: `offset += ret` on
  read, `len += n` on a merge write (measured `0x980 → 0x988 → 0x990 → ... → 0x9a0`).
  Once `offset + want > 0x1000` the window is dead until it is re-armed; a read that
  empties `len` releases the buffer and advances `tail`.

## 3. Read-path facts taken from the image (`llvm-objdump` on `vmlinux.rel0.elf`)

* `__copy_page_to_iter` / `copy_page_to_iter_iovec` compute `kaddr` as a *pure linear
  function of the page pointer* with no validation — `__va(PFN_PHYS(page_to_pfn(page)))`,
  i.e. upstream's `page_to_direct()` — so any forged `struct page *` names a page.
* `copy_page_to_iter()` does **not** allow crossing the page: its inlined
  `page_copy_sane()` requires `offset + bytes <= 0x1000` for a non-compound page,
  otherwise it takes the compound branch (test `page->flags` bit 16, order at
  `page+0x51`) and for order-0 pages hits `brk #0x800`.  That is a **WARN**, not a
  BUG: the instruction after it is a live `return 0`, so `read()` gets EFAULT and the
  buffer's `offset`/`len` are left untouched (recoverable, no `tail++`).
* Consequence: one arm covers at most `0x1000 - offset` bytes.  Linear scanning at
  ~1 write per page only works if the target is a compound (order ≥ 1) page;
  kernel-image/slab targets are order-0, so **2 writes per page** (random and
  linear alike).

## 4. Daemon hardening (all four verified in the guest)

| item | mechanism | evidence |
|---|---|---|
| page reference floor | `tee(prim → hold)` duplicates the buffer ⇒ +1 ref on its page; the hold pipe is never closed | `T 9 -> T 9 0`; the hold pipe's slot0 was later found live with `len=9, ops=anon_pipe_buf_ops` and `page` = our page |
| geometry cache | `B <pipe> <bufs> <ring>` + `F_GETPIPE_SZ` cross-check; `F_SETPIPE_SZ` never called | `stale=0 mismatch=0` for the true ring, `stale=1 mismatch=1` for a drifted one |
| window ledger | `A <len> [<off>]` + `X <n>` that refuses `n >= len` and `n + off > 0x1000`, following the *actual* `ret` | `X 18` (== armed) → `X -1 22`; `X 257 off=0xF00` → refused; `X 256` → allowed; ledger tracked a short read (`armed=291 off=3849`) |
| pipe isolation | selftest pipe ≠ primitive pipe ≠ hold pipe | selftest still round-trips after primitive ops |

## 5. Bugs found and fixed along the way

* **The daemon inherited the caller's stdout.** This initramfs has no `/dev/null`,
  so the `dup2` was silently skipped; the parent's capture pipe never reached EOF and
  every round tripped a 20 s watchdog with no output from later rounds.  Now sinks to
  `/tmp/gl-daemon.out` and closes inherited fds 3..63.  This bites on the device too.
* `prim_arm()`/`tee_hold()` did not consume their replies, so the daemon socket
  stream desynced and a read reported the previous `A 9 0 0` reply as its own.
* The QEMU monitor parses `pmemsave` sizes as 32-bit: `0x100000000` silently does
  nothing, so RAM is dumped in four 1 GiB chunks (`pmemsave 0x40000000/0x80000000/
  0xc0000000/0x100000000 0x40000000`).  Absolute Windows paths also fail — use a
  path relative to the QEMU working directory.

## 6. Locating `pipe->bufs` (and why the device still needs its own answer)

Host side (prototype) the pipe objects are found in a RAM dump by pattern:
the pipe buffer page by its content (`GLPRIMBUF`/`GLPIPESLT`), then pipes by
scanning the kmalloc region for `{head,tail,max_usage,ring_size}` at `+0x60..+0x6c`
with a `bufs` pointer at `+0xa8`, then validating `bufs[slot].page` against the
page's vmemmap pointer (`tools/qemu-pipe/`).  In one boot the daemon's prim pipe was
`pipe_inode_info=0xffffff80c0223000 bufs=0xffffff80c030e400 ring=16`.

This is **not** available on the device, and the layout is not stable across boots
(prim buffer page was `0x1030b7000` in one boot and `0x1013cd000` in the next), so a
boot-cmdline constant cannot work either.  The device needs a locator that survives
per-boot heap randomness — the promising shape is an oracle-based blind search: write
a distinctive `len` (a pointer value whose low 32 bits are non-zero) into candidate
`bufs[i]` slots and use `ioctl(FIONREAD)` on the daemon's pipe as the oracle, with a
coarse slab-window hint to keep the candidate set small.

## 7. Harness notes

* Only round 1 ever executes the freshly staged binary: later rounds log
  `copy failed: /b-local` → `staged binary: FALLBACK /ghostlock` → exec a missing path
  → `exploit status=0x7f00`.  The guest-side shot therefore loops *inside* one process
  (`GHOSTLOCK_PIPE_SHOT_ONLY=1`, `GHOSTLOCK_PIPE_SHOT_LOOP=<secs>`); the init's 20 s
  watchdog only logs, it does not kill.
* `tools/qemu-pipe/shot_patch.py` plants through the QEMU gdbstub in **physical**
  memory mode (`Qqemu.PhyMemMode:1`), which is how the prototype stands in for the
  exploit's one-write plant; phy-mode packets must be sent while the target is halted.

## 8. Still open

* The exploit-side plant (`GHOSTLOCK_PIPE_SHOT_BUFS` + `GHOSTLOCK_W1_TARGET_ABS` +
  `GHOSTLOCK_WRITE_WORD`) is coded but not yet exercised: it needs an in-guest
  transport for the per-boot addresses (a host-published mailbox page is the current
  candidate), or the device locator from §6.
* A `B <hexaddr>`-style cache verb on the daemon should be extended to record
  `ring_size` alongside `bufs`, with a `F_GETPIPE_SZ` assertion on every use.
