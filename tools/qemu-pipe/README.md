# QEMU pipe-primitive harness

Scripts used to verify the pipe-buffer substitution (arbitrary kernel page
read/write) against the PJA110 kernel in QEMU.  See
`docs/analysis/pipe-primitive-qemu-20260925.md` for the results and the plant
recipe.

Flow:

| step | script |
|---|---|
| build the exploit for the guest (`clang++ --target=aarch64-linux-android35 -static`) | `../../` roots; the NDK command line is in the session notes |
| patch `kernel_phys_load` in the GLK1 profile and repack the guest initramfs | `mkprofile_zero.py all` |
| start the guest detached with `-S`, prime `enforcing=1` and `panic_on_oops=0` through the gdbstub, release | `qemu-daemon.ps1` |
| dump guest RAM (four 1 GiB chunks; the monitor parses sizes as 32-bit, and needs paths relative to the QEMU working directory) | `shot_cycle.ps1` or the same `pmemsave` loop |
| find pipe buffer pages by content, and `pipe_inode_info` by field pattern + `bufs[slot].page` validation | `scan_pipe.py`, `find_pipes.py`, `locate_shot.py` |
| plant `bufs[i].page` / `offset|len` / `flags=CAN_MERGE` through the gdbstub in physical mode (`Qqemu.PhyMemMode:1`, target halted), then read back the target page | `shot_patch.py` |

Guest-side setup for the read/write shot:

```
gl.GHOSTLOCK_PIPE_DAEMON=1 gl.GHOSTLOCK_PIPE_SHOT_ONLY=1 \
gl.GHOSTLOCK_PIPE_SHOT_READ=8 gl.GHOSTLOCK_PIPE_SHOT_LOOP=8
```

The shot loops inside one guest process because only round 1 ever executes the
freshly staged binary (later rounds fall back to a missing `/ghostlock` and exit
with status `0x7f00`).
