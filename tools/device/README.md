# Device-side helpers (OPPO PJA110 / `OP5943L1`)

Everything here is run on the handset from `adb shell` (uid 2000, no root).

## `w1-selinux.sh` — the SELinux write (W1)

The one configuration that has landed on hardware: route=3 MulticastWaiter,
`mcast_waiter_off=32`, tcp6 carrier, and the GLK1 profile whose
`kernel_phys_load=0` falls back to the compiled-in `P0_KERNEL_PHYS_LOAD=0xa8000000`
(alias of `selinux_state` → `0xffffff802b3f9990`).  See
`docs/analysis/device-gates/CPP20-20260925-w1-selinux-pass.md` for the evidence.

Deployment used on 2026-09-25 (fresh directory, hashes compared on both sides):

```
adb push <build>/ghostlock        /data/local/tmp/gl-w1/ghostlock   # md5 281fcd45035620463d702bec9fb276ba
adb push gl-w1-profile.bin        /data/local/tmp/gl-w1/profile.bin # md5 8b0ed66432e66f81ea9b9fd8ecdeb13f
adb push w1-selinux.sh            /data/local/tmp/gl-w1/w1.sh
adb shell chmod 755 /data/local/tmp/gl-w1/ghostlock /data/local/tmp/gl-w1/w1.sh

adb shell sh /data/local/tmp/gl-w1/w1.sh            # start, wait for the store, exit
adb shell sh /data/local/tmp/gl-w1/w1.sh --status   # just report state
```

Modes:

| mode | behaviour |
|---|---|
| default | starts the exploit with `setsid … > w1.log 2>&1 &`, **echoes new log lines to the screen** once a second, prints `enforce=…` when `Write 1 complete` appears (~11 s), **exit 0**. The exploit keeps running; the log is also kept in `w1.log`. |
| `--quiet` (`-q`) | same, but the log stays off the screen — it only goes to `w1.log`; the final result line is still printed. |
| `--foreground` | `exec ./ghostlock …` — blocks here, log straight on the console (the exploit parks). |
| `--status` | print `getenforce`, the `ghostlock` process and the last log lines; run nothing. |

The exploit's output goes to a *file*, not a pipe, and the screen mirror is a `tail`
of that file: if the terminal or the adb session goes away mid-run, a pipe would hand
the exploit EPIPE/SIGPIPE, and this process must never die on its own.

The script returning is safe — it is the *parked exploit process* that must stay
alive (`setsid` keeps it across the shell exiting and an adb disconnect).  Killing
that process is what wedges the kernel; a reboot is the clean exit.

Three things the script warns about, all measured:

* `--profile` must be an absolute path (a relative one fails with "cannot load
  resolved profile" even for a valid GLK1 file);
* the process parks after W1 and must not be killed — the kernel's exit-time PI
  cleanup over the forged state wedges the machine;
* the effect is not persistent (a reboot restores Enforcing) and on this handset
  the platform reacts to the activity (the system was restarted shortly after a
  landing), so W2 (cred write) needs an explicit decision.

## `cleanup-tmp.sh` — strip this project's leftovers from `/data/local/tmp`

Keeps `/data/local/tmp/gl-w1` (the working configuration) and
`/data/local/tmp/ubuntu2` (the user's Ubuntu chroot — never touched), removes this
project's logs, profiles, test binaries and staging directories, and lists every
remaining file and directory it deliberately left alone.

```
adb shell sh /data/local/tmp/gl-w1/cleanup-tmp.sh --dry-run   # print the plan
adb shell sh /data/local/tmp/gl-w1/cleanup-tmp.sh             # do it
```
