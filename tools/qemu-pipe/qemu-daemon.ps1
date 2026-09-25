# qemu-daemon.ps1 -- start the GhostLock QEMU guest ONCE and leave it running.
#
#   powershell -NoProfile -File qemu-daemon.ps1 [-Knobs "..."] [-Primed 1] [-Fresh]
#
# QEMU is spawned detached (Start-Process), so it survives this script and the
# shell that launched it.  Use qemu-status.ps1 to inspect, qemu-stop.ps1 to kill.
# With -Primed 1 the guest is booted with -S, selinux_state.enforcing is set to 1
# through the gdbstub, then the guest is released -- so W1's zero-write is
# observable (1 -> 0) without any breakpoints slowing the guest down.
param(
    [string]$Dir = 'C:\Users\ASUS\dsh\.scratch\qemu-gl',
    [string]$Initrd = 'initramfs-zero.cpio',
    [string]$Knobs = 'gl.PICK=local gl.GHOSTLOCK_MCAST_SOCKET=tcp6 gl.GHOSTLOCK_PHYS_OFFSET=0x40000000',
    [int]$Primed = 1,
    [int]$Monitor = 4449,
    [int]$Gdb = 4478,
    [int]$BootWait = 7,
    [switch]$Fresh
)
$QEMU = 'C:\msys64\ucrt64\bin\qemu-system-aarch64.exe'
$KERN = 'C:\Users\ASUS\dsh\workspace\boot\kernel'
$LOG = Join-Path $Dir 'daemon-serial.log'
$PIDF = Join-Path $Dir 'daemon.pid'

if ($Fresh) {
    Get-Process qemu-system-aarch64 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Remove-Item $LOG -Force -ErrorAction SilentlyContinue
}
if (Get-Process qemu-system-aarch64 -ErrorAction SilentlyContinue) {
    Write-Host "qemu already running (pid(s): $((Get-Process qemu-system-aarch64).Id -join ',')) -- use qemu-stop.ps1 first or pass -Fresh"
    exit 0
}

$append = "console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init nokaslr oops=panic softlockup_panic=1 loglevel=7 $Knobs"
$qargs = '-M virt -cpu max -smp 4 -m 4096 ' +
    ('-kernel {0} ' -f $KERN) + ('-initrd {0} ' -f (Join-Path $Dir $Initrd)) +
    ('-append "{0}" ' -f $append) +
    ('-serial file:{0} ' -f $LOG) +
    ('-monitor tcp:127.0.0.1:{0},server,nowait ' -f $Monitor) +
    ('-gdb tcp::{0} ' -f $Gdb) + '-S -display none'
$p = Start-Process -FilePath $QEMU -ArgumentList $qargs -WindowStyle Hidden -PassThru
$p.Id | Out-File -Encoding ascii $PIDF
Write-Host ("started qemu pid={0}  initrd={1}" -f $p.Id, $Initrd)
Write-Host ("  monitor=127.0.0.1:{0}  gdbstub=127.0.0.1:{1}  serial={2}" -f $Monitor, $Gdb, $LOG)

Start-Sleep -Seconds 3
$rsp = @'
import socket, sys, time
port = int(sys.argv[1]); prime = int(sys.argv[2]); wait = float(sys.argv[3])
def cs(d): return sum(d.encode('latin1')) & 0xff
def rd(s):
    b=b''
    while True:
        c=s.recv(1)
        if c==b'$': break
    while True:
        c=s.recv(1)
        if c==b'#': break
        b+=c
    s.recv(2); s.sendall(b'+'); return b.decode('latin1')
def cmd(s,d,wait=True):
    s.sendall(('$'+d+'#'+'%02x'%cs(d)).encode()); return rd(s) if wait else ''
s=socket.create_connection(('127.0.0.1',port),timeout=15); s.settimeout(25)
print('  stop reason:', cmd(s,'?'))
cmd(s,'c',wait=False); time.sleep(wait); s.sendall(b'\x03'); rd(s)
print('  state before prime:', cmd(s,'mffffffc00b3f9990,8'))
if prime:
    print('  prime enforcing=1 :', cmd(s,'Mffffffc00b3f9990,8:0100000000000000'),
          '->', cmd(s,'mffffffc00b3f9990,8'))
    # Host-side bootstrap: clear panic_on_oops while the target is stopped, so an
    # oops left behind by a write attempt cannot take the machine down. This keeps
    # the exploit's own write sequence to exactly one write per attempt (which is
    # the condition under which the spray lands).
    print('  panic_on_oops before:', cmd(s,'mffffffc00b160804,4'))
    print('  panic_on_oops = 0  :', cmd(s,'Mffffffc00b160804,4:00000000'),
          '->', cmd(s,'mffffffc00b160804,4'))
cmd(s,'c',wait=False)
print('  guest released (daemon keeps running)')
s.close()
'@
$rsp | Out-File -Encoding ascii (Join-Path $Dir 'rsp_boot.py')
python (Join-Path $Dir 'rsp_boot.py') $Gdb $Primed $BootWait
