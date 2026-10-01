# shot_cycle.ps1 -- boot a fresh guest with the daemon knobs, dump 4x1GiB of guest
# RAM, and locate the daemon's prim/hold pipes.  Repeats are used to check whether
# the heap layout (and therefore the shot addresses) is deterministic per boot.
#
#   powershell -NoProfile -File shot_cycle.ps1 [-Runs 2] [-Settle 45]
param(
    [string]$Dir = 'C:\Users\ASUS\dsh\.scratch\qemu-gl',
    [int]$Runs = 2,
    [int]$Settle = 45,
    [string]$Knobs = 'gl.PICK=local gl.GHOSTLOCK_MCAST_SOCKET=tcp6 gl.GHOSTLOCK_PHYS_OFFSET=0x40000000 gl.GHOSTLOCK_PIPE_DAEMON=1',
    [int]$Monitor = 4449,
    [string]$Targets = '0x103046000'
)
$py = 'C:\python\python.exe'
$addrs = @('0x40000000', '0x80000000', '0xc0000000', '0x100000000')
for ($run = 1; $run -le $Runs; $run++) {
    Write-Host "===== run $run/$Runs ====="
    & powershell -NoProfile -File (Join-Path $Dir 'qemu-daemon.ps1') -Dir $Dir -Fresh -Knobs $Knobs |
        Select-Object -Last 1
    Write-Host "  settling ${Settle}s (daemon must create its pipes)"
    Start-Sleep -Seconds $Settle

    $c = New-Object System.Net.Sockets.TcpClient('127.0.0.1', $Monitor)
    $s = $c.GetStream(); $s.ReadTimeout = 5000
    Start-Sleep -Milliseconds 300
    $b = New-Object byte[] 65536
    try { [void]$s.Read($b, 0, $b.Length) } catch {}
    for ($i = 0; $i -lt 4; $i++) {
        $name = "glr$run`_$i.bin"
        $f = Join-Path $Dir $name
        Remove-Item $f -Force -ErrorAction SilentlyContinue
        $cmd = "pmemsave $($addrs[$i]) 0x40000000 $name"
        $x = [Text.Encoding]::ASCII.GetBytes($cmd + "`n")
        $s.Write($x, 0, $x.Length); $s.Flush()
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed.TotalSeconds -lt 300) {
            Start-Sleep -Seconds 2
            if ((Test-Path $f) -and (Get-Item $f).Length -ge 1073741824) { break }
        }
    }
    $c.Close()
    Push-Location $Dir
    & $py (Join-Path $Dir 'scan_pipe.py') --chunk "glr$run`_0.bin" --chunk "glr$run`_1.bin" `
        --chunk "glr$run`_2.bin" --chunk "glr$run`_3.bin" 2>&1 |
        Select-String -Pattern 'GLPRIMBUF|ISOLATE|PIPE_BUFFER|page ' | Select-Object -First 12 |
        ForEach-Object { '  ' + $_.Line }
    Write-Host "  -- pipes --"
    & $py (Join-Path $Dir 'locate_shot.py') --chunk "glr$run`_0.bin" --chunk "glr$run`_1.bin" `
        --chunk "glr$run`_2.bin" --chunk "glr$run`_3.bin" --page $Targets 2>&1 |
        ForEach-Object { '  ' + $_ }
    Pop-Location
}
