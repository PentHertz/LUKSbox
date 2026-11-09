# bench_transfer.ps1, Windows port of scripts/bench_transfer.sh: file-transfer
# throughput of `luksbox put` / `get` for each kind of vault, with a plain
# copy of the same file as reference. Numbers and their reading:
# docs/PERFORMANCE.md.
#
# Usage (Windows PowerShell 5.1 or PowerShell 7):
#   cargo build --release -p luksbox-cli
#   powershell -ExecutionPolicy Bypass -File scripts\bench_transfer.ps1 `
#       -Bin target\release\luksbox.exe -MiB 512 [-Configs "siv,bundle4,..."]
#
#   configs: raw siv gcm chacha hide pad detached bundle1 bundle4 bundle16
#            (default: all).
#
# Needs about 3x -MiB of free disk in %TEMP%. Times include the unlock
# (Argon2id, ~0.5 s with the default preset); the "open" column is that
# cost alone. Nothing outside the temporary folder is touched. Timing uses
# Process.WaitForExit: Start-Process -Wait polls about once a second and
# would round every time up to the next second.
param(
  [Parameter(Mandatory)] [string]$Bin,
  [int]$MiB = 512,
  [string[]]$Configs = @('raw','siv','gcm','chacha','hide','pad','detached','bundle4','bundle1','bundle16'),
  [string]$Work = (Join-Path $env:TEMP ("luksbox-bench-" + [guid]::NewGuid().ToString('N').Substring(0,8)))
)
$ErrorActionPreference = 'Continue'
$Bin = (Resolve-Path $Bin).Path
# `-File` passes "a,b" as one string: split it.
$Configs = @($Configs | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
New-Item -ItemType Directory -Force $Work | Out-Null
$env:LUKSBOX_PASSPHRASE = 'bench-pass'; $env:LUKSBOX_NEW_PASSPHRASE = 'bench-pass'
$env:LUKSBOX_SYNC_STATE_DIR = Join-Path $Work 'state'; $env:LUKSBOX_DEVICE_LABEL = 'bench'
$src = Join-Path $Work 'src.bin'
if (-not (Test-Path $src) -or (Get-Item $src).Length -ne [int64]$MiB * 1MB) {
  $buf = New-Object byte[] (1MB); $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  $fs = [IO.File]::Create($src); for ($i = 0; $i -lt $MiB; $i++) { $rng.GetBytes($buf); $fs.Write($buf, 0, $buf.Length) }; $fs.Close()
}
$sum = (Get-FileHash $src -Algorithm SHA256).Hash
$err = Join-Path $Work 'err.txt'
# Run luksbox; stdin is inherited (a redirected stdin pipe would count as a
# second passphrase source next to LUKSBOX_PASSPHRASE, which luksbox refuses).
function T([string[]]$a) {
  $psi = New-Object Diagnostics.ProcessStartInfo $Bin, ($a -join ' ')
  $psi.UseShellExecute = $false; $psi.RedirectStandardInput = $false
  $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $p = [Diagnostics.Process]::Start($psi)
  $eTask = $p.StandardError.ReadToEndAsync(); $null = $p.StandardOutput.ReadToEnd()
  $p.WaitForExit(); $sw.Stop()
  Set-Content $err $eTask.Result
  return @($sw.Elapsed.TotalSeconds, $p.ExitCode)
}
function Q($s) { '"' + $s + '"' }
function Clean { foreach ($n in 'v.lbx','v.hdr','v.lbxs','state','out.bin') { $x = Join-Path $Work $n; if (Test-Path $x) { Remove-Item -Recurse -Force $x } } }
$V0 = Join-Path $Work 'v.lbx'; $out = Join-Path $Work 'out.bin'
"{0,-10} {1,8} {2,9} {3,8} {4,9} {5,7}  {6}" -f 'config','put s','put MB/s','get s','get MB/s','open s','result'
foreach ($c in $Configs) {
  Clean
  if ($c -eq 'raw') {
    $sw = [Diagnostics.Stopwatch]::StartNew(); Copy-Item $src $out; $sw.Stop(); $p = $sw.Elapsed.TotalSeconds
    $sw = [Diagnostics.Stopwatch]::StartNew(); $null = Get-FileHash $out; $sw.Stop(); $g = $sw.Elapsed.TotalSeconds
    "{0,-10} {1,8:N2} {2,9:N0} {3,8:N2} {4,9:N0} {5,7}  {6}" -f 'raw-copy',$p,($MiB/$p),$g,($MiB/$g),'-','(get = sha256 read)'; continue
  }
  $cr = switch -Wildcard ($c) { 'siv' {@('--cipher','aes-256-gcm-siv')} 'gcm' {@('--cipher','aes-256-gcm')} 'chacha' {@('--cipher','chacha20-poly1305')} 'hide' {@('--hide-sizes')} 'pad' {@('--pad-files')} 'detached' {@('--header',(Q (Join-Path $Work 'v.hdr')))} default {@()} }
  $r = T (@('create',(Q $V0)) + $cr); if ($r[1] -ne 0) { "${c}: create failed: " + (Get-Content $err -Tail 3 -ErrorAction SilentlyContinue); continue }
  $V = $V0; $U = @(); if ($c -eq 'detached') { $U = @('--header',(Q (Join-Path $Work 'v.hdr'))) }
  if ($c -like 'bundle*') {
    $ps = $c.Substring(6) + 'M'; $V = Join-Path $Work 'v.lbxs'
    $r = T @('sync','convert',(Q $V0),(Q $V),'--page-size',$ps); if ($r[1] -ne 0) { "${c}: convert failed: " + (Get-Content $err -Tail 3); continue }
  }
  $o = (T (@('ls',(Q $V)) + $U + @('/')))[0]
  $r = T (@('put',(Q $V)) + $U + @((Q $src),'/big.bin')); $p = $r[0]; if ($r[1] -ne 0) { "${c}: put failed: " + (Get-Content $err -Tail 3); continue }
  $r = T (@('get',(Q $V)) + $U + @('/big.bin',(Q $out))); $g = $r[0]; if ($r[1] -ne 0) { "${c}: get failed: " + (Get-Content $err -Tail 3); continue }
  $ok = if ((Get-FileHash $out -Algorithm SHA256).Hash -eq $sum) { 'ok' } else { 'MISMATCH' }
  if ($c -like 'bundle*') { $sz = [math]::Round(((Get-ChildItem $V -Recurse -File | Measure-Object Length -Sum).Sum)/1MB); $extra = " bundle=${sz}MiB" } else { $sz = [math]::Round(((Get-ChildItem "$V0*" -File | Measure-Object Length -Sum).Sum)/1MB); $extra = " vault=${sz}MiB" }
  "{0,-10} {1,8:N2} {2,9:N0} {3,8:N2} {4,9:N0} {5,7:N2}  {6}" -f $c,$p,($MiB/$p),$g,($MiB/$g),$o,($ok+$extra)
}
Clean
Remove-Item -Recurse -Force $Work
