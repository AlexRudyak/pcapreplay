<#
.SYNOPSIS
  Builds the pcapreplay Windows installer: dist\pcapreplay-setup-<version>.exe

.DESCRIPTION
  1. builds pcapreplay.exe (console, CLI) and pcapreplay-gui.exe (windowless, opens the GUI)
  2. renders the application icon
  3. stages files under dist\stage
  4. runs Inno Setup's ISCC.exe

  Requires Go and Inno Setup 6 (winget install JRSoftware.InnoSetup).
  Optional: put the official WinDivert.dll and WinDivert64.sys in installer\redist to bundle them.

.EXAMPLE
  powershell -File installer\build.ps1 -Version 0.2.1
#>
param(
  [string]$Version = "0.2.1",
  [string]$Iscc = ""
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# --- tools ---
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw "Go is not installed or not on PATH." }
if (-not $Iscc) {
  $Iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
            "$env:ProgramFiles\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Iscc -or -not (Test-Path $Iscc)) { throw "Inno Setup 6 not found. Install it: winget install JRSoftware.InnoSetup" }

$commit = ""
try { $commit = (git rev-parse --short HEAD 2>$null) } catch {}
$verString = if ($commit) { "$Version+$commit" } else { $Version }

# --- stage ---
$stage = Join-Path $root "dist\stage"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force "$stage\docs", "$stage\samples" | Out-Null

$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
$common = @("-trimpath")
Write-Host "Building pcapreplay.exe ($verString)..."
go build @common -ldflags "-s -w -X main.version=$verString" -o "$stage\pcapreplay.exe" .\cmd\pcapreplay
if ($LASTEXITCODE) { throw "go build failed" }
Write-Host "Building pcapreplay-gui.exe..."
go build @common -ldflags "-s -w -H=windowsgui -X main.version=$verString -X main.defaultCommand=gui" -o "$stage\pcapreplay-gui.exe" .\cmd\pcapreplay
if ($LASTEXITCODE) { throw "go build (gui) failed" }
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED

Write-Host "Rendering icon..."
go run .\cmd\mkicon -o "$stage\pcapreplay.ico"
if ($LASTEXITCODE) { throw "icon generation failed" }

Copy-Item README.md, installer\README-install.txt $stage
Copy-Item docs\*.md "$stage\docs"
Copy-Item samples\*.pcap "$stage\samples"

# --- WinDivert (optional, see fetch-windivert.ps1) ---
$redist = Join-Path $root "installer\redist"
$bundled = (Test-Path "$redist\WinDivert.dll") -and (Test-Path "$redist\WinDivert64.sys")
if ($bundled -and -not (Test-Path "$redist\WinDivert-LICENSE.txt")) {
  throw "installer\redist has WinDivert binaries but no WinDivert-LICENSE.txt: the licence text must be shipped with them."
}
if ($bundled) { Write-Host "WinDivert: bundling files from installer\redist" }
else { Write-Host "WinDivert: not bundled (run installer\fetch-windivert.ps1 to add it)" }

# --- compile the installer ---
Write-Host "Compiling installer with Inno Setup..."
& $Iscc "/DAppVersion=$Version" "/Qp" "$root\installer\pcapreplay.iss"
if ($LASTEXITCODE) { throw "ISCC failed" }

$setup = Join-Path $root "dist\pcapreplay-setup-$Version.exe"
$hash = (Get-FileHash $setup -Algorithm SHA256).Hash.ToLower()
"$hash  pcapreplay-setup-$Version.exe" | Set-Content "$setup.sha256" -Encoding ascii
Write-Host ("`nBuilt {0} ({1:N1} MB)`nSHA-256 {2}" -f $setup, ((Get-Item $setup).Length / 1MB), $hash)
