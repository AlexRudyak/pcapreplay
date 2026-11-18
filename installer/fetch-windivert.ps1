<#
.SYNOPSIS
  Downloads the official WinDivert 2.2.2 release, verifies it and stages the files the installer bundles.

.DESCRIPTION
  Source : https://github.com/basil00/WinDivert/releases/tag/v2.2.2  (WinDivert-2.2.2-A.zip, 405,137 bytes)
  Result : installer\redist\WinDivert.dll, WinDivert64.sys, WinDivert-LICENSE.txt
  Checks : exact download size, SHA-256 (printed; compared with -ExpectedSha256 when given), and a VALID
           Authenticode signature on both binaries. Nothing from the archive is executed.

  Antivirus note: many scanners flag WinDivert (a packet-diverting driver that malware also abuses). If yours
  blocks the download this script stops and says so; it never changes antivirus settings. Decide for yourself
  whether to allow it, or copy the files into installer\redist manually.

  Licence: WinDivert is dual-licensed LGPLv3 / GPLv2. Redistributing it requires shipping its licence text
  (this script stages it and the installer includes it) and keeping the driver unmodified.

.EXAMPLE
  powershell -File installer\fetch-windivert.ps1
  powershell -File installer\fetch-windivert.ps1 -ExpectedSha256 <hash you verified independently>
#>
param([string]$ExpectedSha256 = "")
$ErrorActionPreference = "Stop"
$url      = "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip"
$expected = 405137
$root     = Split-Path -Parent $PSScriptRoot
$redist   = Join-Path $root "installer\redist"
$work     = Join-Path ([IO.Path]::GetTempPath()) ("windivert-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force $work | Out-Null   # an empty, isolated directory for the untrusted download
try {
  $zip = Join-Path $work "WinDivert-2.2.2-A.zip"
  Write-Host "Downloading $url"
  Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

  try { $size = (Get-Item $zip -ErrorAction Stop).Length; $hash = (Get-FileHash $zip -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() }
  catch {
    throw ("The downloaded archive cannot be read: $($_.Exception.Message)`n" +
           "Your antivirus most likely blocked it (WinDivert is commonly flagged). This script does not change " +
           "antivirus settings. If you trust the official release, allow it yourself and run the script again, or " +
           "copy WinDivert.dll and WinDivert64.sys (x64) into $redist manually.")
  }
  if ($size -ne $expected) { throw "Unexpected download size $size (expected $expected). Refusing to continue." }
  Write-Host "SHA-256: $hash"
  if ($ExpectedSha256 -and $hash -ne $ExpectedSha256.ToLower()) { throw "SHA-256 mismatch: expected $ExpectedSha256." }
  if (-not $ExpectedSha256) { Write-Warning "No -ExpectedSha256 given: only size and signatures were checked." }

  $ex = Join-Path $work "x"
  Expand-Archive -Path $zip -DestinationPath $ex
  $dll = Get-ChildItem $ex -Recurse -Filter "WinDivert.dll"   | Where-Object { $_.FullName -match "[\\/]x64[\\/]" } | Select-Object -First 1
  $sys = Get-ChildItem $ex -Recurse -Filter "WinDivert64.sys" | Where-Object { $_.FullName -match "[\\/]x64[\\/]" } | Select-Object -First 1
  $lic = Get-ChildItem $ex -Recurse -Filter "LICENSE*"        | Select-Object -First 1
  if (-not $dll -or -not $sys) { throw "x64 WinDivert.dll / WinDivert64.sys not found in the archive." }
  if (-not $lic) { throw "No LICENSE file in the archive; refusing to bundle without the licence text." }

  foreach ($f in $dll, $sys) {
    $sig = Get-AuthenticodeSignature $f.FullName
    Write-Host ("{0}: signature {1}, signer {2}" -f $f.Name, $sig.Status, $sig.SignerCertificate.Subject)
    if ($sig.Status -ne "Valid") { throw "$($f.Name) does not carry a valid Authenticode signature ($($sig.Status)). Refusing to bundle it." }
  }

  New-Item -ItemType Directory -Force $redist | Out-Null
  Copy-Item $dll.FullName (Join-Path $redist "WinDivert.dll")     -Force
  Copy-Item $sys.FullName (Join-Path $redist "WinDivert64.sys")   -Force
  Copy-Item $lic.FullName (Join-Path $redist "WinDivert-LICENSE.txt") -Force
  Write-Host "`nStaged in $redist. Rebuild the installer: powershell -File installer\build.ps1"
}
finally { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
