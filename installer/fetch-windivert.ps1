<#
.SYNOPSIS
  Downloads (or takes a local copy of) the official WinDivert 2.2.2 release, verifies it and stages the files
  the installer bundles.

.DESCRIPTION
  Source : https://github.com/basil00/WinDivert/releases/tag/v2.2.2  (WinDivert-2.2.2-A.zip, 405,137 bytes)
  Result : installer\redist\WinDivert.dll, WinDivert64.sys, WinDivert-LICENSE.txt

  Verification (nothing from the archive is ever executed):
    * archive size and SHA-256 against the values pinned below (override with -ExpectedSha256)
    * extracted WinDivert.dll / WinDivert64.sys SHA-256 against pinned values. These were cross-checked against
      the byte-identical copies distributed independently through PyPI (pydivert 3.1.3).
    * WinDivert64.sys must carry a VALID Authenticode signature (Windows will only load a signed kernel driver).
      WinDivert.dll is NOT signed in official releases, so it is verified by hash and by being an x64 PE image
      that exports the WinDivert API.
    * the licence text must be present.

  Antivirus note: many scanners flag WinDivert (a packet-diverting driver that malware also abuses). If yours
  blocks the file this script stops and says so; it never changes antivirus settings.

  Licence: WinDivert is dual-licensed LGPLv3 / GPLv2. Redistributing it requires shipping the licence text (staged
  here and included by the installer) and keeping the binaries unmodified.

.EXAMPLE
  powershell -File installer\fetch-windivert.ps1                                        # download
  powershell -File installer\fetch-windivert.ps1 -ZipPath installer\vendor\WinDivert-2.2.2-A.zip
#>
param(
  [string]$ExpectedSha256 = "63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15",
  # Use an already downloaded WinDivert-2.2.2-A.zip instead of downloading it (the file is only read).
  [string]$ZipPath = ""
)
$ErrorActionPreference = "Stop"
$url      = "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip"
$expected = 405137
$pinned   = @{
  "WinDivert.dll"   = "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2"
  "WinDivert64.sys" = "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2"
}
$root   = Split-Path -Parent $PSScriptRoot
$redist = Join-Path $root "installer\redist"
$work   = Join-Path ([IO.Path]::GetTempPath()) ("windivert-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force $work | Out-Null   # an empty, isolated directory for the untrusted archive
try {
  if ($ZipPath) {
    $zip = (Resolve-Path $ZipPath).Path
    Write-Host "Using local archive $zip"
  } else {
    $zip = Join-Path $work "WinDivert-2.2.2-A.zip"
    Write-Host "Downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
  }

  try { $size = (Get-Item $zip -ErrorAction Stop).Length; $hash = (Get-FileHash $zip -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() }
  catch {
    throw ("The archive cannot be read: $($_.Exception.Message)`n" +
           "Your antivirus most likely blocked it (WinDivert is commonly flagged). This script does not change " +
           "antivirus settings. If you trust the official release, allow it yourself and run the script again, or " +
           "copy WinDivert.dll and WinDivert64.sys (x64) into $redist manually.")
  }
  if ($size -ne $expected) { throw "Unexpected archive size $size (expected $expected). Refusing to continue." }
  Write-Host "Archive SHA-256: $hash"
  if ($ExpectedSha256 -and $hash -ne $ExpectedSha256.ToLower()) { throw "Archive SHA-256 mismatch: expected $ExpectedSha256." }

  $ex = Join-Path $work "x"
  Expand-Archive -Path $zip -DestinationPath $ex
  $dll = Get-ChildItem $ex -Recurse -Filter "WinDivert.dll"   | Where-Object { $_.FullName -match "[\\/]x64[\\/]" } | Select-Object -First 1
  $sys = Get-ChildItem $ex -Recurse -Filter "WinDivert64.sys" | Where-Object { $_.FullName -match "[\\/]x64[\\/]" } | Select-Object -First 1
  $lic = Get-ChildItem $ex -Recurse -Filter "LICENSE*"        | Select-Object -First 1
  if (-not $dll -or -not $sys) { throw "x64 WinDivert.dll / WinDivert64.sys not found in the archive." }
  if (-not $lic) { throw "No LICENSE file in the archive; refusing to bundle without the licence text." }

  foreach ($f in $dll, $sys) {
    $h = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
    if ($h -ne $pinned[$f.Name]) { throw "$($f.Name) SHA-256 $h does not match the pinned value $($pinned[$f.Name])." }
    Write-Host ("{0}: SHA-256 matches the pinned value" -f $f.Name)
  }

  $sig = Get-AuthenticodeSignature $sys.FullName
  Write-Host ("WinDivert64.sys: signature {0}, signer {1}" -f $sig.Status, $sig.SignerCertificate.Subject)
  if ($sig.Status -ne "Valid") { throw "WinDivert64.sys does not carry a valid Authenticode signature ($($sig.Status)). Refusing to bundle it." }

  $bytes = [IO.File]::ReadAllBytes($dll.FullName)
  $pe = [BitConverter]::ToInt32($bytes, 0x3c)
  if ([Text.Encoding]::ASCII.GetString($bytes, $pe, 2) -ne "PE" -or [BitConverter]::ToUInt16($bytes, $pe + 4) -ne 0x8664) { throw "WinDivert.dll is not an x64 PE image." }
  $txt = [Text.Encoding]::ASCII.GetString($bytes)
  foreach ($api in "WinDivertOpen", "WinDivertRecv", "WinDivertSendEx", "WinDivertClose", "WinDivertHelperCalcChecksums") {
    if (-not $txt.Contains($api)) { throw "WinDivert.dll does not export $api." }
  }

  New-Item -ItemType Directory -Force $redist | Out-Null
  Copy-Item $dll.FullName (Join-Path $redist "WinDivert.dll")     -Force
  Copy-Item $sys.FullName (Join-Path $redist "WinDivert64.sys")   -Force
  Copy-Item $lic.FullName (Join-Path $redist "WinDivert-LICENSE.txt") -Force
  Write-Host "`nStaged in $redist. Rebuild the installer: powershell -File installer\build.ps1"
}
finally { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
