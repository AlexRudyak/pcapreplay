# installer

Builds the **Windows installer** (`dist/pcapreplay-setup-<version>.exe`) with [Inno Setup](https://jrsoftware.org/isinfo.php)
6 (`winget install JRSoftware.InnoSetup`).

```powershell
powershell -File installer\build.ps1 -Version 0.2.0
```

`build.ps1` builds `pcapreplay.exe` (console, CLI) and `pcapreplay-gui.exe` (windowless, opens the GUI), renders the icon
with `cmd/mkicon`, stages everything under `dist/stage`, runs `ISCC.exe` and writes a `.sha256` file.

## What the installer does (`pcapreplay.iss`)

* Installs **per user by default** (no UAC prompt); "all users" is offered.
* Start Menu shortcuts: **pcapreplay** and **pcapreplay (Administrator)** (the shortcut has the "run as administrator"
  flag set), optional desktop shortcut, optional **PATH** entry (added and removed in the `[Code]` section).
* Installs the sample capture and a short `README-install.txt`.
* Registers a normal uninstaller that removes everything it added. The history folder is **kept** on uninstall.
* Silent install: `pcapreplay-setup-0.2.0.exe /VERYSILENT /CURRENTUSER /TASKS=addpath` (`/ALLUSERS` for machine-wide).

## Bundling WinDivert (optional)

The installer includes the [WinDivert](https://github.com/basil00/WinDivert) 2.2.x driver (official release: <https://github.com/basil00/WinDivert/releases/tag/v2.2.2>) when `WinDivert.dll`, `WinDivert64.sys` and the licence are staged in
`installer/redist/` (git-ignored). `fetch-windivert.ps1` downloads the official release (or uses `-ZipPath`), checks
**pinned SHA-256 hashes**, the driver's Authenticode signature and the licence text, and stages the files.
WinDivert is LGPLv3/GPLv2 and must stay unmodified; the licence ships as `WinDivert-LICENSE.txt`. Some antivirus
products flag it (the same technique is abused by malware), so a build machine may need an exclusion for
`installer/redist` and `installer/vendor`.

## Notes

* The installer is **not code-signed**: Windows SmartScreen may show an "unknown publisher" warning. Sign it with
  `signtool` for distribution.
* `README-install.txt` is the text shown after installation.
