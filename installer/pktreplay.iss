; Inno Setup script for pktreplay (Windows x64).
; Build with installer\build.ps1, which stages the files under dist\stage and
; calls ISCC with /DAppVersion=<version>.

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#define AppName "pktreplay"
#define Stage "..\dist\stage"

[Setup]
; Never change AppId: it identifies the product for upgrades and uninstall.
AppId={{598A8418-56AC-43B8-ABBC-57951B040CDD}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=pktreplay
AppComments=Streaming PCAP/PCAPNG analysis and replay
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
DisableDirPage=auto
; Per-user install by default (no UAC prompt); the user may choose "all users".
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=pktreplay-setup-{#AppVersion}
SetupIconFile={#Stage}\pktreplay.ico
UninstallDisplayIcon={app}\pktreplay.ico
UninstallDisplayName={#AppName} {#AppVersion}
VersionInfoVersion={#AppVersion}.0
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes
CloseApplications=yes
RestartApplications=no
UsePreviousTasks=yes
InfoAfterFile={#Stage}\README-install.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "addpath"; Description: "Add pktreplay to the &PATH (run it from any terminal)"; GroupDescription: "Command line:"
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
Source: "{#Stage}\pktreplay.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Stage}\pktreplay-gui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Stage}\pktreplay.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Stage}\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Stage}\README-install.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Stage}\docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs
Source: "{#Stage}\samples\*"; DestDir: "{app}\samples"; Flags: ignoreversion recursesubdirs
; The WinDivert driver is only bundled when its official files were placed in
; installer\redist before building (see README-install.txt for the licence note).
#if FileExists(AddBackslash(SourcePath) + "redist\WinDivert64.sys")
Source: "redist\WinDivert.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "redist\WinDivert64.sys"; DestDir: "{app}"; Flags: ignoreversion
#endif

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\pktreplay-gui.exe"; IconFilename: "{app}\pktreplay.ico"; Comment: "Analyze and replay packet captures"
Name: "{autoprograms}\{#AppName} (Administrator)"; Filename: "{app}\pktreplay-gui.exe"; IconFilename: "{app}\pktreplay.ico"; Comment: "Needed for raw packet injection"
Name: "{autoprograms}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\pktreplay-gui.exe"; IconFilename: "{app}\pktreplay.ico"; Tasks: desktopicon

[Run]
; Mark the "(Administrator)" shortcut as "Run as administrator" (bit 0x20 of byte 0x15 of the .lnk).
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""$p='{autoprograms}\{#AppName} (Administrator).lnk'; $b=[IO.File]::ReadAllBytes($p); $b[21]=$b[21] -bor 32; [IO.File]::WriteAllBytes($p,$b)"""; Flags: runhidden; StatusMsg: "Configuring the Administrator shortcut..."
Filename: "{app}\pktreplay-gui.exe"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[Code]
const
  UserEnvKey = 'Environment';
  SystemEnvKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function EnvRoot: Integer;
begin
  if IsAdminInstallMode then Result := HKEY_LOCAL_MACHINE else Result := HKEY_CURRENT_USER;
end;

function EnvKey: String;
begin
  if IsAdminInstallMode then Result := SystemEnvKey else Result := UserEnvKey;
end;

function PathContains(const Path, Dir: String): Boolean;
begin
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Path) + ';') > 0;
end;

procedure AddToPath(const Dir: String);
var
  Old: String;
begin
  if not RegQueryStringValue(EnvRoot, EnvKey, 'Path', Old) then Old := '';
  if PathContains(Old, Dir) then Exit;
  if (Old <> '') and (Old[Length(Old)] <> ';') then Old := Old + ';';
  RegWriteExpandStringValue(EnvRoot, EnvKey, 'Path', Old + Dir);
end;

procedure RemoveFromPath(const Dir: String);
var
  Old, Work: String;
  P: Integer;
begin
  if not RegQueryStringValue(EnvRoot, EnvKey, 'Path', Old) then Exit;
  Work := ';' + Old + ';';
  P := Pos(';' + Uppercase(Dir) + ';', Uppercase(Work));
  if P = 0 then Exit;
  Delete(Work, P, Length(Dir) + 1);          { remove "<dir>;" keeping the leading separator }
  if (Length(Work) > 0) and (Work[1] = ';') then Delete(Work, 1, 1);
  if (Length(Work) > 0) and (Work[Length(Work)] = ';') then Delete(Work, Length(Work), 1);
  RegWriteExpandStringValue(EnvRoot, EnvKey, 'Path', Work);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('addpath') then
    AddToPath(ExpandConstant('{app}'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
end;
