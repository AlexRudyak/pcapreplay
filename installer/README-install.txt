pcapreplay is installed.

START IT
  Start Menu > pcapreplay                    opens the interface in your browser
  Start Menu > pcapreplay (Administrator)    same, with the rights raw packet injection needs
  Command line (if you ticked "Add to PATH"; open a NEW terminal):
      pcapreplay conversations "C:\captures\trace.pcap"
      pcapreplay replay -mode udp -backend null -burst "C:\captures\trace.pcap"
      pcapreplay -h

A sample capture is in the "samples" folder of the install directory.

HISTORY
  pcapreplay keeps a history of what you send and a library of the pcap files you sent (so you can send
  them again even if the original moves). It lives in %LOCALAPPDATA%\pcapreplay\history and is NOT removed
  when you uninstall; delete that folder yourself if you want it gone. Open History in the header to
  browse, export or clear it, and to change what is kept.

If the interface does not appear or closes, read the log:
  %LOCALAPPDATA%\pcapreplay\pcapreplay-gui.log
Starting pcapreplay.exe by double-click or "Run as administrator" also opens the interface (keep that
console window open while you use it). If your browser cannot be launched, pcapreplay shows a dialog
with the address to open.

WHAT WORKS WITHOUT ANY EXTRA FILES
  Analysis, conversation lists, filters, dry-run replays and recording work
  immediately and need no privileges.

SENDING PACKETS ONTO THE NETWORK (raw injection)
  Windows uses the WinDivert driver. If WinDivert.dll and WinDivert64.sys are in the install
  folder (this installer bundles them when they were available at build time; the licence is in
  WinDivert-LICENSE.txt), just start "pcapreplay (Administrator)". Some antivirus products flag
  WinDivert because the same technique is abused by malware; allow it only if you trust this
  installer. If the files are missing, pcapreplay says so and you can add them as follows.
    1. Download the official WinDivert 2.2.x release from https://github.com/basil00/WinDivert/releases (the official
       repository; project site: https://reqrypt.org/windivert.html)
       and verify it.
    2. Copy WinDivert.dll and WinDivert64.sys (x64) into the pcapreplay install folder
       (the folder that contains pcapreplay.exe).
    3. Start "pcapreplay (Administrator)".
  Loopback targets (127.0.0.1) are not supported by WinDivert network-layer injection.

Only replay traffic on networks you own or are authorised to test.

UNINSTALL
  Settings > Apps > Installed apps > pcapreplay, or Start Menu > Uninstall pcapreplay.
  The uninstaller also removes the PATH entry it added.
