pktreplay is installed.

START IT
  Start Menu > pktreplay                    opens the interface in your browser
  Start Menu > pktreplay (Administrator)    same, with the rights raw packet injection needs
  Command line (if you ticked "Add to PATH"; open a NEW terminal):
      pktreplay conversations "C:\captures\trace.pcap"
      pktreplay replay -mode udp -backend null -burst "C:\captures\trace.pcap"
      pktreplay -h

A sample capture is in the "samples" folder of the install directory.

WHAT WORKS WITHOUT ANY EXTRA FILES
  Analysis, conversation lists, filters, dry-run replays and recording work
  immediately and need no privileges.

SENDING PACKETS ONTO THE NETWORK (raw injection)
  Windows uses the WinDivert driver. If WinDivert.dll and WinDivert64.sys are in the install
  folder (this installer bundles them when they were available at build time; the licence is in
  WinDivert-LICENSE.txt), just start "pktreplay (Administrator)". Some antivirus products flag
  WinDivert because the same technique is abused by malware; allow it only if you trust this
  installer. If the files are missing, pktreplay says so and you can add them as follows.
    1. Download the official WinDivert 2.2.x release from https://reqrypt.org/windivert.html
       and verify it.
    2. Copy WinDivert.dll and WinDivert64.sys (x64) into the pktreplay install folder
       (the folder that contains pktreplay.exe).
    3. Start "pktreplay (Administrator)".
  Loopback targets (127.0.0.1) are not supported by WinDivert network-layer injection.

Only replay traffic on networks you own or are authorised to test.

UNINSTALL
  Settings > Apps > Installed apps > pktreplay, or Start Menu > Uninstall pktreplay.
  The uninstaller also removes the PATH entry it added.
