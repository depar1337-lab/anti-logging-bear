; Anti-Logging Bear by Priest

#ifndef AppVersion
  #define AppVersion "1.1.0"
#endif
#ifndef Arch
  #define Arch "x64"
#endif

[Setup]
AppId={{6F1E7C2A-9D4B-4B8E-A3B1-2C7D5E0F9A41}
AppName=Barry Bear
AppVersion={#AppVersion}
AppPublisher=Priest
DefaultDirName={localappdata}\Programs\Barry Bear
DefaultGroupName=Barry Bear
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
MinVersion=6.1sp1
OutputDir=..\dist
OutputBaseFilename=BarryBear-{#Arch}-setup
SetupIconFile=..\src\antiloggingbear\assets\app.ico
UninstallDisplayIcon={app}\BarryBear.exe
UninstallDisplayName=Barry Bear
Compression=lzma2/max
SolidCompression=yes
WizardStyle=classic
WizardImageFile=wizard-large.bmp,wizard-large@2x.bmp
WizardSmallImageFile=wizard-small.bmp,wizard-small@2x.bmp
WizardImageStretch=no
#if Arch == "x64"
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#endif

[Messages]
WelcomeLabel2=This will install Barry Bear on your computer.%n%nBarry checks downloads for keyloggers, password stealers and other malware before you open them.%n%nIt is recommended that you close all other applications before continuing.

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[InstallDelete]
Type: files; Name: "{app}\AntiLoggingBear.exe"
Type: files; Name: "{autoprograms}\Anti-Logging Bear.lnk"
Type: files; Name: "{autodesktop}\Anti-Logging Bear.lnk"

[Files]
Source: "..\dist\BarryBear\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{autoprograms}\Barry Bear"; Filename: "{app}\BarryBear.exe"
Name: "{autodesktop}\Barry Bear"; Filename: "{app}\BarryBear.exe"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Classes\*\shell\AntiLoggingBear"; Flags: uninsdeletekey dontcreatekey
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "Barry Bear"; Flags: uninsdeletevalue dontcreatekey
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "Anti-Logging Bear"; Flags: uninsdeletevalue dontcreatekey

[Run]
Filename: "{app}\BarryBear.exe"; Description: "Start Barry Bear"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{cmd}"; Parameters: "/c taskkill /im BarryBear.exe /f"; Flags: runhidden; RunOnceId: "StopApp"
