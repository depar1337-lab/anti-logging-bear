; Anti-Logging Bear by Priest

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#ifndef Arch
  #define Arch "x64"
#endif

[Setup]
AppId={{6F1E7C2A-9D4B-4B8E-A3B1-2C7D5E0F9A41}
AppName=Anti-Logging Bear
AppVersion={#AppVersion}
AppPublisher=Priest
DefaultDirName={localappdata}\Programs\Anti-Logging Bear
DefaultGroupName=Anti-Logging Bear
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
MinVersion=6.1sp1
OutputDir=..\dist
OutputBaseFilename=AntiLoggingBear-{#Arch}-setup
SetupIconFile=..\src\antiloggingbear\assets\app.ico
UninstallDisplayIcon={app}\AntiLoggingBear.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
#if Arch == "x64"
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#endif

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "..\dist\AntiLoggingBear\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{autoprograms}\Anti-Logging Bear"; Filename: "{app}\AntiLoggingBear.exe"
Name: "{autodesktop}\Anti-Logging Bear"; Filename: "{app}\AntiLoggingBear.exe"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Classes\*\shell\AntiLoggingBear"; Flags: uninsdeletekey dontcreatekey
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "Anti-Logging Bear"; Flags: uninsdeletevalue dontcreatekey

[Run]
Filename: "{app}\AntiLoggingBear.exe"; Description: "Start Anti-Logging Bear"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{cmd}"; Parameters: "/c taskkill /im AntiLoggingBear.exe /f"; Flags: runhidden; RunOnceId: "StopApp"
