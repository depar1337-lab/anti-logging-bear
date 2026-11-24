# Changelog

## 1.3.0

- Opens installers and more archive types with a bundled 7-Zip: NSIS installers, self-extracting archives, MSI, CAB, CHM, ISO and DMG, plus every RAR version
- Check a whole folder from the window, the right-click menu, drag and drop or the command line
- Verifies Windows code signatures: shows who signed a program, and flags tampered programs and revoked certificates
- The web app opens 7z and RAR archives
- Faster: script checks run about twice as fast, and the community rules load in under a second the first time
- Fewer false alarms on signed software, browsers and Chromium-based apps, installers, and .NET apps that store their own logins
- Signing-ready builds (see docs/SIGNING.md) and a benchmark tool for measuring detection

## 1.2.0

- Over 10,000 community YARA rules from YARA Forge, downloaded weekly and kept compressed so antivirus doesn't mistake them for malware
- Looks inside PyInstaller programs and reads their Python code
- Reads .NET programs' imports, classes and embedded resources, and spots obfuscators like ConfuserEx
- Reads the JavaScript inside Electron apps (app.asar)
- Opens 7z and RAR archives, including password-protected detection and archives inside archives
- Optional MalwareBazaar fingerprint lookups
- Automatic updates: Barry checks for a new version once a day and, with your OK, downloads it, checks its fingerprint and installs it (installed Windows copies; portable and Mac copies get the right download)
- Fixed a rule that could take many minutes on large minified JavaScript files
- Fewer false alarms: .NET framework files, placeholder Discord tokens, and file-type lists that mention curl

## 1.1.0

- The program is now called Barry Bear. Settings, history and quarantined files carry over from Anti-Logging Bear
- Classic Windows look for the desktop app: bevelled buttons, title-barred windows, a block progress bar and a sunken status bar
- Pixel-art Barry icon for the program, installer and shortcuts, and a classic install wizard with Barry on it
- Download file names start with BarryBear

## 1.0.1

- Mac app for Intel Macs (macOS 10.15 or later), alongside the Apple silicon build (macOS 11 or later)
- Mac builds no longer need macOS 15 for YARA rules; each build is checked against its stated minimum macOS
- The web app offers the right download when opened on a Windows PC or a Mac, and has a Downloads page
- Web app redesign with square, classic-Windows style windows and buttons
- Installer file names no longer include the version number

## 1.0.0

First release.

- Reads zip archives in memory and never extracts them
- Analyzers for Windows programs and ASI mods, scripts (PowerShell, batch, VBScript, JScript, HTA, Python, Lua, CLEO), Office documents, PDFs and shortcuts
- Capability-based scoring, so hotkey mods stay clean while keyloggers and stealers are flagged
- Bundled YARA rules, Microsoft Defender / ClamAV second opinion, optional VirusTotal hash lookups
- Download watcher with alerts, one-click quarantine and restore
- Simple and detailed views, HTML/JSON/text reports, scan history
- Settings for strict mode, custom rules, start at login, the Explorer right-click menu, high contrast and large text
- Windows 7 SP1 to 11 (x64 and x86) and macOS builds
- Web app for iPhone, iPad and Android: same engine running in the browser, works offline from the Home Screen, files never uploaded
