# Changelog

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
