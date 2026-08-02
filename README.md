# Mazaag Macro Detector

**Minecraft Screenshare Macro Detection Tool**

dev by ValyaR  
Discord: `_iaec`  `.mazaag`

---

## What is this?

A lightweight tool made for Minecraft screenshares.  
It scans the PC for macros, auto-clickers, and automation tools commonly used for cheating.

It looks for:
- Running macro processes
- AutoHotkey / AutoIt scripts
- TinyTask, OP Auto Clicker, GS Auto Clicker, and many more
- Startup entries & Scheduled Tasks
- Prefetch + BAM execution traces
- Deleted files in Recycle Bin
- Peripheral software (Razer, Logitech, etc.)
- Minecraft log keywords

Results are shown with clear severity:

- **HIGH** → Strong evidence  
- **MEDIUM** → Clear traces  
- **LOW** → Weak / possible context

---

## How to run (easiest way)

### Online (one command)

Open **CMD** or **PowerShell** and paste this:

```cmd
powershell -ExecutionPolicy Bypass -NoProfile -Command "iwr 'https://raw.githubusercontent.com/Va2lyR/MazaagMacroDetector/refs/heads/main/MazaagtoolM.ps1' -UseBasicParsing | iex"
