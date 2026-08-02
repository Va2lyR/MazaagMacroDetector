# Mazaag Macro Detector

**Professional Minecraft Screenshare Macro Detection Tool**

[![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg)]()
[![Language](https://img.shields.io/badge/Language-PowerShell-blue.svg)]()
[![License](https://img.shields.io/badge/License-For%20Screenshare%20Use-red.svg)]()

**Developer:** ValyaR  
**Discord:** `_iaec` · `.mazaag`

---

## Overview

Mazaag Macro Detector is a lightweight forensic tool designed specifically for **Minecraft screenshares**.  
It scans the system for traces of macros, auto-clickers, and input automation tools commonly used to gain unfair advantages.

The tool combines multiple detection methods used in modern Windows forensics to provide clear and reliable results.

---

## Features

- Running process detection (AutoHotkey, AutoIt, TinyTask, OP Auto Clicker, GS Auto Clicker, and more)
- Script file & content analysis (`.ahk`, `.au3`)
- Startup folders & Scheduled Tasks inspection
- Prefetch & BAM execution traces
- Windows Event Log analysis (when run as Administrator)
- Recycle Bin deleted file recovery
- Peripheral software detection (Razer, Logitech, Corsair, etc.)
- USB device history
- Minecraft log keyword scanning
- Clean severity-based reporting system

### Severity Levels

| Level     | Meaning                          |
|-----------|----------------------------------|
| **HIGH**  | Strong / direct evidence         |
| **MEDIUM**| Clear traces found               |
| **LOW**   | Weak or contextual indicators    |

---

## Quick Start (Recommended)

### Online Execution (One Command)

Open **Command Prompt** or **PowerShell** and paste the following:

```cmd
powershell -ExecutionPolicy Bypass -NoProfile -Command "iwr 'https://raw.githubusercontent.com/Va2lyR/MazaagMacroDetector/refs/heads/main/MazaagtoolM.ps1' -UseBasicParsing | iex"
