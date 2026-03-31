# 🔧 Installation & Setup Guide

> Detailed instructions for setting up CyberPath on your local machine and running the included scripts.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Cloning the Repository](#cloning-the-repository)
- [Python Setup](#python-setup)
- [PowerShell Setup](#powershell-setup)
- [Lab Environment Setup](#lab-environment-setup)
- [Running the Scripts](#running-the-scripts)
- [Verifying Your Setup](#verifying-your-setup)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Minimum Requirements

| Tool | Minimum Version | Purpose |
|------|----------------|---------|
| Git | 2.30+ | Cloning and updating the repository |
| Python | 3.8+ | Running Python defensive scripts |
| PowerShell | 5.1+ (or 7+) | Running PowerShell defensive scripts |

### Recommended Additional Tools

| Tool | Purpose |
|------|---------|
| [VirtualBox](https://www.virtualbox.org/) or [VMware](https://www.vmware.com/) | Safe lab environment for testing |
| [Visual Studio Code](https://code.visualstudio.com/) | Editing and previewing Markdown |
| [Wireshark](https://www.wireshark.org/) | Network packet analysis labs |
| [Wazuh](https://wazuh.com/) | Open-source SIEM for SIEM labs |

---

## Cloning the Repository

```bash
# Clone via HTTPS
git clone https://github.com/vibhor-777/CyberPath-Complete-Cybersecurity-Roadmap-Practical-Defense-Guide.git

# Or clone via SSH (if SSH keys are configured)
git clone git@github.com:vibhor-777/CyberPath-Complete-Cybersecurity-Roadmap-Practical-Defense-Guide.git

# Navigate into the repository
cd CyberPath-Complete-Cybersecurity-Roadmap-Practical-Defense-Guide
```

### Keeping Your Local Copy Updated

```bash
# Fetch and merge the latest changes from main
git pull origin main
```

---

## Python Setup

CyberPath's Python scripts are designed to run with **no external dependencies** (Python standard library only). You only need Python 3.8+.

### Verify Python Installation

```bash
# Linux / macOS
python3 --version

# Windows
python --version
```

### (Optional) Virtual Environment

If you want to isolate any future experimentation:

```bash
# Create a virtual environment
python3 -m venv cyberpath-env

# Activate (Linux/macOS)
source cyberpath-env/bin/activate

# Activate (Windows PowerShell)
cyberpath-env\Scripts\Activate.ps1

# Deactivate when done
deactivate
```

---

## PowerShell Setup

### Check PowerShell Version

```powershell
$PSVersionTable.PSVersion
```

### Install PowerShell 7+ (Recommended)

PowerShell 7 is cross-platform (Windows, Linux, macOS) and supports the latest features:

```bash
# Linux (Debian/Ubuntu)
sudo apt-get install -y powershell

# macOS (via Homebrew)
brew install --cask powershell

# Windows (via winget)
winget install --id Microsoft.PowerShell
```

### Execution Policy (Windows)

Some scripts require the execution policy to allow local scripts to run. In an **elevated PowerShell session**:

```powershell
# Allow locally written scripts (most permissive needed for lab use)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

> ⚠️ **Lab Environment Only:** Only change execution policy on machines you own or manage. Do not set `Unrestricted` on production systems.

---

## Lab Environment Setup

All scripts that interact with live system data should be run in a **safe, isolated lab environment**. Never run these scripts against production systems without explicit authorization.

### Recommended Virtual Lab Stack

```
┌─────────────────────────────────────────────────────────┐
│  Host Machine (your computer)                           │
│  ┌───────────────┐  ┌───────────────┐  ┌─────────────┐ │
│  │  Kali Linux   │  │ Ubuntu Server │  │ Windows 10  │ │
│  │  (tools VM)   │  │ (target VM)   │  │ (target VM) │ │
│  └───────────────┘  └───────────────┘  └─────────────┘ │
│         └──────────── Internal Network ─────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Network Isolation Checklist

- [ ] Set all lab VMs to **Host-Only** or **Internal Network** adapter mode in VirtualBox/VMware
- [ ] Verify VMs cannot reach the public internet while running vulnerable configurations
- [ ] Use VM snapshots before each lab exercise — revert to clean state after
- [ ] Keep host OS patched and separate from lab traffic

---

## Running the Scripts

### Python Scripts (in `09_Defensive_Tooling/`)

```bash
# Navigate to the tooling directory
cd 09_Defensive_Tooling/

# File Integrity Monitor — create baseline
python3 fim.py --baseline --dirs /etc /usr/bin

# File Integrity Monitor — monitor against baseline
python3 fim.py --monitor

# DHCP Monitor — watch DHCP lease activity
sudo python3 dhcp_monitor.py --interface eth0

# Log Parser — analyze a log file
python3 log_parser.py --file /var/log/auth.log
```

### PowerShell Scripts (in `09_Defensive_Tooling/`)

```powershell
# Navigate to the tooling directory
Set-Location .\09_Defensive_Tooling\

# Get Security Events (run as Administrator)
.\Get-SecurityEvents.ps1

# Persistence Audit (run as Administrator)
.\Invoke-PersistenceAudit.ps1

# Set Audit Logging (run as Administrator)
.\Set-AuditLogging.ps1 -Enable
```

> ⚠️ **Lab Environment Only:** Run PowerShell scripts as Administrator only in your lab VMs, not on your primary workstation.

---

## Verifying Your Setup

Run these checks to confirm everything is working:

```bash
# Verify Python is working
python3 -c "import hashlib, json, argparse; print('Python OK')"

# Verify Git is tracking correctly
git log --oneline -5

# Verify PowerShell (if installed)
pwsh -Command "Write-Host 'PowerShell OK'"
```

---

## Troubleshooting

### `python3: command not found`

- **Linux:** `sudo apt-get install python3`
- **macOS:** `brew install python3`
- **Windows:** Download from [python.org](https://www.python.org/downloads/) and ensure "Add to PATH" is checked

### `Permission denied` running Python scripts

```bash
# Make the script executable
chmod +x fim.py

# Or run explicitly with Python
python3 fim.py --help
```

### PowerShell: `File cannot be loaded because running scripts is disabled`

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### `fim.py --monitor` reports no baseline found

You must run `--baseline` first to create the initial hash baseline:

```bash
python3 fim.py --baseline --dirs /etc
python3 fim.py --monitor
```

---

*For more help, open an [issue](https://github.com/vibhor-777/CyberPath-Complete-Cybersecurity-Roadmap-Practical-Defense-Guide/issues) or see [FAQ.md](FAQ.md).*
