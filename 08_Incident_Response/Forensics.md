# Digital Forensics — Evidence Acquisition and Analysis

## Beginner Explanation

**Digital forensics** is the science of recovering and investigating digital evidence from computers, networks, and storage devices. Think of it as crime scene investigation for computers — the goal is to reconstruct what happened, when, and how, while preserving the evidence so it remains admissible in legal proceedings.

---

## Chain of Custody

**Chain of custody** is the documented, unbroken record of who collected, handled, transferred, or analyzed a piece of evidence. Without it, evidence may be inadmissible in court or disciplinary proceedings.

### Chain of Custody Form (Template)

```
CHAIN OF CUSTODY FORM

Case Number: ____________________
Incident ID: ____________________
Date/Time of Collection: ____________________

EVIDENCE ITEM 1:
  Description: [e.g., "Western Digital 1TB HDD, Serial: WD-1234567890"]
  Location Found: [e.g., "FINANCE-PC-04, primary drive bay"]
  Hash (SHA-256): ____________________
  Collected By: ____________________  Badge/ID: ____________________
  Witness: ____________________

TRANSFER LOG:
  Date/Time | From | To | Reason | Signature
  __________|______|____|________|__________
```

### Evidence Handling Rules

1. **Document before touching** — Photograph the device in place before collection
2. **Write-protect before imaging** — Use a hardware write blocker; never connect evidence drives directly
3. **Hash before and after** — SHA-256 the drive before and after imaging; hashes must match
4. **Bit-for-bit copy only** — Use forensic imaging tools (dd, FTK Imager, dcfldd); never work on originals
5. **Secure storage** — Evidence must be stored in a locked, access-controlled location
6. **Document every access** — Every person who touches evidence must sign the chain of custody

---

## Evidence Acquisition — Order of Volatility

Digital evidence degrades over time. Collect the most volatile evidence first.

```
Most Volatile (collect first):
  1. CPU registers and cache
  2. RAM (running processes, network connections, encryption keys)
  3. Network connections (active sessions, ARP table, routing table)
  4. Running processes
  5. Open files
  6. Swap/page file
  7. Hard disk contents
  8. Log files (may be on remote server)
  9. Archived/backup media
Least Volatile (collect last):
  10. Physical configuration, printed documents
```

---

## Memory Acquisition

```powershell
# Windows: Acquire memory with WinPmem (Rekall Memory Toolkit)
# ⚠️ Lab Environment Only — Run on isolated systems; may cause brief pause
winpmem_mini_x64_rc2.exe -o memory.raw
# Hash the output immediately
Get-FileHash memory.raw -Algorithm SHA256 | Tee-Object -FilePath memory.raw.sha256

# Alternative: DumpIt (Magnet Forensics - free)
DumpIt.exe /O memory.raw /T raw
```

```bash
# Linux: Acquire memory with LiME (Linux Memory Extractor)
# Install LiME kernel module
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src && make

# Load module and dump memory to file
sudo insmod lime-$(uname -r).ko "path=/mnt/evidence/memory.lime format=lime"

# Hash the output
sha256sum /mnt/evidence/memory.lime > /mnt/evidence/memory.lime.sha256
```

---

## Disk Imaging

```bash
# ⚠️ Lab Environment Only — Always use a write blocker on evidence drives

# FTK Imager (Windows GUI tool — recommended for chain of custody)
# Creates E01 format with built-in hash verification and metadata

# Linux: dd (basic, always hash separately)
dd if=/dev/sdb of=/evidence/disk.img bs=512 status=progress conv=noerror,sync
sha256sum /dev/sdb > /evidence/disk.sha256_source
sha256sum /evidence/disk.img > /evidence/disk.sha256_image
# These two hashes must match

# Linux: dcfldd (forensic-enhanced dd with built-in hashing)
dcfldd if=/dev/sdb of=/evidence/disk.img hash=sha256 hashlog=/evidence/hash.log

# Linux: Guymager (GUI, recommended for physical forensics)
sudo apt-get install guymager
sudo guymager  # GUI interface for forensic imaging
```

---

## Windows Forensic Artifacts

### Windows Event Logs

```powershell
# Location: C:\Windows\System32\winevt\Logs\
# Key log files:
# Security.evtx — Authentication, account management, policy changes
# System.evtx   — System events, service installs, driver errors
# Application.evtx — Application crashes and errors
# Microsoft-Windows-PowerShell/Operational.evtx — PowerShell script block logging
# Microsoft-Windows-Sysmon/Operational.evtx — Sysmon events (if deployed)

# Export event log for analysis
wevtutil epl Security C:\evidence\Security.evtx

# Parse with PowerShell
Get-WinEvent -Path C:\evidence\Security.evtx -FilterXPath "*[System[EventID=4624]]" |
    Select-Object TimeCreated, Message | Export-Csv C:\evidence\logins.csv
```

### Registry Forensics

```powershell
# Key registry hives (C:\Windows\System32\config\):
# SYSTEM    — Hardware config, services, timezone
# SAM       — Local user accounts and password hashes
# SECURITY  — Security policy, cached credentials
# SOFTWARE  — Installed software, application settings
# NTUSER.DAT — Per-user settings (in each user's profile)

# Tools: Registry Explorer (Eric Zimmermann), RegRipper

# Critical forensic registry locations:
$regKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SYSTEM\CurrentControlSet\Services",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKCU:\SOFTWARE\Classes\ms-settings\shell\open\command"  # UAC bypass target
)

foreach ($key in $regKeys) {
    Write-Host "`n=== $key ===" -ForegroundColor Yellow
    Get-ItemProperty $key -ErrorAction SilentlyContinue
}
```

### Prefetch Files

Prefetch files record evidence of program execution — even for programs that have been deleted.

```powershell
# Location: C:\Windows\Prefetch\
# Format: PROGRAMNAME-XXXXXXXX.pf
# Contains: Program name, run count, last run time, files accessed

# List all prefetch files with timestamps
Get-ChildItem C:\Windows\Prefetch -Filter "*.pf" |
    Sort-Object LastWriteTime -Descending |
    Select-Object Name, LastWriteTime, @{N='SizeMB';E={[math]::Round($_.Length/1MB,2)}} |
    Format-Table -AutoSize

# Parse with WinPrefetchView (NirSoft) — shows run count and timestamps
# Parse with PECmd.exe (Eric Zimmermann's tools)
PECmd.exe -d C:\Windows\Prefetch --csv C:\evidence\ --csvf prefetch_results.csv
```

### Shellbags

Shellbags record folder access history — even for folders on network shares or removable drives that no longer exist.

```
# Location: NTUSER.DAT hive → ShellNoRoam/Bags
# Tool: ShellBagsExplorer (Eric Zimmermann)
# Reveals: Folders opened by user, timestamps, order of access
```

### LNK Files (Shortcut Files)

```powershell
# LNK files are created automatically when you open a file
# They reveal the original file path (even from USB drives)
# Location: C:\Users\[User]\AppData\Roaming\Microsoft\Windows\Recent\

Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -Filter "*.lnk" |
    Sort-Object LastWriteTime -Descending | Select-Object -First 20 Name, LastWriteTime

# Parse LNK files with LECmd.exe (Eric Zimmermann)
LECmd.exe -d "$env:APPDATA\Microsoft\Windows\Recent" --csv C:\evidence\
```

### Windows Timeline (ActivitiesCache.db)

```powershell
# Windows 10+ records user activity in SQLite database
# Location: C:\Users\[User]\AppData\Local\ConnectedDevicesPlatform\[GUID]\ActivitiesCache.db
# Contains: Application usage, file opens, timeline entries

# Parse with WxTCmd.exe (Eric Zimmermann)
WxTCmd.exe -f ActivitiesCache.db --csv C:\evidence\
```

---

## Linux Forensic Artifacts

```bash
# Auth logs — Login attempts, sudo usage, SSH sessions
/var/log/auth.log           # Debian/Ubuntu
/var/log/secure             # RHEL/CentOS

# System logs
/var/log/syslog             # General system events
/var/log/messages           # General system messages

# Bash history (per user)
~/.bash_history             # May be cleared by attacker
~/.zsh_history

# Cron jobs
/var/spool/cron/crontabs/   # User cron jobs
/etc/cron.d/                # System cron jobs
/etc/crontab

# Persistence via systemd
/etc/systemd/system/        # System services
~/.config/systemd/user/     # User services

# SSH
~/.ssh/authorized_keys      # Keys that can authenticate as this user
~/.ssh/known_hosts          # Systems this user has SSH'd to
/var/log/auth.log           # SSH login events

# Recent file access (from filesystem timestamps)
find /home /root /tmp /var/tmp -newer /tmp/reference_time -ls 2>/dev/null

# Deleted files recovery (extundelete for ext4)
sudo extundelete /dev/sdb1 --restore-all --output-dir /evidence/recovered/
```

---

## Memory Analysis with Volatility

```bash
# Volatility 3 — comprehensive memory forensics framework

# OS/profile identification
python3 vol.py -f memory.raw windows.info

# List processes
python3 vol.py -f memory.raw windows.pslist    # Standard process list
python3 vol.py -f memory.raw windows.psscan    # Scan for hidden processes
python3 vol.py -f memory.raw windows.pstree    # Parent-child tree

# Command line arguments (reveals encoded commands)
python3 vol.py -f memory.raw windows.cmdline

# Network connections at time of capture
python3 vol.py -f memory.raw windows.netstat

# Detect process injection (executable non-file-backed memory)
python3 vol.py -f memory.raw windows.malfind

# Extract running hives from registry
python3 vol.py -f memory.raw windows.registry.hivelist
python3 vol.py -f memory.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"

# Dump a specific process for further analysis
python3 vol.py -f memory.raw windows.dumpfiles --pid 1234

# YARA scan against memory
python3 vol.py -f memory.raw yarascan.YaraScan --yara-file malware.yar
```

---

## Forensic Analysis Tools Reference

| Tool | Purpose | Platform | Cost |
|------|---------|---------|------|
| **Autopsy** | GUI disk forensics platform | Win/Linux | Free |
| **FTK Imager** | Disk imaging and preview | Windows | Free |
| **Volatility 3** | Memory forensics | Win/Linux/Mac | Free |
| **Eric Zimmermann Tools** | Windows artifact parsing (RegRipper, PECmd, etc.) | Windows | Free |
| **Velociraptor** | Live forensics at scale | Win/Linux | Free |
| **KAPE** | Triage artifact collection | Windows | Free |
| **Wireshark** | Packet analysis | All | Free |
| **Plaso/Log2Timeline** | Timeline generation from artifacts | Win/Linux | Free |

---

## Real-World Relevance

**The Lazarus Group Attribution (2014–2016):** Forensic analysis of the Sony Pictures breach identified code reuse between the malware and earlier North Korean threat actor tools — a finding enabled by careful static analysis of malware artifacts recovered from compromised systems. Memory forensics revealed injected code that hadn't touched disk, and Windows Prefetch analysis proved execution timelines. The combination of artifact types built a picture that allowed confident nation-state attribution.

---

## Practice Challenge

**Forensics Task:**

1. Create a test environment: On a Windows VM, create a file, delete it, and clear the Recycle Bin.
2. Use FTK Imager to mount the volume (not the live OS).
3. Try to recover the deleted file using Autopsy or a similar tool.
4. Take a RAM dump of the VM using WinPmem.
5. Use Volatility to list all running processes and their command lines from the dump.
6. Document your findings and methodology in your `Writeup/` folder.
