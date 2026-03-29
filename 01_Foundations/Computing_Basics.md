# Computing Basics for Security Professionals

## Beginner Explanation

Before you can defend a house, you need to understand how the house is built. This module covers the foundational computing concepts that underpin every security topic in this repository — operating systems, file systems, processes, and the command line.

---

## Operating System Architecture

An **Operating System (OS)** is software that manages hardware resources and provides services to applications. Security practitioners must understand the OS intimately because most attacks target the OS layer.

### Key OS Components

| Component | Function | Security Relevance |
|-----------|----------|-------------------|
| **Kernel** | Core of the OS; manages CPU, memory, I/O | Kernel exploits grant full system control |
| **User Space** | Where applications run | Attack surface for most malware |
| **System Calls** | Interface between user space and kernel | Monitored by EDR solutions |
| **File System** | Organizes and stores data on disk | Permissions control access; forensics reads artifacts |
| **Process Manager** | Creates, schedules, terminates processes | Anomalous processes indicate compromise |
| **Network Stack** | Handles network communication | Packet capture happens here |

### Windows Directory Structure

```
C:\
├── Windows\
│   ├── System32\          ← Core OS binaries (svchost.exe, cmd.exe)
│   ├── SysWOW64\          ← 32-bit binaries on 64-bit systems
│   └── Temp\             ← Malware often stages here
├── Users\
│   ├── [Username]\
│   │   ├── AppData\       ← Application data, often contains malware persistence
│   │   ├── Desktop\
│   │   └── Documents\
│   └── Public\
├── Program Files\          ← 64-bit installed applications
└── Program Files (x86)\    ← 32-bit installed applications
```

### Linux Directory Structure

```
/
├── bin/       ← Essential user binaries (ls, cp, bash)
├── sbin/      ← System administration binaries (iptables, fdisk)
├── etc/       ← Configuration files (sshd_config, passwd, sudoers)
├── var/
│   └── log/  ← System and application logs ← CRITICAL for incident response
├── home/      ← User home directories
├── root/      ← Root user home directory
├── tmp/       ← Temporary files (world-writable; malware staging target)
├── proc/      ← Virtual filesystem; running process info
└── usr/       ← User programs and libraries
```

---

## Command Line Fundamentals

### Linux/macOS CLI Essentials

```bash
# Navigation
pwd               # Print working directory
ls -la            # List files with permissions and hidden files
cd /etc           # Change directory

# File Operations
cat /etc/passwd   # Display file contents
grep "root" /etc/passwd   # Search for pattern in file
find / -name "*.log" 2>/dev/null   # Find all log files

# Permissions (rwx = read/write/execute for owner/group/others)
ls -la /etc/shadow    # Check permissions
chmod 640 file.txt    # Set permissions
chown user:group file.txt  # Change ownership

# Process Management
ps aux            # List all running processes
top               # Live process monitor
kill -9 <PID>     # Force-terminate a process

# Network
netstat -tulpn    # Show listening ports
ss -tulpn         # Modern replacement for netstat
curl -I https://example.com   # Check HTTP headers

# Log Review
tail -f /var/log/syslog       # Follow live log output
journalctl -u sshd            # Review SSH service logs
grep "Failed" /var/log/auth.log  # Find failed auth attempts
```

### Windows PowerShell Essentials

```powershell
# Navigation
Get-Location           # Like pwd
Get-ChildItem -Force   # Like ls -la (shows hidden items)
Set-Location C:\Users  # Like cd

# File Operations
Get-Content C:\Windows\System32\drivers\etc\hosts
Select-String "pattern" -Path *.log  # Like grep

# Process Management
Get-Process            # List running processes
Stop-Process -Id 1234  # Kill process by PID

# Network
Get-NetTCPConnection   # Show active connections (like netstat)
Test-NetConnection -ComputerName 8.8.8.8 -Port 443  # Test connectivity

# Event Logs
Get-WinEvent -LogName Security -MaxEvents 50
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20
```

---

## Understanding Processes and Memory

### Why Processes Matter for Security

Every running application is a **process** — an instance of a program with allocated memory. Security relevance:

- **Malware hides as processes** — Attackers often name malicious processes to mimic legitimate ones (e.g., `svch0st.exe` instead of `svchost.exe`)
- **Process injection** — Advanced malware injects code into legitimate processes to evade detection
- **Memory forensics** — Malware running only in memory leaves no files on disk; analysts must capture RAM to find it

### Identifying Suspicious Processes

```powershell
# Windows: Find processes with unusual parent-child relationships
Get-WmiObject Win32_Process | Select-Object Name, ProcessId, ParentProcessId, CommandLine

# Look for:
# - cmd.exe or powershell.exe spawned by a browser (possible phishing exploit)
# - wscript.exe or mshta.exe running with encoded arguments
# - Processes running from temp directories
```

```bash
# Linux: Check all processes and their command lines
ps auxf   # Show process tree

# Look for:
# - Processes running from /tmp or /dev/shm
# - Processes with obfuscated arguments (base64 encoded strings)
# - Network connections to unusual destinations
```

---

## File Systems and Permissions

### Linux Permission Model

```
-rwxr-xr--  1 user group 4096 Jan 01 12:00 script.sh
 ^^^          ↑    ↑
 |||          Owner Group
 |||
 ||└── Others: r-- (read only)
 |└─── Group:  r-x (read + execute)
 └──── Owner:  rwx (read + write + execute)
```

| Permission | File Meaning | Directory Meaning |
|------------|-------------|------------------|
| `r` (4) | Read file contents | List directory contents |
| `w` (2) | Modify file | Create/delete files in directory |
| `x` (1) | Execute file | Enter directory |

**Security-critical permissions:**
```bash
# Files that should have restricted permissions
/etc/passwd   → 644 (world-readable, required for login)
/etc/shadow   → 640 (root read only — contains password hashes!)
/etc/sudoers  → 440 (read-only for root and sudo group)

# Check for world-writable files (potential persistence target)
find / -perm -002 -type f 2>/dev/null
```

---

## Networking Basics

Understanding basic networking is essential before diving into network security. Full coverage is in `02_Networking/`, but here are the absolute fundamentals:

| Concept | Description |
|---------|-------------|
| **IP Address** | Unique identifier for a device on a network (IPv4: 192.168.1.1) |
| **MAC Address** | Hardware identifier burned into a network interface card |
| **Port** | Logical communication endpoint (0–65535); ports 0–1023 are "well-known" |
| **Protocol** | Rules governing communication (TCP for reliable, UDP for fast) |
| **DNS** | Translates human-readable names (google.com) to IP addresses |
| **DHCP** | Automatically assigns IP addresses to devices on a network |

**Commonly targeted ports:**
```
22   → SSH (brute-force target)
23   → Telnet (unencrypted; should never be open)
80   → HTTP (web; should be redirected to HTTPS)
443  → HTTPS (encrypted web)
3389 → RDP (Remote Desktop; brute-force and exploit target)
445  → SMB (EternalBlue exploit target)
3306 → MySQL (database; should never be internet-facing)
```

---

## Real-World Relevance

The **2021 Kaseya VSA Supply Chain Attack** succeeded partly because the attackers understood that Kaseya's software ran as a trusted process with high privileges on thousands of managed systems. By compromising the software update mechanism, they gained execution in a trusted process context on over 1,500 businesses simultaneously.

Understanding processes, services, and how trust is established in an OS is what allowed this attack to be so devastating — and it's the same knowledge defenders need to detect and prevent it.

---

## Defensive Measures

1. **Inventory your running services** — Disable anything not required for business function
2. **Enforce the Principle of Least Privilege** — Users and applications should run with the minimum permissions necessary
3. **Monitor process creation** — Use Sysmon (Windows) or auditd (Linux) to log process creation events
4. **Protect sensitive files** — Verify permissions on `/etc/shadow`, `/etc/sudoers`, and Windows SAM database regularly
5. **Enable command-line logging** — Log all PowerShell and Bash commands executed by users

---

## Practice Challenge

**Task:** Build a system baseline.

1. On a lab VM (Linux or Windows), document:
   - All running processes and their parent processes
   - All open network ports and the services listening on them
   - All user accounts and their group memberships
   - All scheduled tasks or cron jobs

2. Save this baseline to a file.

3. Install a benign application (e.g., VLC or LibreOffice).

4. Re-run your baseline collection and compare the output. What changed? Which new processes, ports, or files appeared?

Understanding what "normal" looks like is the first step to detecting what's abnormal.
