# F — Forensics (Digital)

## Beginner Explanation
Digital forensics is the science of collecting, preserving, and analyzing digital evidence. Like a crime scene investigator who photographs and bags physical evidence before touching it, a digital forensic analyst must preserve evidence in its original state before examining it.

## Technical Deep Dive
See the comprehensive coverage in [08_Incident_Response/Forensics.md](../08_Incident_Response/Forensics.md).

### Key Forensic Principles
1. **Preserve before you examine** — Always work on a forensic copy, never the original
2. **Document everything** — Chain of custody is non-negotiable
3. **Hash everything** — SHA-256 before and after; hashes must match
4. **Order of volatility** — Most volatile (RAM) first, least volatile (backups) last

### Quick Artifact Reference

| Artifact | Location | What it Reveals |
|----------|---------|----------------|
| Event Logs | `C:\Windows\System32\winevt\Logs\` | Authentication, process creation, service installs |
| Prefetch | `C:\Windows\Prefetch\` | Evidence of program execution |
| Registry | `C:\Windows\System32\config\` | Persistence, configuration, user activity |
| Browser History | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\` | Web activity |
| LNK Files | `%APPDATA%\Microsoft\Windows\Recent\` | Recent file access |
| Shellbags | NTUSER.DAT | Folder access history |
| Auth Logs | `/var/log/auth.log` | SSH logins, sudo usage |
| Bash History | `~/.bash_history` | Command history |

### Memory Forensics Quick Commands
```bash
# Volatility 3 most-used commands
python3 vol.py -f memory.raw windows.pslist    # Process list
python3 vol.py -f memory.raw windows.psscan    # Hidden processes
python3 vol.py -f memory.raw windows.cmdline   # Command lines
python3 vol.py -f memory.raw windows.netstat   # Network connections
python3 vol.py -f memory.raw windows.malfind   # Injected code
```

## Real-World Relevance
The **2016 Bangladesh Bank Heist ($81M stolen):** Forensic analysis of the SWIFT network computers revealed that attackers had installed malware (later attributed to Lazarus Group) that both sent fraudulent transfer requests and deleted evidence of those transfers from printer logs and SWIFT transaction records. Memory forensics recovered evidence the attackers thought they had erased.

## Defensive Measures
1. Enable comprehensive logging before incidents happen — you can't forensically analyze logs that don't exist
2. Deploy Sysmon for detailed Windows process, network, and file creation logging
3. Use write-once log storage (SIEM with immutable storage) to prevent log tampering
4. Maintain memory acquisition tools (WinPmem) ready for rapid deployment

## Practice Challenge
1. Take a memory snapshot of a lab Windows VM with WinPmem.
2. Run `windows.pstree` in Volatility to build the process hierarchy.
3. Identify which processes were spawned by Explorer.exe vs. services.exe.
4. Run `windows.cmdline` and look for any processes with unusual command-line arguments.
