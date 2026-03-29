# Y — YARA and Detection Engineering

## Beginner Explanation
YARA is a pattern-matching language for identifying malware by searching files and memory for specific strings, byte patterns, or conditions. Detection engineering is the discipline of systematically building, testing, and maintaining detections across all security tools. Together they enable proactive, threat-driven detection.

## Technical Deep Dive
Full YARA coverage: [07_Malware_Defense/YARA_Rules.md](../07_Malware_Defense/YARA_Rules.md)

### YARA Rule Anatomy
```yara
rule DetectMimikatz {
    meta:
        description = "Detects Mimikatz credential dumping strings"
        author      = "CyberPath"
        severity    = "critical"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "privilege::debug"         nocase
        $s3 = "mimikatz"                 nocase wide
    condition:
        2 of ($s*)
}
```

### Detection Engineering Lifecycle
```
1. HYPOTHESIS  → What attacker behavior do I want to detect?
                 (e.g., "Attacker runs Mimikatz to dump credentials")
2. DATA        → Which logs / telemetry contain evidence?
                 (Process creation, PowerShell script block, LSASS access events)
3. WRITE       → Author YARA, Sigma, or native SIEM rule
4. TEST        → Against known-malicious samples (true positive)
                 Against known-good systems (false positive rate)
5. DEPLOY      → Push to EDR, AV pipeline, SIEM
6. TUNE        → Suppress legitimate false positives; tighten conditions
7. MAINTAIN    → Update rule when attacker TTPs evolve
```

### Sigma Rules — SIEM-Agnostic Detection Format
```yaml
title: Suspicious PowerShell Encoded Command
status: stable
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        ScriptBlockText|contains:
            - '-EncodedCommand'
            - '-enc '
    condition: selection
falsepositives:
    - Legitimate admin automation using encoded commands
level: high
```

### Running YARA
```bash
# Scan a single file
yara rules.yar suspicious.exe

# Scan a directory recursively
yara -r rules.yar /path/to/scan/

# Show matched strings
yara -s rules.yar suspicious.exe

# Scan memory dump (Volatility integration)
python3 vol.py -f memory.raw yarascan.YaraScan --yara-file rules.yar
```

### Detection Coverage Mapping
Map every YARA/Sigma rule to a MITRE ATT&CK technique to identify gaps:
```
Covered:  T1059.001 (PowerShell), T1003.001 (LSASS dump), T1053.005 (Scheduled Task)
Gap:      T1070.004 (File Deletion) — no rule exists → write one next sprint
```

## Real-World Relevance
**SUNBURST Discovery (2020):** Immediately after the SolarWinds breach disclosure, FireEye published YARA rules targeting unique SUNBURST DLL strings. Organizations ran these rules against their DLL inventory and determined compromise within hours — enabling rapid triage of 18,000 potentially affected organizations worldwide.

## Defensive Measures
1. Maintain a versioned YARA rule library tuned to your threat landscape
2. Integrate YARA scanning into your EDR and email security gateway
3. Write Sigma rules for behavioral detections and compile to your SIEM's native query language
4. Test rules against known-good samples weekly to detect false-positive drift
5. Subscribe to threat intel feeds that publish YARA rules (Elastic Security, neo23x0/signature-base)

## Practice Challenge
1. Write a YARA rule detecting any file containing both `CreateRemoteThread` and `VirtualAllocEx`.
2. Test it against `notepad.exe` — does it match? Why or why not?
3. Convert the Sigma rule above to your SIEM's native query language (KQL, SPL, or Lucene).
4. Map your existing detection rules to MITRE ATT&CK and identify the top three uncovered techniques.
