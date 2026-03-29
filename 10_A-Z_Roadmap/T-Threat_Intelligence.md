# T — Threat Intelligence

## Beginner Explanation
Threat intelligence transforms raw data (IP addresses, malware hashes, attack techniques) into actionable information that improves defensive decisions. Instead of defending against every possible attack, threat intelligence tells you which specific threats are targeting organizations like yours — and what indicators to look for.

## Technical Deep Dive

### Intelligence Types
| Type | Description | Example |
|------|-------------|---------|
| **Strategic** | High-level trends for executive decisions | "Ransomware targeting healthcare increased 40% in Q3" |
| **Operational** | Specific campaigns in progress | "APT29 targeting law firms with spear-phishing" |
| **Tactical** | TTPs (Tactics, Techniques, Procedures) | MITRE ATT&CK mapping of a specific threat actor |
| **Technical** | Machine-readable IOCs | IP addresses, domain names, file hashes, YARA rules |

### Indicators of Compromise (IOCs)
```
Network IOCs:
  - C2 IP: 185.220.101.45
  - C2 Domain: update-service.windowscdn.net
  - URL: https://evil.com/stage2/payload.bin

Host IOCs:
  - File hash (SHA-256): a3f9e2b8...
  - File path: C:\ProgramData\WindowsUpdate\svcupdate.exe
  - Registry key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate
  - Mutex: {A1B2C3D4-...} (prevents double-infection)

Behavioral IOCs (TTPs — harder to evade than static IOCs):
  - T1059.001: PowerShell execution with base64-encoded command
  - T1053.005: Scheduled task created in non-standard path
  - T1003.001: LSASS memory read by non-system process
```

### MITRE ATT&CK Framework
```
Tactic (Why) → Technique (How) → Procedure (Specific Implementation)

Example:
  Tactic:    Persistence (TA0003)
  Technique: Scheduled Task/Job (T1053)
  Sub-tech:  Scheduled Task (T1053.005)
  Procedure: Attacker creates task "WindowsDefenderUpdate" running PowerShell cradle at logon
```

### Threat Intelligence Platforms and Feeds
| Source | Type | Cost |
|--------|------|------|
| MITRE ATT&CK | TTP framework | Free |
| AlienVault OTX | Community IOC sharing | Free |
| CISA AIS | US government sharing | Free (registration) |
| MISP | Open-source TI platform | Free (self-hosted) |
| Recorded Future | Commercial | Paid |
| CrowdStrike Intel | Commercial | Paid |

### MISP Integration Example
```python
from pymisp import PyMISP

misp = PyMISP("https://your-misp-instance", "YOUR_API_KEY")

# Search for events related to a specific IP
results = misp.search(value="185.220.101.45", type_attribute="ip-dst")

# Add new IOC from incident
event = misp.new_event(distribution=1, threat_level_id=2, analysis=2,
                        info="Incident 2024-001: Ransomware C2")
misp.add_attribute(event["Event"]["id"], type="ip-dst", value="185.220.101.45")
```

## Real-World Relevance
**FireEye Breach Discovery (2020):** FireEye discovered the SolarWinds supply chain attack while investigating anomalous use of their own red team tools. By sharing IOCs immediately (YARA rules, Snort signatures, file hashes), thousands of organizations updated their defenses within hours. Threat intelligence sharing directly saved other organizations from compromise.

## Defensive Measures
1. Subscribe to CISA advisories and relevant ISAC feeds for your industry
2. Deploy a MISP instance for internal IOC management and sharing
3. Map your logging to MITRE ATT&CK — ensure you have detection coverage for your top threats
4. Automate IOC ingestion into your SIEM and EDR
5. Conduct quarterly threat landscape reviews — who is targeting organizations like yours?

## Practice Challenge
1. Create a free account on AlienVault OTX and subscribe to pulses related to ransomware.
2. Find the MITRE ATT&CK page for T1053.005 (Scheduled Task). List three detection data sources.
3. Write a SIEM rule (in pseudo-code) that detects the creation of a scheduled task running from a temp directory.
