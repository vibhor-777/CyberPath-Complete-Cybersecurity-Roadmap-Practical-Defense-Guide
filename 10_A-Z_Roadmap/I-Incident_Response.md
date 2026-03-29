# I — Incident Response

## Beginner Explanation
Incident Response (IR) is the structured process for handling security breaches. Without a plan, organizations waste critical time, destroy evidence, and make things worse. The PICERL framework gives every responder a shared language and a repeatable process.

## Technical Deep Dive
See the comprehensive coverage in [08_Incident_Response/](../08_Incident_Response/).

### PICERL at a Glance
| Phase | Goal | Key Actions |
|-------|------|------------|
| **P**reparation | Build capabilities before incidents | IR plan, playbooks, SIEM, EDR |
| **I**dentification | Detect and confirm an incident | Triage alerts, classify severity |
| **C**ontainment | Stop the spread | Isolate hosts, block IPs, disable accounts |
| **E**radication | Remove the threat | Delete malware, close access vectors |
| **R**ecovery | Restore operations safely | Restore from backup, re-harden, monitor |
| **L**essons Learned | Improve defenses | Post-incident review, update playbooks |

### Initial Triage — First 15 Minutes
```powershell
# What processes are running?
Get-Process | Sort-Object CPU -Descending | Select-Object -First 20

# What network connections exist?
Get-NetTCPConnection -State Established

# Recent failed and successful logins
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4624} -MaxEvents 50

# Any new services installed?
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 20
```

## Real-World Relevance
**Target Breach (2013):** FireEye alerts fired correctly during the Identification phase, but no escalation procedure existed. The lack of Preparation (documented escalation paths) meant alerts were missed, and 40 million credit card numbers were stolen.

## Defensive Measures
1. Document and test your IR plan at least annually via tabletop exercises
2. Pre-stage forensics tools and evidence collection kits
3. Establish out-of-band communication channels (attackers may monitor your primary comms)
4. Know your breach notification obligations before an incident occurs

## Practice Challenge
Run the tabletop scenario from [08_Incident_Response/PICERL_Lifecycle.md](../08_Incident_Response/PICERL_Lifecycle.md) with a colleague. Time your responses to each phase. Identify gaps in your current preparation.
