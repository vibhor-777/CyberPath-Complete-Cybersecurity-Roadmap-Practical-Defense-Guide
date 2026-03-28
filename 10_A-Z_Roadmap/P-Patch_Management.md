# P — Patch Management

## Beginner Explanation
Patch management is the process of keeping software up to date with security fixes. The majority of successful cyberattacks exploit known vulnerabilities that already have patches available. A systematic patching process is one of the highest-ROI defensive controls.

## Technical Deep Dive

### Patch Priority Framework
| Severity | CVSS Score | Patch Timeline |
|----------|-----------|---------------|
| Critical | 9.0–10.0 | Within 24–72 hours |
| High | 7.0–8.9 | Within 7 days |
| Medium | 4.0–6.9 | Within 30 days |
| Low | 0.1–3.9 | Within 90 days |

Prioritize by: CVSS + internet exposure + active exploitation in the wild.

### Windows — WSUS / Microsoft Update
```powershell
# Check pending updates
Get-WindowsUpdate -AcceptAll -Verbose

# Force immediate update check
UsoClient StartScan
UsoClient StartDownload
UsoClient StartInstall

# WSUS: Approve critical updates for auto-install
Get-WsusUpdate -Classification Critical -Approval Unapproved | Approve-WsusUpdate -Action Install -TargetGroupName "All Computers"
```

### Linux — Unattended Upgrades (Debian/Ubuntu)
```bash
apt-get install -y unattended-upgrades
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'CONF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
CONF
dpkg-reconfigure --priority=low unattended-upgrades
```

### Vulnerability Scanning Before and After Patching
```bash
# OpenVAS / GVM scan (credentialed)
gvm-cli socket --gvm-socket /var/run/gvm/gvmd.sock --xml "<get_tasks/>"

# Nessus credentialed scan summary
# Tools → Scans → New Scan → Advanced Scan → Credentials tab

# After patching — rescan and verify CVE closure
# Track: CVEs identified → patched → verified closed
```

### Patch Management Metrics
- **MTTR (Mean Time to Remediate):** Average days from CVE disclosure to patch applied
- **Patch compliance rate:** % of systems patched within SLA per severity tier
- **Vulnerability debt:** Total open critical/high CVEs across estate

## Real-World Relevance
**Equifax (2017):** Apache Struts CVE-2017-5638 had a patch available for 2 months before the breach. An attacker exploited it to compromise 147 million records. A systematic patch process with a 7-day SLA for high/critical vulnerabilities would have closed this window.

## Defensive Measures
1. Inventory all software — you can't patch what you don't know exists
2. Subscribe to CVE feeds for your software stack (CISA KEV, NVD, vendor advisories)
3. Automate patch deployment for OS-level security patches
4. Track and report patch compliance weekly to leadership
5. Treat critical CVEs with active exploitation as emergency patches

## Practice Challenge
1. Run `apt list --upgradable` on a lab Linux VM — identify any security updates.
2. Apply updates and verify they were applied.
3. Check the CISA Known Exploited Vulnerabilities catalog (cisa.gov/known-exploited-vulnerabilities-catalog) for any software you run.
