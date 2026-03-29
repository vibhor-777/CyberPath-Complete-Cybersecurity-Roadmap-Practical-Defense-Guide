# Incident Response Playbooks

These playbooks provide step-by-step response procedures for the most common attack scenarios. Each playbook follows the PICERL lifecycle: **P**reparation, **I**dentification, **C**ontainment, **E**radication, **R**ecovery, **L**essons Learned.

Keep these accessible offline — if your systems are compromised, your wiki may be unavailable.

---

## Playbook 1: Ransomware

### Indicators of Compromise
- Mass file extension changes (e.g., `.locked`, `.encrypted`, `.WNCRY`)
- `vssadmin delete shadows /all` in process logs
- Ransom note files (e.g., `README.txt`, `HOW_TO_DECRYPT.html`) appearing in directories
- High disk I/O with unusual process as source
- C2 beaconing to onion domains or unknown external IPs

### Response Steps

**Identification**
- [ ] Alert triggered: identify source host via EDR/SIEM (Event ID 4688 / process creation)
- [ ] Determine patient zero: which host first showed encryption activity?
- [ ] Identify the ransomware family (check ransom note, Bleeping Computer ID Ransomware)
- [ ] Assess scope: how many hosts/shares are affected?

**Containment**
- [ ] **Immediately isolate patient zero** at the network switch (disable port) or via EDR isolation
- [ ] Disable the compromised user account (do not just change password — attacker may have persistence)
- [ ] Block identified C2 IPs and domains at the perimeter firewall and DNS sinkhole
- [ ] Take snapshot/memory dump of infected system before any remediation (forensic evidence)
- [ ] Identify and isolate any other hosts showing encryption activity
- [ ] Disable affected file shares temporarily to prevent further encryption

**Eradication**
- [ ] Identify the initial access vector (phishing? RDP? VPN? vulnerable service?)
- [ ] Remove malware artifacts: malicious binaries, scheduled tasks, registry persistence, services
- [ ] Verify no backdoors or additional implants remain (compare against baseline)
- [ ] Patch the vulnerability used for initial access before reconnecting systems

**Recovery**
- [ ] Restore affected data from last known-good backup (verify backup integrity first)
- [ ] Verify restored files are clean — scan with updated AV/EDR signatures
- [ ] Reconnect systems in a staged manner, monitoring for re-infection
- [ ] Reset passwords for all affected accounts and any accounts with access to affected systems
- [ ] **Do not pay the ransom** without legal/executive approval and law enforcement notification

**Communication**
- [ ] Notify: CISO, Legal, Executive leadership, Public Relations (if required)
- [ ] Notify law enforcement: FBI IC3 (US), NCSC (UK), or relevant national authority
- [ ] Assess breach notification requirements (GDPR 72h, HIPAA, state laws)

**Lessons Learned**
- [ ] Root cause analysis: what was the initial access vector?
- [ ] Control gaps: what detection or prevention control was missing?
- [ ] Document timeline and IOCs; share (sanitized) with your ISAC

---

## Playbook 2: Phishing / Business Email Compromise (BEC)

### Indicators of Compromise
- User reports suspicious email or clicked link
- Alert from email security gateway (DMARC fail, malicious URL)
- New inbox rules forwarding email externally
- Anomalous sign-in from unexpected geography or device
- Unauthorized financial transaction or wire transfer request

### Response Steps

**Identification**
- [ ] Obtain original email headers and body from affected user
- [ ] Check SPF, DKIM, DMARC results in email headers
- [ ] Verify if link was clicked and/or credentials were entered (check proxy/browser history)
- [ ] Determine if this is targeted spear-phishing (personal details) or mass phishing
- [ ] Search email gateway for other recipients of the same message

**Containment**
- [ ] Purge malicious email from all mailboxes (Microsoft 365: `New-ComplianceSearchAction -Purge`)
- [ ] Reset the compromised user's password immediately
- [ ] Revoke all active sessions: `Revoke-AzureADUserAllRefreshToken` or equivalent
- [ ] Enable MFA on the affected account if not already active
- [ ] Block the malicious URL and sender domain at email gateway and proxy
- [ ] Review and remove any suspicious inbox rules (forwarding to external addresses)
- [ ] Check for OAuth app grants that may have been authorized during compromise

**Eradication**
- [ ] Review sign-in logs for access from attacker IP/device during compromise window
- [ ] Determine what data was accessed, read, or exfiltrated during compromise
- [ ] Review sent items for emails sent by attacker impersonating the user
- [ ] For BEC: contact bank or wire transfer recipient immediately if financial fraud occurred

**Recovery**
- [ ] Restore any deleted or modified emails from backup
- [ ] Enforce MFA and re-verify all inbox rules for the affected user
- [ ] Implement DMARC `p=reject` policy on your domain to prevent future spoofing

**Lessons Learned**
- [ ] Add to simulated phishing campaign; send targeted training to affected user
- [ ] Review DMARC/DKIM/SPF configuration for all domains
- [ ] Evaluate email gateway rule for the specific lure type that succeeded

---

## Playbook 3: Malware / Trojan Infection

### Indicators of Compromise
- EDR alert on malicious process execution or file
- Unexpected network connection from endpoint to unknown external IP
- Persistence mechanism created (scheduled task, registry Run key, service)
- Unusual parent-child process relationships (e.g., Word spawning PowerShell)
- AV quarantine event followed by continued malicious activity

### Response Steps

**Identification**
- [ ] Collect EDR telemetry: process tree, network connections, file writes, registry modifications
- [ ] Hash the malware file and check against VirusTotal
- [ ] Identify the infection vector: email attachment, drive-by download, USB, lateral movement?
- [ ] Assess lateral movement: did the malware attempt to spread to other hosts?

**Containment**
- [ ] Isolate the infected endpoint via EDR or network switch port disable
- [ ] Disable the affected user account pending investigation
- [ ] Block identified C2 IPs and domains at firewall and DNS
- [ ] Acquire forensic memory dump and disk image before remediation

**Eradication**
- [ ] Remove malware using EDR remediation or manual removal (based on analysis findings)
- [ ] Delete all persistence mechanisms: scheduled tasks, services, registry keys, startup entries
- [ ] Verify no additional implants or backdoors (compare running processes/services to baseline)
- [ ] Scan for lateral movement artifacts on other hosts that communicated with infected host

**Recovery**
- [ ] Reimage endpoint if full confidence in clean state cannot be achieved
- [ ] Restore user data from backup if needed
- [ ] Verify system is clean before reconnecting to network

---

## Playbook 4: Unauthorized Access / Insider Threat

### Indicators of Compromise
- UEBA alert: data access significantly above baseline
- Large volume download to USB, personal cloud, or external email
- Access to systems outside normal role or business hours
- Repeated failed access attempts followed by success
- HR notification of disciplinary action or resignation

### Response Steps

**Identification**
- [ ] Collect access logs for the user across all systems: file server, SharePoint, email, VPN
- [ ] Determine what data was accessed, copied, or transmitted
- [ ] Preserve logs without tipping off the subject (covert collection phase)
- [ ] Involve HR, Legal, and management before taking overt action

**Containment (Coordinated with HR/Legal)**
- [ ] Revoke access simultaneously with HR action (termination/suspension)
- [ ] Recover company devices immediately
- [ ] Disable all accounts and revoke remote access credentials
- [ ] Preserve forensic artifacts from user's devices before returning or wiping

**Eradication**
- [ ] Identify all data exfiltrated; assess breach notification obligations
- [ ] Remove any backdoors or unauthorized accounts created by the insider

**Recovery**
- [ ] Review and strengthen data exfiltration prevention controls (DLP, USB blocking)
- [ ] Implement UEBA alerting for mass data access anomalies

---

## Playbook 5: DDoS Attack

### Indicators of Compromise
- Significant increase in inbound traffic volume
- Service degradation or complete unavailability
- Single IP or small IP ranges generating disproportionate traffic
- Network device CPU/memory at saturation
- ISP or upstream provider notification

### Response Steps

**Identification**
- [ ] Confirm the outage is DDoS, not an internal failure (check network device health)
- [ ] Identify attack type: volumetric (UDP flood), protocol (SYN flood), or application layer (HTTP flood)
- [ ] Collect source IPs, packet types, and target ports from firewall and flow data

**Containment**
- [ ] Activate DDoS protection service (AWS Shield, Cloudflare, Akamai) if available
- [ ] Apply upstream null routing or blackhole filtering via ISP for volumetric attacks
- [ ] Apply ACLs to block identified source IP ranges at perimeter
- [ ] Enable rate limiting on web servers for application-layer attacks
- [ ] Redirect DNS to DDoS scrubbing service

**Recovery**
- [ ] Restore services once attack subsides or scrubbing is effective
- [ ] Monitor for resumption or shifting attack vectors

**Lessons Learned**
- [ ] Subscribe to DDoS protection service if not already in place
- [ ] Configure rate limiting and WAF rules proactively
- [ ] Establish ISP null-routing contact procedure in advance
