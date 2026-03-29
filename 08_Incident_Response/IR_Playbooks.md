# Incident Response Playbooks

These playbooks provide step-by-step procedures for the most common incident types. Adapt them to your organization's environment before an incident occurs.

---

## Playbook 1 — Phishing Email Analysis and Response

### Detection Triggers
- User reports suspicious email
- Email gateway quarantine alert
- SIEM alert on email-borne malware
- User reports clicking a link and receiving a security warning

### Phase: Identification and Analysis

```
Step 1: Do NOT click any links or open any attachments on a production machine

Step 2: Collect the email artifact
  - Export as .eml or .msg file (Outlook: File → Save As → Outlook Message Format)
  - Note: sending IP, sender address, reply-to address, subject, timestamp

Step 3: Analyze email headers
  - Open headers: Outlook → File → Properties → Internet headers
  - Look for:
    □ SPF check result (Received-SPF: FAIL = sender is spoofed)
    □ DKIM signature result (dkim=fail = signature invalid)
    □ DMARC result (dmarc=fail = failed authentication policy)
    □ Originating IP vs. claimed sending domain mismatch
    □ X-Originating-IP header

Step 4: Analyze links (safely)
  - Hover over links (don't click) to see actual destination
  - Check links on VirusTotal: https://www.virustotal.com/gui/url
  - Use URLScan.io for safe detonation: https://urlscan.io
  - Identify: phishing kit, credential harvesting page, malware download

Step 5: Analyze attachments (safely — in sandbox only)
  - Hash the attachment (SHA-256) and check on VirusTotal
  - Upload to Any.Run or Hybrid-Analysis for behavioral analysis
  - NEVER open on a production machine
```

### Phase: Containment

```
□ Quarantine the email from all mailboxes (use Exchange/M365 Content Search)
  PowerShell (Exchange Online):
  New-ComplianceSearchAction -SearchName "PhishSearch" -Purge -PurgeType SoftDelete

□ Block sender domain/IP at email gateway

□ Block malicious URLs at web proxy/DNS filter

□ Block malicious file hashes at EDR

□ Identify all recipients — who else received this email?
  Get-MessageTrace -SenderAddress "attacker@evil.com" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)

□ Identify who clicked the link (web proxy logs, email read receipts)

□ For users who clicked: escalate to endpoint compromise playbook
```

### Phase: Eradication

```
□ Reset credentials for any users who entered credentials on phishing page
□ Revoke active sessions for affected users (M365: Revoke-AzureADUserAllRefreshToken)
□ Enable MFA if not already enabled for affected accounts
□ Notify affected users (without causing panic)
```

### Phase: Recovery and Lessons Learned

```
□ Confirm no credentials were used (check audit logs for account activity)
□ Update email gateway rules to block similar campaigns
□ Add IOCs to threat intelligence platform
□ Run security awareness reminder if many users clicked
□ Document in incident report
```

---

## Playbook 2 — Ransomware Response

### Detection Triggers
- User reports files with changed extensions and ransom note
- EDR alerts on shadow copy deletion
- SIEM alerts on mass file rename events
- Help desk flood of "my files are corrupted"

### Phase: Identification

```
Step 1: Confirm ransomware (not just file corruption)
  - Look for: renamed files with new extensions, ransom note files
  - Identify variant using: ID Ransomware (id-ransomware.malwarehunterteam.com)
    (Upload the ransom note or a sample encrypted file — no decryption needed)

Step 2: Identify scope
  - Which systems are affected?
  - Is encryption still ongoing?
  - Are network shares encrypted? (indicates network-propagating ransomware)
  - Was Active Directory compromised? (indicates sophisticated operator)

Step 3: Identify entry point (while containing)
  - Check EDR for initial execution
  - Review email logs for phishing around time of first infection
  - Check VPN/RDP logs for unauthorized access
  - Look for EternalBlue (MS17-010) exploitation if lateral movement is rapid
```

### Phase: Containment — IMMEDIATE

```
⚠️ SPEED IS CRITICAL — Every second of delay means more encrypted files

□ IMMEDIATELY isolate affected hosts from the network
  - Pull the network cable (physical isolation is fastest)
  - OR: Disable NIC via EDR (if EDR is still responsive)
  - Do NOT power off — preserve evidence and encryption keys in RAM

□ Disable affected user accounts if credentials were compromised

□ Isolate network segments if propagation is occurring
  - Block SMB (445) between VLANs at firewall
  - Disable inter-VLAN routing as last resort

□ Alert IT/server team to monitor backup systems
  - Ensure backup servers are NOT connected to affected networks
  - Verify offline/immutable backups are intact

□ Notify executive leadership and legal immediately

□ DO NOT pay the ransom without legal/executive approval and law enforcement consultation
```

### Phase: Eradication

```
□ Identify the ransomware binary (from EDR, memory forensics, or Prefetch)
□ Collect IOCs: file hashes, C2 IPs, ransom note content, file extension
□ Report to law enforcement (FBI IC3, CISA) — required in many jurisdictions
□ Search for decryptors: NoMoreRansom.org (may have free decryptor)
□ Remove ransomware from affected systems
□ Remove all attacker persistence mechanisms (scheduled tasks, services)
□ Rotate ALL credentials — assume all credentials on affected systems are compromised
□ Rebuild heavily compromised systems from known-good images
```

### Phase: Recovery

```
□ Verify backups are clean (test restore in isolated environment first)
□ Restore from most recent verified clean backup
□ Apply patches for the exploited vulnerability
□ Implement controls to prevent recurrence:
    - Disable SMBv1 if EternalBlue was used
    - Enable MFA on VPN/RDP if credential compromise was the entry
    - Implement network segmentation to limit future blast radius
□ Restore services incrementally, monitoring closely
□ Monitor for 90 days with enhanced alerting
```

### Prevention Checklist

```
□ Maintain offline/immutable backups (3-2-1 rule: 3 copies, 2 media types, 1 offsite)
□ Test backup restoration quarterly
□ Patch critical vulnerabilities within 30 days
□ Disable SMBv1 network-wide
□ Restrict RDP access — VPN + MFA only
□ Enable Network Level Authentication on RDP
□ Implement network segmentation — limit lateral movement
□ Deploy EDR with ransomware-specific behavioral detection
□ Restrict execution from %TEMP% and %APPDATA% (AppLocker/WDAC)
□ Enable Protected Users security group for privileged accounts
```

---

## Playbook 3 — Insider Threat / Unauthorized Data Access

### Detection Triggers
- DLP alert on large data transfer or sensitive file access
- SIEM alert on abnormal data access volume for a user
- HR notification of employee resignation/termination
- Audit finding of excessive data downloads
- Manager report of suspicious employee behavior

### Phase: Identification

```
⚠️ Insider threat investigations require HR and Legal involvement from the start
   Do NOT confront the employee until instructed by HR/Legal

Step 1: Verify the alert (false positive check)
  - Is the access volume unusual compared to the user's 30-day baseline?
  - Is there a legitimate business reason? (Project, audit, authorized work)
  - Check with manager — is this expected activity?

Step 2: Scope the activity
  - What data was accessed? (Classification level)
  - How much data? (Volume indicates severity)
  - Was data exfiltrated? (Email, USB, cloud upload, SFTP)
  - Timeline of activity (started when? related to HR events?)

Step 3: Evidence collection (covert — do not alert the user)
  - Export DLP logs
  - Export email audit logs (sent items, forwarding rules)
  - Export web proxy logs (cloud storage uploads)
  - Export USB device logs (Event ID 4663 on Windows)
  - Capture network traffic from the user's workstation (via SPAN port)
  - DO NOT remotely access the user's machine in a way they would notice
```

### Phase: Containment (Coordinated with HR/Legal)

```
For confirmed malicious insider (coordinated with HR):
□ Revoke access simultaneously with HR action (termination/suspension)
□ Preserve all accounts — do not delete (evidence preservation)
□ Revoke VPN, remote access, cloud access, physical badge
□ Preserve device — do not allow user to return equipment without imaging
□ Check for email forwarding rules set to external accounts
□ Check for cloud sync clients (OneDrive, Dropbox) and revoke tokens
□ Freeze access to corporate systems — even legacy/forgotten systems
```

### Legal Considerations

```
□ Maintain strict confidentiality — limit knowledge to HR, Legal, IR team
□ Do NOT discuss investigation with the subject's colleagues
□ Preserve all evidence per chain of custody requirements
□ Consult legal before contacting law enforcement
□ Regulatory reporting may be required if PII/PHI was accessed
□ Employment law governs what monitoring is permissible — consult legal
```

---

## Playbook 4 — Credential Compromise / Account Takeover

### Detection Triggers
- Login from unusual geography or impossible travel (two logins 20 minutes apart from different continents)
- SIEM alert: 4625 (failed logins) followed by 4624 (success) from external IP
- Threat intelligence: credentials found in dark web dump
- User reports they cannot log in (account locked)
- Suspicious email forwarding or inbox rules created

### Phase: Identification

```
Step 1: Confirm the account is compromised (not just MFA challenge)
  - Check login geography vs. user's known location
  - Check login time vs. user's working hours
  - Check user-agent (login from unexpected device/browser)
  - Review post-login activity (what did they do?)

Step 2: Identify scope
  - Are other accounts compromised? (Credential stuffing often hits multiple accounts)
  - Was the account used to access sensitive systems?
  - Was the account used to create new accounts or grant permissions?
  - Were email forwarding rules created?
```

### Phase: Containment

```
□ Disable the compromised account immediately
□ Revoke all active sessions (M365: Revoke-AzureADUserAllRefreshToken)
□ Reset the password to a random value (don't reuse)
□ Revoke all OAuth tokens and app permissions granted by the account
□ Check for and remove malicious inbox forwarding rules
□ Check for any accounts or API keys created by the compromised account
□ Notify the user via out-of-band channel (phone, not email — email may be compromised)
```

### Phase: Eradication and Recovery

```
□ Issue a new strong password and enroll in MFA before re-enabling
□ Enroll hardware security key if account has elevated privileges
□ Audit actions taken during the compromise window
□ Determine entry point: phishing, credential stuffing, brute force, insider?
□ Remediate the root cause
□ Review and revoke any permissions granted during compromise
□ Monitor account closely for 30 days after restoration
```

---

## Documentation Templates

### Incident Ticket (Minimum Required Fields)

```
INCIDENT TICKET

ID: INC-YYYY-XXXX
Date/Time Created: 
Severity: P1 / P2 / P3 / P4
Status: Open / In Progress / Contained / Closed
Assigned To:
Reported By:

Summary:
[2-3 sentence description]

Affected Systems:
[List of hostnames/IPs]

Current Actions:
[Timestamped action log]

Next Steps:
[What happens next]
```
