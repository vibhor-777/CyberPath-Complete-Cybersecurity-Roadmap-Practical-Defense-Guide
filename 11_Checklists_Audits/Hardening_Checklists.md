# Hardening Checklists

Hardening reduces the attack surface by disabling unnecessary features, applying secure configurations, and enforcing least privilege. Use these checklists during system provisioning and quarterly audits. Each item should be verified — not assumed.

---

## Windows Server Hardening Checklist

### Account and Authentication
- [ ] Rename or disable the built-in `Administrator` account
- [ ] Ensure the built-in `Guest` account is disabled
- [ ] Enforce minimum password length of 14+ characters via GPO
- [ ] Set account lockout: 5 attempts, 30-minute lockout, 30-minute counter reset
- [ ] Require MFA for all remote access (RDP, VPN, admin portals)
- [ ] Disable NTLM authentication where Kerberos is available
- [ ] Remove accounts that have not logged in within 90 days

### Services and Attack Surface
- [ ] Disable SMBv1 (`Set-SmbServerConfiguration -EnableSMB1Protocol $false`)
- [ ] Disable unnecessary services (Telnet, FTP, Print Spooler on non-print servers)
- [ ] Disable Remote Registry service
- [ ] Disable Windows Script Host if not required (`wscript //off`)
- [ ] Block execution from `%TEMP%`, `%APPDATA%`, `%Downloads%` via AppLocker/WDAC

### Patching and Updates
- [ ] Apply all Critical and High patches within SLA (Critical: 72h, High: 7d)
- [ ] Enable Windows Update or configure WSUS
- [ ] Verify patch compliance via SCCM or Intune Compliance Policy

### Audit Logging
- [ ] Enable audit logon events (Success and Failure) — Event IDs 4624, 4625, 4648
- [ ] Enable audit process creation — Event ID 4688 with command-line logging
- [ ] Enable PowerShell Script Block Logging — Event ID 4104
- [ ] Enable audit object access for sensitive file shares
- [ ] Forward all logs to SIEM via Windows Event Forwarding (WEF) or Sysmon

### Network
- [ ] Enable Windows Firewall on all profiles (Domain, Private, Public)
- [ ] Block inbound SMB (445) and RPC (135) from untrusted networks at perimeter
- [ ] Restrict RDP (3389) to management VLAN only; disable if not required
- [ ] Enable IPSec or SMB signing to prevent relay attacks

### Credential Protection
- [ ] Enable Windows Defender Credential Guard (requires UEFI, Secure Boot, VT-x)
- [ ] Enable Protected Users security group for privileged accounts
- [ ] Deploy LAPS (Local Administrator Password Solution) for local admin accounts
- [ ] Audit accounts with `AdminCount=1` — remove stale shadow admins

### Endpoint Protection
- [ ] Enable and configure Microsoft Defender Antivirus (or equivalent EDR)
- [ ] Enable Tamper Protection in Defender
- [ ] Enable Attack Surface Reduction (ASR) rules
- [ ] Deploy Sysmon with a hardened configuration (SwiftOnSecurity/sysmon-config)

---

## Linux Server Hardening Checklist

### SSH Hardening
```bash
# /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no       # Key-based auth only
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers deploy ansible       # Explicit allowlist
Protocol 2
```
- [ ] SSH key-based authentication enforced; password auth disabled
- [ ] Root login via SSH disabled
- [ ] SSH access restricted to specific users and management IPs (AllowUsers + firewall)
- [ ] SSH version 2 only

### Account Security
- [ ] Remove or lock unused accounts (`usermod -L username`)
- [ ] Verify no accounts have empty passwords: `awk -F: '($2 == "")' /etc/shadow`
- [ ] Restrict `su` to wheel group: `auth required pam_wheel.so use_uid`
- [ ] Configure sudo: no `NOPASSWD` for interactive users; log all commands
- [ ] Set password policies in `/etc/login.defs` (PASS_MAX_DAYS 90, PASS_MIN_LEN 14)

### Services and Packages
- [ ] Disable unused services: `systemctl disable <service>`
- [ ] Remove unnecessary packages: `apt autoremove` / `yum autoremove`
- [ ] Disable IPv6 if not in use: `net.ipv6.conf.all.disable_ipv6 = 1`
- [ ] Configure NTP for accurate log timestamps

### Filesystem
- [ ] Mount `/tmp` with `noexec,nosuid,nodev` options
- [ ] Mount `/var/tmp` with `noexec,nosuid,nodev`
- [ ] Set sticky bit on world-writable directories: `chmod +t /tmp`
- [ ] Verify SUID/SGID binaries: `find / -perm /6000 -type f 2>/dev/null`

### Kernel and Network Hardening (sysctl)
```bash
# /etc/sysctl.d/99-hardening.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
```
- [ ] Apply kernel hardening parameters via sysctl
- [ ] Enable and configure firewalld or ufw with default-deny inbound

### Audit Logging
- [ ] Install and configure auditd
- [ ] Audit authentication events, privilege escalation, and file modifications
- [ ] Forward logs to SIEM (rsyslog or Filebeat)
- [ ] Enable AIDE or similar FIM tool for critical file integrity monitoring

### Patching
- [ ] Enable automatic security updates (unattended-upgrades or dnf-automatic)
- [ ] Schedule patching windows; track compliance

---

## Network Device Hardening Checklist

### Management Access
- [ ] Disable Telnet; use SSHv2 only
- [ ] Restrict management access to dedicated management VLAN (OOB if possible)
- [ ] Set console and VTY timeouts (exec-timeout 5 0)
- [ ] Use centralized RADIUS/TACACS+ for device authentication
- [ ] Change all default credentials immediately

### Protocols
- [ ] Disable CDP/LLDP on untrusted external-facing interfaces
- [ ] Enable BPDU Guard on all access ports (prevents rogue switches)
- [ ] Enable port security or 802.1X on access layer switches
- [ ] Disable unused switch ports; assign to an isolated VLAN
- [ ] Disable IP directed broadcasts
- [ ] Enable DHCP snooping and Dynamic ARP Inspection (DAI)

### Routing
- [ ] Use MD5 or SHA authentication for routing protocols (OSPF, BGP)
- [ ] Implement route filtering — only advertise intended prefixes
- [ ] Enable RPF (Reverse Path Forwarding) to prevent IP spoofing

### Logging and Monitoring
- [ ] Configure syslog to a central SIEM with correct timestamp (NTP synchronized)
- [ ] Enable SNMP v3 with authentication and encryption (disable v1/v2c)
- [ ] Log all management plane access (login, configuration changes)

---

## Cloud (AWS) Hardening Checklist

### Identity and Access
- [ ] Enable MFA on the root account and all IAM users
- [ ] Delete or disable root account access keys
- [ ] Apply IAM policies with least privilege (no wildcards on Action or Resource)
- [ ] Enable IAM Access Analyzer to find overly permissive policies
- [ ] Use IAM Roles for EC2 instances — no static credentials on instances

### Logging and Monitoring
- [ ] Enable CloudTrail in all regions with log file integrity validation
- [ ] Enable AWS Config for continuous configuration compliance monitoring
- [ ] Enable GuardDuty for threat detection
- [ ] Enable S3 bucket access logging for sensitive buckets
- [ ] Enable VPC Flow Logs for all VPCs

### Network
- [ ] Restrict security groups: no `0.0.0.0/0` on inbound SSH or RDP
- [ ] Enable default VPC flow logging
- [ ] Use private subnets for all workloads not requiring direct internet access
- [ ] Deploy WAF in front of all internet-facing applications

### Data Protection
- [ ] Enable default S3 bucket encryption (AES-256 or AWS KMS)
- [ ] Block all public S3 bucket access at the account level (S3 Block Public Access)
- [ ] Enable EBS volume encryption by default
- [ ] Enable RDS encryption at rest and in transit (SSL/TLS)
- [ ] Rotate KMS keys and IAM access keys on schedule
