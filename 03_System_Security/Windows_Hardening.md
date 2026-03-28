# Windows Hardening

> **Module:** 03 — System Security | **Focus:** Defensive configuration of Windows endpoints and servers

Windows is the dominant operating system in enterprise environments and, consequently, the most frequently targeted by adversaries. A default Windows installation ships with many features enabled for compatibility and convenience — not security. This guide walks through the key hardening controls every defender must know, from registry security to Sysmon deployment, using an "Assume Breach" mindset throughout.

---

## 📋 Table of Contents

1. [Registry Security](#1-registry-security)
2. [Group Policy Objects (GPO)](#2-group-policy-objects-gpo)
3. [Windows Defender Configuration](#3-windows-defender-configuration)
4. [Disabling Unnecessary Services](#4-disabling-unnecessary-services)
5. [Account Management and Password Policies](#5-account-management-and-password-policies)
6. [Windows Event IDs to Monitor](#6-windows-event-ids-to-monitor)
7. [PowerShell Logging and Transcription](#7-powershell-logging-and-transcription)
8. [Assume Breach — Host-Based Sensors for Lateral Movement](#8-assume-breach--host-based-sensors-for-lateral-movement)
9. [Sysmon Configuration for Endpoint Detection](#9-sysmon-configuration-for-endpoint-detection)
10. [Module Practice Challenge](#10-module-practice-challenge)

---

## 1. Registry Security

### 🟢 Beginner Explanation

The Windows Registry is a hierarchical database that stores configuration settings for the operating system and applications. Think of it as the central nervous system of Windows — every application and system component reads from and writes to it. Because of this, adversaries love to abuse the registry to **persist** on a system: they can plant a value that tells Windows to run their malicious code every time the machine starts or a user logs in, without touching any obvious startup folder.

### 🔬 Technical Deep Dive

#### Key Autorun / Persistence Locations

The most commonly abused registry keys for persistence are the "Run" and "RunOnce" keys:

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

Any value placed under these keys will execute the specified binary when Windows starts (HKLM, system-wide) or when the current user logs in (HKCU, user-specific).

Additional high-value persistence locations attackers use:

```
HKLM\SYSTEM\CurrentControlSet\Services\                  ← Malicious service registration
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\  ← Userinit / Shell hijacking
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\  ← Debugger hijacking
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\
```

#### Querying Registry Autorun Keys (PowerShell)

```powershell
# List all HKLM Run entries
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" |
    Select-Object * -ExcludeProperty PS*

# List all HKCU Run entries
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" |
    Select-Object * -ExcludeProperty PS*

# Check both RunOnce keys
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue
```

#### Restricting Write Access to Run Keys

By default, standard users can write to `HKCU\...\Run`, which is a legitimate persistence vector for user applications — but also for malware running under a standard user token. Restricting `HKLM\...\Run` write access to Administrators only is critical:

```powershell
# ⚠️ Lab Environment Only — modifying registry ACLs can break legitimate applications
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$acl = Get-Acl $regPath

# Remove any non-admin write permissions (review before applying)
$acl.Access | Where-Object {
    $_.RegistryRights -match "SetValue|CreateSubKey" -and
    $_.IdentityReference -notmatch "Administrators|SYSTEM"
} | ForEach-Object { $acl.RemoveAccessRule($_) }

Set-Acl -Path $regPath -AclObject $acl
```

#### Monitoring Registry Changes with Auditing

Enable object access auditing via Group Policy (see Section 2), then configure auditing on the key directly:

```powershell
# Enable auditing on the Run key for all users
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$acl = Get-Acl $regPath
$auditRule = New-Object System.Security.AccessControl.RegistryAuditRule(
    "Everyone",
    "SetValue,CreateSubKey,Delete",
    "ContainerInherit,ObjectInherit",
    "None",
    "Success,Failure"
)
$acl.SetAuditRule($auditRule)
Set-Acl -Path $regPath -AclObject $acl
```

This generates **Event ID 4657** (Registry value modified) in the Security log whenever a write occurs.

### 🌍 Real-World Relevance

The MITRE ATT&CK technique **T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)** is one of the most commonly observed persistence mechanisms in real-world intrusions. Threat actors including APT groups and ransomware operators routinely drop payloads into Run keys because it is simple, effective, and often overlooked by defenders who focus only on file-based artifacts.

### 🛡️ Defensive Measures

| Control | Action |
|---------|--------|
| Least Privilege | Ensure standard users cannot write to `HKLM` Run keys |
| Registry Auditing | Enable Object Access auditing + audit rule on persistence keys |
| Autoruns (Sysinternals) | Run `Autoruns.exe` (or `autorunsc.exe -a *`) to enumerate all persistence mechanisms |
| AppLocker / WDAC | Block execution of binaries launched from user-writable paths |
| Sysmon Rule 13 | Log registry value set events for monitored keys |
| SIEM Alerting | Alert on new values written to Run/RunOnce keys |

---

## 2. Group Policy Objects (GPO)

### 🟢 Beginner Explanation

Group Policy is Windows' built-in mechanism for applying security and configuration settings to computers and users — either locally (Local Group Policy) or across an entire Active Directory domain (Domain GPO). Instead of manually configuring every machine, an administrator creates a policy, links it to an Organizational Unit (OU), and Windows automatically applies it. For defenders, GPO is the most powerful native tool to enforce a security baseline at scale.

### 🔬 Technical Deep Dive

#### Opening the Group Policy Management Console

On a Domain Controller or management workstation with RSAT installed:

```
Win + R → gpmc.msc
```

Locally on any Windows machine:

```
Win + R → gpedit.msc
```

#### Advanced Audit Policy Configuration

Standard audit categories are too coarse. Use **Advanced Audit Policy** instead, found at:

```
Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies
```

Recommended settings for a hardened endpoint:

| Subcategory | Setting |
|-------------|---------|
| Account Logon → Credential Validation | Success, Failure |
| Account Management → User Account Management | Success, Failure |
| Account Management → Security Group Management | Success, Failure |
| Detailed Tracking → Process Creation | Success |
| Logon/Logoff → Logon | Success, Failure |
| Logon/Logoff → Logoff | Success |
| Logon/Logoff → Special Logon | Success |
| Object Access → Registry | Success, Failure |
| Object Access → File System | Failure |
| Policy Change → Audit Policy Change | Success, Failure |
| Privilege Use → Sensitive Privilege Use | Success, Failure |
| System → Security System Extension | Success |

Apply via PowerShell using `auditpol`:

```powershell
# Enable process creation auditing (generates Event ID 4688)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Enable credential validation auditing
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# Enable audit policy change auditing
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable

# Verify current settings
auditpol /get /category:*
```

#### Critical GPO Security Settings

Navigate to: `Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options`

Key settings to configure:

```
Network access: Do not allow anonymous enumeration of SAM accounts → Enabled
Network access: Do not allow anonymous enumeration of SAM accounts and shares → Enabled
Network access: Restrict anonymous access to Named Pipes and Shares → Enabled
Network security: LAN Manager authentication level → Send NTLMv2 response only. Refuse LM & NTLM
Network security: Minimum session security for NTLM SSP → Require NTLMv2 session security, Require 128-bit encryption
Interactive logon: Do not display last user name → Enabled
Interactive logon: Machine inactivity limit → 900 seconds (15 min)
User Account Control: Run all administrators in Admin Approval Mode → Enabled
User Account Control: Behavior of the elevation prompt for administrators → Prompt for credentials on the secure desktop
```

#### Enabling Command Line Logging in Process Creation Events

This is essential for detecting malicious command-line activity. Apply via GPO:

```
Computer Configuration → Administrative Templates → System → Audit Process Creation
→ "Include command line in process creation events" → Enabled
```

Or via registry:

```powershell
# ⚠️ Lab Environment Only — sets command line inclusion in Event ID 4688
$auditKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
# Create the key if it doesn't already exist
if (-not (Test-Path $auditKeyPath)) {
    New-Item -Path $auditKeyPath -Force | Out-Null
}
Set-ItemProperty -Path $auditKeyPath `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
```

### 🌍 Real-World Relevance

Without Advanced Audit Policy configured, a Windows system generates almost no useful forensic data. Incident responders frequently arrive at compromised environments only to find that no auditing was enabled — meaning there is no evidence of what the attacker did, which accounts they used, or which processes they ran. GPO is the lever that turns a blind machine into a monitored endpoint.

### 🛡️ Defensive Measures

| Control | GPO Path |
|---------|----------|
| Restrict credential caching | `Security Settings → Local Policies → Security Options → Interactive logon: Number of previous logons to cache → 1` |
| Disable LLMNR | `Administrative Templates → Network → DNS Client → Turn off multicast name resolution → Enabled` |
| Disable NetBIOS over TCP/IP | Deploy via DHCP scope option 001 or registry key |
| Enforce SMB signing | `Security Settings → Local Policies → Security Options → Microsoft network server: Digitally sign communications (always) → Enabled` |
| Block Macro execution | `Administrative Templates → Microsoft Office → Security → VBA Macro Notification Settings → Disable all macros` |

---

## 3. Windows Defender Configuration

### 🟢 Beginner Explanation

Windows Defender Antivirus (now part of Microsoft Defender for Endpoint in enterprise environments) is the built-in antimalware solution in Windows 10/11 and Windows Server 2016+. Many organisations disable it when deploying third-party AV, but even when a third-party solution is present, Defender's supplementary features — such as Attack Surface Reduction (ASR) rules, Controlled Folder Access, and Network Protection — remain independently valuable.

### 🔬 Technical Deep Dive

#### Verifying Defender Status

```powershell
# Check overall Defender status
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled,
    AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled,
    NISEnabled, OnAccessProtectionEnabled, BehaviorMonitorEnabled

# Check definition version and last update
Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated, AntivirusSignatureVersion
```

#### Enabling Attack Surface Reduction (ASR) Rules

ASR rules block specific behaviors commonly exploited by malware, regardless of whether the payload matches a known signature:

```powershell
# ⚠️ Lab Environment Only — test ASR rules in Audit mode before enabling in Block mode

# Block Office applications from creating child processes (T1566 — Phishing)
Add-MpPreference -AttackSurfaceReductionRules_Ids "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" `
    -AttackSurfaceReductionRules_Actions Enabled

# Block Office from injecting into other processes
Add-MpPreference -AttackSurfaceReductionRules_Ids "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" `
    -AttackSurfaceReductionRules_Actions Enabled

# Block credential stealing from lsass.exe (T1003 — OS Credential Dumping)
Add-MpPreference -AttackSurfaceReductionRules_Ids "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" `
    -AttackSurfaceReductionRules_Actions Enabled

# Block untrusted and unsigned processes that run from USB
Add-MpPreference -AttackSurfaceReductionRules_Ids "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" `
    -AttackSurfaceReductionRules_Actions Enabled

# Block persistence through WMI event subscription
Add-MpPreference -AttackSurfaceReductionRules_Ids "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" `
    -AttackSurfaceReductionRules_Actions Enabled

# List all current ASR rules and their states
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
```

#### Enabling Controlled Folder Access

Controlled Folder Access (Ransomware Protection) prevents unauthorized applications from modifying files in protected directories:

```powershell
# Enable Controlled Folder Access
Set-MpPreference -EnableControlledFolderAccess Enabled

# Add custom folders to protection
Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\SensitiveData"

# Allow a specific trusted application
Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\MyApp\myapp.exe"

# Check current status
Get-MpPreference | Select-Object EnableControlledFolderAccess
```

#### Enabling Cloud-Delivered Protection and Automatic Sample Submission

```powershell
# Enable cloud protection (MAPS)
Set-MpPreference -MAPSReporting Advanced

# Enable automatic sample submission for unknown files
Set-MpPreference -SubmitSamplesConsent SendAllSamples

# Set cloud block level to High
Set-MpPreference -CloudBlockLevel High

# Set extended cloud check timeout (seconds)
Set-MpPreference -CloudExtendedTimeout 50
```

### 🌍 Real-World Relevance

The Lazarus Group and many ransomware operators specifically check for and attempt to disable Windows Defender before executing their payloads. ASR rules, when properly tuned, can block entire classes of attacks regardless of signature — making them one of the highest-value controls available at no additional licensing cost on Windows 10/11.

### 🛡️ Defensive Measures

- Enable Tamper Protection to prevent attackers from disabling Defender via PowerShell or registry (`Virus & Threat Protection Settings → Tamper Protection`)
- Use Defender for Endpoint (MDE) in enterprise environments for EDR capabilities
- Set up alert rules in Microsoft Defender portal for ASR rule blocks
- Monitor Event ID **5007** (Defender configuration changed) to detect tampering

---

## 4. Disabling Unnecessary Services

### 🟢 Beginner Explanation

Every running service is a potential attack surface. Services that you do not need represent unnecessary risk — they consume resources, may have vulnerabilities, and can be exploited to elevate privileges or move laterally. The principle of minimal footprint dictates: if you don't need it, turn it off.

### 🔬 Technical Deep Dive

#### Auditing Running Services

```powershell
# List all running services with display name, start type, and path
Get-Service | Where-Object {$_.Status -eq "Running"} |
    Select-Object Name, DisplayName, StartType |
    Sort-Object DisplayName

# Get service binary paths (critical for identifying suspicious services)
Get-WmiObject Win32_Service |
    Select-Object Name, DisplayName, StartMode, State, PathName |
    Where-Object {$_.State -eq "Running"} |
    Sort-Object DisplayName | Format-Table -AutoSize
```

#### Services Commonly Safe to Disable (Review Before Applying)

```powershell
# ⚠️ Lab Environment Only — validate against your environment before disabling

$servicesToDisable = @(
    "Fax",                    # Fax service — rarely needed
    "XblGameSave",            # Xbox game save sync
    "XboxNetApiSvc",          # Xbox network service
    "WSearch",                # Windows Search indexer — disable if not needed
    "SysMain",                # Superfetch — disable on SSDs/servers
    "RemoteRegistry",         # Allows remote registry editing — high risk
    "Telnet",                 # Cleartext remote access — should never be enabled
    "SNMP",                   # Simple Network Management Protocol — if not monitored
    "SNMPTRAP",               # SNMP trap service
    "RasMan",                 # Remote Access Connection Manager — if no VPN needed
    "SessionEnv",             # Remote Desktop Configuration — if RDP not in use
    "TermService",            # Remote Desktop Services — if RDP not in use
    "UmRdpService"            # Remote Desktop Device Redirector
)

foreach ($svc in $servicesToDisable) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled
        Write-Host "Disabled: $svc"
    }
}
```

#### Disabling Remote Desktop Protocol (RDP) When Not Required

```powershell
# ⚠️ Lab Environment Only — disabling RDP will prevent remote access

# Disable RDP via registry
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
    -Name "fDenyTSConnections" -Value 1

# Disable via firewall rule
Disable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Re-enable if needed
# Set-ItemProperty ... -Value 0
# Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

#### Disabling NetBIOS over TCP/IP

NetBIOS is exploited for credential capture attacks (Responder, NTLM relay). Disable it where not required:

```powershell
# Disable NetBIOS via WMI on all adapters
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true}
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # 2 = Disable NetBIOS over TCP/IP
}
```

### 🌍 Real-World Relevance

The 2017 NotPetya and WannaCry outbreaks spread explosively through corporate networks because **SMBv1** was still enabled on thousands of systems (it is disabled by default in modern Windows, but organisations had not applied the patch or the setting). Disabling a single unnecessary service or protocol feature would have stopped the lateral spread on those machines.

### 🛡️ Defensive Measures

- Use the Microsoft Security Compliance Toolkit (SCT) baseline to identify recommended service states
- Audit services quarterly and compare to a documented baseline
- Use `sc query type= all state= all` for a complete service inventory
- Alert on new service installations via Event ID **7045** (new service installed)

---

## 5. Account Management and Password Policies

### 🟢 Beginner Explanation

Weak account policies are the single most common reason attackers gain initial footholds and maintain persistence. Accounts with weak passwords, disabled expiry, or excessive privileges are low-hanging fruit. This section covers the controls that make credential-based attacks significantly harder.

### 🔬 Technical Deep Dive

#### Configuring Password Policy via GPO

Navigate to: `Computer Configuration → Windows Settings → Security Settings → Account Policies → Password Policy`

Recommended settings (align with NIST SP 800-63B):

```
Minimum password length:          14 characters (NIST recommends 8 minimum; 14+ is better)
Password complexity requirements: Enabled
Maximum password age:             Never (NIST no longer recommends forced rotation)
Minimum password age:             1 day
Enforce password history:         24 passwords remembered
Store passwords using reversible encryption: Disabled
```

#### Configuring Account Lockout Policy

Navigate to: `Computer Configuration → Windows Settings → Security Settings → Account Policies → Account Lockout Policy`

```
Account lockout threshold:        5 invalid logon attempts
Account lockout duration:         30 minutes
Reset account lockout counter:    30 minutes
```

#### Managing Local Accounts with PowerShell

```powershell
# List all local user accounts
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired

# Disable the built-in Administrator account (rename it first)
Rename-LocalUser -Name "Administrator" -NewName "HelpDesk_Admin"
Disable-LocalUser -Name "HelpDesk_Admin"

# Disable the built-in Guest account
Disable-LocalUser -Name "Guest"

# Check members of the local Administrators group
Get-LocalGroupMember -Group "Administrators"

# Find accounts that have never logged in (potential orphaned accounts)
Get-LocalUser | Where-Object {$_.LastLogon -eq $null -and $_.Enabled -eq $true}

# Find accounts with passwords that never expire
Get-LocalUser | Where-Object {$_.PasswordExpires -eq $null -and $_.Enabled -eq $true}
```

#### Implementing LAPS (Local Administrator Password Solution)

LAPS automatically manages and rotates local Administrator passwords, storing them securely in Active Directory. Without LAPS, the same local admin password is typically reused across all machines — a single credential compromise enables lateral movement to every endpoint.

```powershell
# Install LAPS on a workstation (requires LAPS MSI to be available)
# Install-WindowsFeature LAPS  (Server)

# Verify LAPS is installed
Get-Command Get-AdmPwdPassword -ErrorAction SilentlyContinue

# Retrieve LAPS password for a computer (requires AD permissions)
# Get-AdmPwdPassword -ComputerName "WORKSTATION01"
```

### 🌍 Real-World Relevance

Pass-the-Hash (PtH) and Pass-the-Ticket (PtT) attacks are trivially easy when the same local administrator password is reused across workstations. In many breach investigations, a single compromised workstation leads to domain-wide compromise within hours because the attacker simply re-uses the extracted hash on every other machine. LAPS directly mitigates this pattern.

### 🛡️ Defensive Measures

- Deploy LAPS to all domain-joined endpoints
- Enforce MFA on all privileged accounts
- Use Privileged Access Workstations (PAWs) for administrative tasks
- Review local Administrators group membership regularly
- Alert on Event ID **4732** (member added to security-enabled local group)

---

## 6. Windows Event IDs to Monitor

### 🟢 Beginner Explanation

Windows records security-relevant events in the **Security Event Log**. Each event type has a numeric ID. By forwarding these logs to a SIEM and alerting on critical event IDs, defenders gain visibility into authentication attempts, account changes, process executions, and policy modifications — the very activities attackers try to conduct covertly.

### 🔬 Technical Deep Dive

#### Critical Event ID Reference

| Event ID | Category | Description | Threat Relevance |
|----------|----------|-------------|-----------------|
| **4624** | Logon | Successful account logon | Detect unusual logon types (Type 3 = network, Type 10 = remote interactive) |
| **4625** | Logon | Failed logon attempt | Brute-force and password spraying detection |
| **4648** | Logon | Logon using explicit credentials | Pass-the-Hash, lateral movement |
| **4672** | Logon | Special privileges assigned at logon | Privilege escalation detection |
| **4688** | Process | New process created | Malicious execution, living-off-the-land |
| **4698** | Task Scheduler | Scheduled task created | Persistence via scheduled tasks |
| **4702** | Task Scheduler | Scheduled task updated | Modifying existing tasks for persistence |
| **4699** | Task Scheduler | Scheduled task deleted | Covering tracks |
| **4720** | Account | User account created | Backdoor account creation |
| **4726** | Account | User account deleted | Covering tracks |
| **4728** | Account | Member added to security-enabled global group | Privilege escalation |
| **4732** | Account | Member added to security-enabled local group | Local admin escalation |
| **4776** | Authentication | NTLM authentication attempt | Credential attacks, NTLM relay |
| **1102** | Audit | Security audit log cleared | Anti-forensics, covering tracks |
| **7045** | System | New service installed | Persistence via malicious service |
| **4657** | Registry | Registry value modified | Registry persistence detection |
| **5140** | Network | Network share was accessed | Lateral movement, data staging |
| **4771** | Authentication | Kerberos pre-authentication failed | Password spraying against Kerberos |

#### Querying Events with PowerShell

```powershell
# Find all failed logon attempts (Event ID 4625) in the last 24 hours
$startTime = (Get-Date).AddHours(-24)
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $startTime
} | Select-Object TimeCreated, Message | Format-List

# Find accounts that logged on with network logon (Type 3) — look for lateral movement
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
    Where-Object {$_.Message -match "Logon Type:\s+3"} |
    Select-Object TimeCreated,
        @{N='Account';E={($_.Message -split '\n' | Select-String 'Account Name:')[1]}},
        @{N='SourceIP';E={($_.Message -split '\n' | Select-String 'Source Network Address:')[0]}} |
    Sort-Object TimeCreated -Descending | Select-Object -First 20

# Find new scheduled tasks (Event ID 4698)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} |
    Select-Object TimeCreated, Message | Format-List

# Detect audit log clearing (Event ID 1102) — critical alert
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} |
    Select-Object TimeCreated, Message

# Find new service installations (Event ID 7045)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
    Select-Object TimeCreated, Message | Format-List

# Find processes launched with suspicious parents using Event ID 4688
# (requires command line auditing enabled — see Section 2)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
    Where-Object {$_.Message -match "powershell|cmd|wscript|mshta|rundll32|regsvr32"} |
    Select-Object TimeCreated, Message | Format-List
```

#### Detecting Password Spraying with 4625

```powershell
# Identify source IPs with high volumes of failed logons
$failedLogons = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = (Get-Date).AddHours(-1)
}

$failedLogons | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time       = $_.TimeCreated
        Account    = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
        SourceIP   = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
        LogonType  = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'} | Select-Object -ExpandProperty '#text'
    }
} | Group-Object SourceIP | Sort-Object Count -Descending | Select-Object Count, Name
```

#### Setting Up Windows Event Forwarding (WEF)

For centralised log collection without a third-party SIEM:

```
On Collector (server):
1. Run: wecutil qc /q
2. Open Event Viewer → Subscriptions → Create Subscription

On Source (endpoints) via GPO:
Computer Configuration → Administrative Templates → Windows Components →
Event Forwarding → Configure target Subscription Manager
Value: Server=http://COLLECTOR_HOSTNAME:5985/wsman/SubscriptionManager/WEC
```

### 🌍 Real-World Relevance

During the 2020 SolarWinds compromise, attackers moved laterally through victim networks for months undetected. Post-breach analysis showed that **Event ID 4624 logon type 3** events (network logons) and **4648** events (explicit credential logons) were present in the logs the entire time — but no one was watching. Proper SIEM alerting on these IDs would have significantly shortened the dwell time.

### 🛡️ Defensive Measures

- Forward Security and System logs to a SIEM (Splunk, Elastic, Microsoft Sentinel)
- Build detection rules for Event IDs 1102, 7045, 4698/4702, 4720
- Set Security log size to at least 1 GB (`wevtutil sl Security /ms:1073741824`)
- Alert on any account logon outside business hours or from unexpected source IPs

---

## 7. PowerShell Logging and Transcription

### 🟢 Beginner Explanation

PowerShell is the most powerful administrative tool in Windows — which also makes it the most powerful attacker tool. "Living off the land" (LoTL) attacks use PowerShell to download payloads, dump credentials, move laterally, and maintain persistence — all without dropping a traditional executable. Enabling PowerShell logging ensures you can see exactly what commands were run, when, and by whom.

### 🔬 Technical Deep Dive

#### Three Layers of PowerShell Logging

| Log Type | What It Captures | Event ID | Log Location |
|----------|-----------------|----------|--------------|
| Module Logging | All modules loaded and their output | 4103 | `Microsoft-Windows-PowerShell/Operational` |
| Script Block Logging | Full content of every script block executed | 4104 | `Microsoft-Windows-PowerShell/Operational` |
| Transcription | Human-readable text file of entire session | — | Configurable directory |

#### Enabling via GPO

```
Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell

→ Turn on Module Logging → Enabled → Module Names: *
→ Turn on PowerShell Script Block Logging → Enabled
   ✓ Log script block invocation start/stop events
→ Turn on PowerShell Transcription → Enabled
   → Transcript output directory: \\FILESERVER\PSTranscripts$
   ✓ Include invocation headers
```

#### Enabling via Registry (when GPO is not available)

```powershell
# ⚠️ Lab Environment Only — creates registry keys for PS logging

$psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

# Module Logging
$mlPath = "$psLogPath\ModuleLogging"
New-Item -Path $mlPath -Force | Out-Null
Set-ItemProperty -Path $mlPath -Name "EnableModuleLogging" -Value 1 -Type DWord
New-Item -Path "$mlPath\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "$mlPath\ModuleNames" -Name "*" -Value "*" -Type String

# Script Block Logging
$sbPath = "$psLogPath\ScriptBlockLogging"
New-Item -Path $sbPath -Force | Out-Null
Set-ItemProperty -Path $sbPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Set-ItemProperty -Path $sbPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord

# Transcription
$txPath = "$psLogPath\Transcription"
New-Item -Path $txPath -Force | Out-Null
Set-ItemProperty -Path $txPath -Name "EnableTranscripting" -Value 1 -Type DWord
Set-ItemProperty -Path $txPath -Name "EnableInvocationHeader" -Value 1 -Type DWord
Set-ItemProperty -Path $txPath -Name "OutputDirectory" -Value "C:\PSTranscripts" -Type String
```

#### Querying PowerShell Script Block Logs

```powershell
# Find all script block log entries from the last hour
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-PowerShell/Operational'
    Id        = 4104
    StartTime = (Get-Date).AddHours(-1)
} | Select-Object TimeCreated,
    @{N='ScriptBlock';E={$_.Properties[2].Value}} |
    Format-List

# Search for known suspicious keywords in script blocks
$suspiciousPatterns = 'IEX|Invoke-Expression|DownloadString|FromBase64String|' +
    'Net\.WebClient|Invoke-Mimikatz|sekurlsa|LSASS|AmsiBypass|' +
    'Bypass|EncodedCommand|-enc |-w hidden'

Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104
} | Where-Object {$_.Message -match $suspiciousPatterns} |
    Select-Object TimeCreated, Message | Format-List
```

#### Constrained Language Mode

Restrict PowerShell capabilities by default, requiring explicit elevation for advanced features:

```powershell
# Check current language mode
$ExecutionContext.SessionState.LanguageMode

# Constrained Language Mode is enforced via:
# 1. AppLocker / WDAC policy
# 2. System-wide via WDAC policy (preferred — cannot be bypassed like registry keys)

# Check if AMSI is active (PowerShell 5+)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') |
    ForEach-Object { $_.GetField('amsiInitFailed','NonPublic,Static').GetValue($null) }
# Returns False = AMSI is active (good)
```

### 🌍 Real-World Relevance

PowerShell has been used in a significant majority of reported enterprise breaches in recent years, including by FIN7, APT32, and virtually every major ransomware operation. The AMSI (Antimalware Scan Interface) was added specifically to give security products visibility into PowerShell commands before they execute. Script block logging was the single feature that most frequently enabled forensic reconstruction of attacker activity in post-breach investigations between 2018 and 2024.

### 🛡️ Defensive Measures

- Enforce PowerShell v5+ (earlier versions lack logging)
- Disable PowerShell v2 (bypasses logging): `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`
- Set execution policy to `RemoteSigned` or `AllSigned` (not a security boundary, but raises the bar)
- Monitor for `-EncodedCommand` and `-WindowStyle Hidden` flags in process creation events
- Alert on Event ID 4104 entries containing known malicious patterns

---

## 8. Assume Breach — Host-Based Sensors for Lateral Movement

### 🟢 Beginner Explanation

"Assume Breach" is a modern security philosophy that accepts the premise: *a sufficiently motivated attacker will eventually get in*. Rather than focusing exclusively on prevention, defenders invest equally in **detection** — building visibility so that when a breach occurs, you can detect it quickly, contain it, and minimise damage. On the host level, this means deploying sensors that create forensic telemetry about every significant system action.

### 🔬 Technical Deep Dive

#### Lateral Movement Techniques to Detect

Adversaries moving laterally through a network typically use one or more of these techniques:

| Technique | ATT&CK ID | Artifacts / Indicators |
|-----------|-----------|------------------------|
| Pass-the-Hash (PtH) | T1550.002 | Event 4624 Type 3, NTLM auth from unexpected host |
| Pass-the-Ticket (PtT) | T1550.003 | Kerberos ticket anomalies, Event 4768/4769 |
| PSExec / Remote Exec | T1569.002 | Event 7045 (service install), Event 4688 from PSEXESVC |
| WMI execution | T1047 | WmiPrvSE.exe spawning child processes |
| PowerShell Remoting | T1021.006 | Event 4624 Type 3, wsmprovhost.exe |
| RDP | T1021.001 | Event 4624 Type 10, mstsc.exe |
| SMB Admin Shares | T1021.002 | Event 5140 (share access), C$ / ADMIN$ / IPC$ |
| SCM Service Install | T1543.003 | Event 7045 |
| Scheduled Tasks | T1053.005 | Event 4698/4702 |
| DCOM | T1021.003 | DCOM-related process creation |

#### Host-Based Detection Queries

```powershell
# Detect WMI-spawned child processes (common lateral movement technique)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
    Where-Object {$_.Message -match 'WmiPrvSE'} |
    Select-Object TimeCreated, Message | Format-List

# Detect PSExec indicators
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
    Where-Object {$_.Message -match 'PSEXESVC|psexec'} |
    Select-Object TimeCreated, Message

# Detect admin share access
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5140} |
    Where-Object {$_.Message -match "ADMIN\$|C\$|IPC\$"} |
    Select-Object TimeCreated, Message | Format-List

# Detect network logons outside business hours (rough example)
$businessStart = 7  # 7 AM
$businessEnd   = 19 # 7 PM
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
    Where-Object {
        $_.TimeCreated.Hour -lt $businessStart -or
        $_.TimeCreated.Hour -ge $businessEnd
    } |
    Where-Object {$_.Message -match "Logon Type:\s+3"} |
    Select-Object TimeCreated, Message | Format-List
```

#### Implementing Credential Guard

Credential Guard uses virtualisation-based security (VBS) to isolate LSASS, preventing credential extraction by tools like Mimikatz:

```powershell
# Check Credential Guard status
Get-ComputerInfo | Select-Object DeviceGuardSecurityServicesRunning,
    DeviceGuardSecurityServicesConfigured

# Enable Credential Guard via GPO:
# Computer Configuration → Administrative Templates → System → Device Guard
# → Turn on Virtualization Based Security → Enabled
#   → Credential Guard Configuration: Enabled with UEFI lock
```

### 🌍 Real-World Relevance

The Mandiant M-Trends 2023 report found the median dwell time (time from initial breach to detection) was **16 days** for organisations with mature detection capabilities, vs months for those without. Organisations that implemented Assume Breach strategies — including host-based sensors and lateral movement detection — consistently identified attackers earlier and suffered far less damage.

### 🛡️ Defensive Measures

- Enable Credential Guard on all supported hardware
- Deploy Microsoft Defender for Endpoint (EDR) or equivalent
- Build SIEM correlation rules for multi-hop logon chains
- Implement network segmentation to limit lateral movement blast radius
- Enable Protected Users security group for privileged accounts

---

## 9. Sysmon Configuration for Endpoint Detection

### 🟢 Beginner Explanation

Sysmon (System Monitor) is a free Microsoft Sysinternals tool that runs as a system service and logs detailed information about process creations, network connections, file creation times, registry modifications, and more — far beyond what Windows native logging provides. When Sysmon events are forwarded to a SIEM, they dramatically enhance an organisation's ability to detect and investigate malicious activity.

### 🔬 Technical Deep Dive

#### Sysmon Event Types

| Event ID | Description |
|----------|-------------|
| 1 | Process creation (includes full command line and parent) |
| 2 | File creation time changed |
| 3 | Network connection |
| 4 | Sysmon service state change |
| 5 | Process terminated |
| 6 | Driver loaded |
| 7 | Image (DLL) loaded |
| 8 | CreateRemoteThread (process injection indicator) |
| 9 | RawAccessRead |
| 10 | ProcessAccess (handle to another process — LSASS access) |
| 11 | FileCreate |
| 12 | RegistryEvent — key/value create or delete |
| 13 | RegistryEvent — value set |
| 14 | RegistryEvent — key/value renamed |
| 15 | FileCreateStreamHash |
| 17 | PipeEvent — pipe created |
| 18 | PipeEvent — pipe connected |
| 19 | WmiEvent — WMI filter activity |
| 20 | WmiEvent — WMI consumer activity |
| 21 | WmiEvent — WMI consumer to filter |
| 22 | DNSEvent — DNS query |
| 23 | FileDelete |
| 25 | ProcessTampering |
| 26 | FileDeleteDetected |

#### Installing Sysmon

```powershell
# Download Sysmon from Microsoft (in lab environment, or deploy via GPO/MECM in enterprise)
# sysmon64.exe is the 64-bit version

# Install Sysmon with a configuration file
.\sysmon64.exe -accepteula -i sysmonconfig.xml

# Update configuration
.\sysmon64.exe -c sysmonconfig.xml

# Uninstall
.\sysmon64.exe -u force

# Check Sysmon status
Get-Service -Name Sysmon64
```

#### Sysmon Configuration File (Recommended Baseline)

The following is a focused, production-usable Sysmon configuration targeting the highest-value events:

```xml
<!-- sysmonconfig.xml — Defensive baseline configuration -->
<!-- Based on SwiftOnSecurity/sysmon-config (community reference) -->
<Sysmon schemaversion="4.90">

  <HashAlgorithms>sha256,imphash</HashAlgorithms>
  <CheckRevocation/>

  <EventFiltering>

    <!-- Event ID 1: Process Creation -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <!-- Exclude noisy but known-good processes -->
        <Image condition="is">C:\Windows\System32\conhost.exe</Image>
        <Image condition="is">C:\Windows\System32\wermgr.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Event ID 3: Network Connections — log unexpected outbound -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- Log PowerShell network connections -->
        <Image condition="end with">powershell.exe</Image>
        <Image condition="end with">powershell_ise.exe</Image>
        <!-- Log connections from scripting engines -->
        <Image condition="end with">wscript.exe</Image>
        <Image condition="end with">cscript.exe</Image>
        <Image condition="end with">mshta.exe</Image>
        <!-- Log connections from browsers to non-standard ports -->
        <DestinationPort condition="is">4444</DestinationPort>
        <DestinationPort condition="is">1337</DestinationPort>
        <DestinationPort condition="is">8080</DestinationPort>
      </NetworkConnect>
    </RuleGroup>

    <!-- Event ID 7: Image Loaded — detect DLL injection -->
    <RuleGroup name="" groupRelation="or">
      <ImageLoad onmatch="include">
        <!-- Log DLLs loaded without signatures -->
        <Signed condition="is">false</Signed>
      </ImageLoad>
    </RuleGroup>

    <!-- Event ID 8: CreateRemoteThread — process injection -->
    <RuleGroup name="" groupRelation="or">
      <CreateRemoteThread onmatch="exclude">
        <!-- Exclude known legitimate remote thread creation -->
        <SourceImage condition="is">C:\Windows\System32\csrss.exe</SourceImage>
      </CreateRemoteThread>
    </RuleGroup>

    <!-- Event ID 10: ProcessAccess — detect LSASS credential dumping -->
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="end with">lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>

    <!-- Event IDs 12, 13, 14: Registry monitoring for persistence -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
        <TargetObject condition="contains">CurrentVersion\RunOnce</TargetObject>
        <TargetObject condition="contains">CurrentVersion\Image File Execution Options</TargetObject>
        <TargetObject condition="contains">Winlogon\Userinit</TargetObject>
        <TargetObject condition="contains">Winlogon\Shell</TargetObject>
        <TargetObject condition="contains">\Services\</TargetObject>
        <TargetObject condition="contains">ScheduledTasks</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Event ID 22: DNS Queries — detect C2 beaconing patterns -->
    <RuleGroup name="" groupRelation="or">
      <DnsQuery onmatch="exclude">
        <!-- Exclude common legitimate queries -->
        <QueryName condition="end with">.microsoft.com</QueryName>
        <QueryName condition="end with">.windows.com</QueryName>
        <QueryName condition="end with">.windowsupdate.com</QueryName>
      </DnsQuery>
    </RuleGroup>

  </EventFiltering>
</Sysmon>
```

#### Querying Sysmon Events

Sysmon logs to `Microsoft-Windows-Sysmon/Operational`:

```powershell
# Find all Sysmon process creation events for powershell.exe
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id      = 1
} | Where-Object {$_.Message -match "powershell"} |
    Select-Object TimeCreated, Message | Format-List

# Find LSASS access events (potential credential dumping — Event 10)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id      = 10
} | Where-Object {$_.Message -match "lsass"} |
    Select-Object TimeCreated, Message | Format-List

# Find remote thread creation (Event 8 — process injection)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id      = 8
} | Select-Object TimeCreated, Message | Format-List

# Find network connections from scripting engines (Event 3)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id      = 3
} | Where-Object {$_.Message -match "wscript|cscript|mshta|powershell"} |
    Select-Object TimeCreated, Message | Format-List
```

### 🌍 Real-World Relevance

Sysmon is used by threat intelligence teams, SOCs, and IR firms worldwide as the gold-standard free endpoint telemetry source on Windows. The SwiftOnSecurity and Neo23x0 open-source Sysmon configurations are used in hundreds of organisations as their detection baseline. In many documented breach investigations, Sysmon Event ID 10 (LSASS access) was the earliest indicator of credential theft — weeks before any other detection fired.

### 🛡️ Defensive Measures

- Deploy Sysmon via GPO or endpoint management (MECM, Intune)
- Forward Sysmon logs to SIEM using Windows Event Forwarding or a log agent
- Use community-maintained configs as a baseline (SwiftOnSecurity, Olaf Hartong)
- Build SIEM detection rules around Sysmon Event IDs 1, 3, 8, 10, 13
- Monitor for Sysmon service termination — attackers sometimes kill it before acting

---

## 10. Module Practice Challenge

> **Scenario:** You are a security engineer at a mid-size company. A new Windows 10 workstation has just been provisioned with default settings. Your task is to harden it and validate your controls.

### 🏁 Challenge Tasks

**Tier 1 — Foundation**
1. Open `gpedit.msc` and enable Advanced Audit Policy for Process Creation, Logon/Logoff, and Account Management
2. Enable PowerShell Script Block Logging and Module Logging via registry or GPO
3. List all values in `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and document each entry
4. Disable the following services if present: `RemoteRegistry`, `Fax`, `XblGameSave`
5. Run `Get-LocalUser` and disable any account that has never logged in

**Tier 2 — Intermediate**
6. Install Sysmon with the configuration from Section 9
7. Generate test events by opening PowerShell and running `whoami; ipconfig; net user` — then find those events in the Sysmon log
8. Enable Windows Defender Attack Surface Reduction rules in Audit mode for the Office and credential-stealing rules
9. Configure account lockout policy: 5 attempts, 30-minute lockout
10. Check Event ID 4688 in the Security log — do you see command lines? If not, enable the GPO setting

**Tier 3 — Advanced**
11. Write a PowerShell script that queries the Security event log and summarises the top 10 source IPs by failed logon count (4625) in the last 24 hours
12. Configure registry auditing on `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and verify that a test write generates Event ID 4657
13. Research and implement SMB signing enforcement via GPO
14. Document all findings in a hardening checklist comparing pre- and post-hardening state

### ✅ Success Criteria

- Sysmon is installed and logging to `Microsoft-Windows-Sysmon/Operational`
- PowerShell script blocks are visible in Event ID 4104
- At least 5 unnecessary services are disabled
- Registry run keys are audited and generating events
- You can answer: "What processes ran in the last hour?" using Event ID 4688

---

← [Back to System Security Overview](./README.md) | [Next: Linux Hardening →](./Linux_Hardening.md)
