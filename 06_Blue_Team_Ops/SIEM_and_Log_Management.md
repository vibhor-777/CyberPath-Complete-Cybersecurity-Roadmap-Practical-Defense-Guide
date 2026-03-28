# SIEM and Log Management

> **Back to:** [Blue Team Ops](./README.md) | [Main Roadmap](../README.md)

---

## Table of Contents

1. [What is a SIEM?](#1-what-is-a-siem)
2. [ELK Stack Deployment](#2-elk-stack-deployment)
3. [Wazuh HIDS/SIEM](#3-wazuh-hidssiem)
4. [Key Log Sources](#4-key-log-sources)
5. [Critical Windows Event IDs](#5-critical-windows-event-ids)
6. [Log Retention and SIEM Sizing](#6-log-retention-and-siem-sizing)
7. [Writing Correlation Rules](#7-writing-correlation-rules)
8. [Log Forwarding with Beats](#8-log-forwarding-with-beats)
9. [Splunk SPL Query Examples](#9-splunk-spl-query-examples)
10. [Practice Challenge](#10-practice-challenge)

---

## 1. What is a SIEM?

### Beginner Explanation

A **Security Information and Event Management (SIEM)** system is like a security camera DVR for your entire IT environment. Every device — servers, workstations, firewalls, applications — generates logs. A SIEM collects all those logs in one place, normalizes them into a common format, and then looks for patterns that indicate something suspicious is happening. When it finds a match, it raises an alert for the security team to investigate.

### Technical Deep Dive

A SIEM provides four core functions:

| Function | Description |
|----------|-------------|
| **Collection** | Ingests logs via syslog, Beats agents, API, or direct database queries |
| **Normalization** | Parses raw log strings into structured fields (IP, user, timestamp, action) |
| **Correlation** | Applies rules across multiple events to detect multi-step attacks |
| **Alerting** | Generates tickets, emails, or webhook notifications when rules fire |

**Event Correlation Example:**

A single failed login (`EventID 4625`) is noise. But 50 failed logins from the same source IP within 60 seconds, followed by a successful login (`EventID 4624`), is a brute-force attack followed by account compromise — a correlation rule catches that pattern.

```
Rule: Brute Force then Success
  IF count(EventID=4625, src_ip=X) > 50 within 60s
  AND EventID=4624 with src_ip=X within 300s
  THEN alert("Brute Force Success - " + X)
```

**Normalization** converts vendor-specific log formats into a common schema. For example, both a Cisco firewall and a Windows host log "denied connection" events, but in completely different formats. The SIEM parser maps both to fields like `src_ip`, `dst_ip`, `action=deny`.

### Real-World Relevance

The 2020 SolarWinds breach went undetected for months partly because defenders lacked centralized log visibility. A well-tuned SIEM with proper log sources would have detected the anomalous SAML token usage that characterized the attack.

### Defensive Measures

- Ensure **all** critical assets are sending logs to the SIEM — gaps in coverage are blind spots
- Define a **use-case library** of what threats you're trying to detect before writing rules
- Implement **alert fatigue management**: tune high-volume, low-fidelity rules aggressively
- Assign **severity tiers** (Critical/High/Medium/Low) and SLA response times per tier

---

## 2. ELK Stack Deployment

### Beginner Explanation

The **ELK Stack** (Elasticsearch, Logstash, Kibana) is a free, open-source SIEM platform. Elasticsearch stores and searches logs at scale. Logstash processes and parses incoming log data. Kibana provides the web dashboard for visualizing and querying data. Together, they form a powerful, self-hosted SIEM.

### Technical Deep Dive

**Architecture:**

```
[Endpoints]
  Winlogbeat / Filebeat
        │
        ▼
[Logstash :5044]  ←── parse, filter, enrich
        │
        ▼
[Elasticsearch :9200]  ←── store, index, search
        │
        ▼
[Kibana :5601]  ←── dashboards, alerts, SIEM UI
```

**Logstash Pipeline Configuration (`/etc/logstash/conf.d/windows.conf`):**

```ruby
input {
  beats {
    port => 5044
  }
}

filter {
  if [event][module] == "winlogbeat" {
    mutate {
      add_field => { "log_source" => "windows" }
    }
    if [event][code] == "4625" {
      mutate {
        add_tag => ["failed_login"]
      }
    }
  }
  geoip {
    source => "[source][ip]"
    target => "geoip"
  }
}

output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "winlogbeat-%{+YYYY.MM.dd}"
  }
}
```

**Elasticsearch Index Template** — defines field mappings for efficient querying:

```json
{
  "index_patterns": ["winlogbeat-*"],
  "mappings": {
    "properties": {
      "event.code":    { "type": "keyword" },
      "source.ip":     { "type": "ip" },
      "user.name":     { "type": "keyword" },
      "@timestamp":    { "type": "date" }
    }
  }
}
```

**Kibana Detection Rules** — use the Security → Rules interface to create threshold-based or custom query rules:

```
# KQL query for brute force detection
event.code: "4625" AND winlog.logon.type: "Network"
```

### Defensive Measures

- Run Elasticsearch with **X-Pack Security** enabled — unauthenticated Elasticsearch clusters have caused major data breaches
- Use **ILM (Index Lifecycle Management)** to automatically move old indices to warm/cold storage
- Enable **TLS** on all Beats-to-Logstash and Logstash-to-Elasticsearch communications
- Restrict Kibana access behind a VPN or SSO provider

---

## 3. Wazuh HIDS/SIEM

### Beginner Explanation

**Wazuh** is a free, open-source security platform that acts as both a Host Intrusion Detection System (HIDS) and a SIEM. Agents installed on endpoints monitor file integrity, detect rootkits, check for vulnerabilities, and forward logs to a central Wazuh manager — which correlates events and raises alerts.

### Technical Deep Dive

**Wazuh Architecture:**

```
[Wazuh Agent]  ──► [Wazuh Manager :1514/1515]  ──► [Elasticsearch]  ──► [Kibana/Wazuh UI]
```

**Wazuh Rule Anatomy (`/var/ossec/rules/local_rules.xml`):**

```xml
<!-- Rule: Detect multiple failed SSH logins -->
<group name="sshd,authentication_failed">

  <rule id="100001" level="10" frequency="5" timeframe="120">
    <if_matched_sid>5716</if_matched_sid>
    <description>SSH brute force attempt (5 failures in 2 min)</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failures,pci_dss_10.2.4,</group>
  </rule>

</group>
```

**Rule Fields:**

| Field | Purpose |
|-------|---------|
| `id` | Unique rule identifier (local rules: 100000–109999) |
| `level` | Alert severity 0–15 (0=ignore, 15=critical) |
| `frequency` | Number of times parent rule must fire |
| `timeframe` | Time window in seconds |
| `if_matched_sid` | Parent rule that must fire first |
| `mitre` | ATT&CK technique mapping |

**File Integrity Monitoring (FIM) Configuration (`ossec.conf`):**

```xml
<syscheck>
  <frequency>3600</frequency>
  <directories check_all="yes" report_changes="yes" realtime="yes">
    /etc,/usr/bin,/usr/sbin
  </directories>
  <directories check_all="yes" report_changes="yes" realtime="yes">
    C:\Windows\System32
  </directories>
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/resolv.conf</ignore>
</syscheck>
```

### Defensive Measures

- Enable **active response** to automatically block IPs exceeding brute-force thresholds
- Use Wazuh's **SCA (Security Configuration Assessment)** module to continuously check CIS benchmark compliance
- Integrate Wazuh with **VirusTotal** to automatically scan new/modified files

---

## 4. Key Log Sources

### Windows Event Logs

| Log Channel | Location | Key Contents |
|-------------|----------|-------------|
| Security | `%SystemRoot%\System32\winevt\Logs\Security.evtx` | Logon/logoff, privilege use, account management |
| System | `winevt\Logs\System.evtx` | Service installs, driver loads, crashes |
| Application | `winevt\Logs\Application.evtx` | Application errors and events |
| Sysmon | `winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx` | Process creation, network connections, file hash |
| PowerShell | `winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx` | Script block logging |

### Linux syslog / auditd

```bash
# Key log files on Linux
/var/log/auth.log        # Authentication events (Ubuntu/Debian)
/var/log/secure          # Authentication events (RHEL/CentOS)
/var/log/syslog          # General system messages
/var/log/audit/audit.log # auditd events (syscall-level)

# Enable auditd rules for privilege escalation monitoring
auditctl -w /etc/sudoers -p wa -k sudoers_change
auditctl -w /usr/bin/sudo -p x -k sudo_exec
auditctl -a always,exit -F arch=b64 -S execve -k exec_log
```

### Firewall Logs

Firewall logs capture allowed and denied network connections. Key fields to parse:

```
# Palo Alto Networks log format (simplified)
2024-01-15 14:23:11 TRAFFIC allow src=192.168.1.100 dst=8.8.8.8 sport=54321 dport=443 proto=tcp bytes=1452

# iptables log format
Jan 15 14:23:11 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=10.0.0.5 PROTO=TCP DPT=22
```

### Web Server Logs

```
# Apache Combined Log Format
203.0.113.50 - admin [15/Jan/2024:14:23:11 +0000] "POST /wp-login.php HTTP/1.1" 200 4523 "-" "sqlmap/1.7"

# nginx access log
203.0.113.50 - - [15/Jan/2024:14:23:11 +0000] "GET /etc/passwd HTTP/1.1" 404 152 "-" "curl/7.68.0"
```

Detection opportunities in web logs:
- **Status 200 on admin paths** from unexpected IPs
- **SQLmap/scanner user-agents** in the User-Agent field
- **Path traversal patterns** (`../`, `%2e%2e%2f`) in the URI

---

## 5. Critical Windows Event IDs

### The Essential Monitoring List

| Event ID | Category | Description | Why It Matters |
|----------|----------|-------------|----------------|
| **4624** | Logon | Successful account logon | Baseline normal activity; anomalies indicate compromise |
| **4625** | Logon | Failed account logon | Brute force detection |
| **4648** | Logon | Logon using explicit credentials | Pass-the-hash / credential theft indicator |
| **4688** | Process | New process created | Command execution tracking (requires audit policy) |
| **4698** | Task Scheduler | Scheduled task created | Persistence mechanism |
| **4702** | Task Scheduler | Scheduled task modified | Persistence modification |
| **4720** | Account Mgmt | User account created | Unauthorized account creation |
| **4732** | Account Mgmt | Member added to security-enabled local group | Privilege escalation |
| **4776** | Credential | NTLM authentication attempt | Lateral movement / Pass-the-Hash |
| **1102** | Audit Log | Security audit log cleared | Anti-forensics / covering tracks |
| **7045** | System | New service installed | Persistence / malware installation |

### Enabling Enhanced Logging

By default, Windows does not log process creation (4688) with command-line arguments. Enable it via Group Policy:

```
Computer Configuration →
  Windows Settings →
    Security Settings →
      Advanced Audit Policy Configuration →
        Detailed Tracking →
          Audit Process Creation → Enable (Success)

# Also enable command-line in process creation events:
Computer Configuration →
  Administrative Templates →
    System →
      Audit Process Creation →
        Include command line in process creation events → Enabled
```

**Also deploy Sysmon** for far richer process telemetry:

```xml
<!-- Sysmon config snippet - log all process creation -->
<RuleGroup name="" groupRelation="or">
  <ProcessCreate onmatch="exclude">
    <!-- Exclude noisy but known-good processes -->
    <Image condition="is">C:\Windows\System32\svchost.exe</Image>
  </ProcessCreate>
</RuleGroup>
```

---

## 6. Log Retention and SIEM Sizing

### Retention Policy Framework

| Log Type | Recommended Retention | Regulatory Driver |
|----------|-----------------------|-------------------|
| Security events | 12 months online, 7 years archive | PCI DSS, HIPAA |
| Firewall/NetFlow | 90 days online, 1 year archive | SOC 2 |
| Web server logs | 180 days online | GDPR (breach evidence) |
| Authentication logs | 12 months online | Most frameworks |
| DNS query logs | 90 days | SOC investigations |

### SIEM Storage Sizing Formula

```
Daily Storage = (Events per Second) × 86400 × (Average Event Size in bytes)

Example:
  500 EPS × 86,400 seconds × 500 bytes = ~21.6 GB/day

Monthly:  21.6 GB × 30 = ~648 GB
Annually: 21.6 GB × 365 = ~7.9 TB (before compression)

ELK compression ratio typically 3:1 to 5:1
Compressed annual: ~1.6–2.6 TB
```

**EPS Estimation by Environment Size:**

| Environment | Approximate EPS |
|-------------|----------------|
| Small (< 100 endpoints) | 100–500 EPS |
| Medium (100–500 endpoints) | 500–2,000 EPS |
| Large (500–2,000 endpoints) | 2,000–10,000 EPS |
| Enterprise (2,000+) | 10,000+ EPS |

---

## 7. Writing Correlation Rules

### Rule Logic Examples

**Brute Force Detection (Elasticsearch Watcher):**

```json
{
  "trigger": { "schedule": { "interval": "5m" } },
  "input": {
    "search": {
      "request": {
        "indices": ["winlogbeat-*"],
        "body": {
          "query": {
            "bool": {
              "filter": [
                { "term": { "event.code": "4625" } },
                { "range": { "@timestamp": { "gte": "now-5m" } } }
              ]
            }
          },
          "aggs": {
            "by_source": {
              "terms": { "field": "source.ip", "min_doc_count": 20 }
            }
          }
        }
      }
    }
  },
  "condition": {
    "compare": { "ctx.payload.aggregations.by_source.buckets": { "not_eq": [] } }
  },
  "actions": {
    "send_alert": {
      "webhook": {
        "method": "POST",
        "url": "https://siem.internal/api/alerts",
        "body": "Brute force detected from {{ctx.payload.aggregations.by_source.buckets.0.key}}"
      }
    }
  }
}
```

**Impossible Travel Detection (Pseudocode):**

```python
# Detect a user logging in from two geographically distant IPs
# within a time window too short to travel

for user in get_users_with_multiple_logins(window="1h"):
    logins = get_logins(user, window="1h")
    for i in range(len(logins) - 1):
        distance_km = geo_distance(logins[i].ip, logins[i+1].ip)
        time_hours  = (logins[i+1].timestamp - logins[i].timestamp).hours
        speed_kmh   = distance_km / max(time_hours, 0.001)
        if speed_kmh > 900:  # faster than commercial aircraft
            alert(f"Impossible travel for {user}: {logins[i].ip} → {logins[i+1].ip}")
```

**PowerShell Encoded Command Detection (KQL):**

```
event.code: "4688" AND
process.command_line: (*-enc* OR *-EncodedCommand* OR *-e * OR *-en *)
AND process.name: "powershell.exe"
```

---

## 8. Log Forwarding with Beats

### Winlogbeat Configuration (`winlogbeat.yml`)

```yaml
winlogbeat.event_logs:
  - name: Security
    event_id: 4624, 4625, 4648, 4688, 4698, 4702, 4720, 4732, 4776, 1102, 7045
    level: critical, error, warning, information

  - name: Microsoft-Windows-Sysmon/Operational

  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4103, 4104  # Script block logging

output.logstash:
  hosts: ["siem.internal:5044"]
  ssl.certificate_authorities: ["/etc/pki/ca.crt"]
  ssl.certificate: "/etc/pki/client.crt"
  ssl.key: "/etc/pki/client.key"

processors:
  - add_host_metadata: ~
  - add_cloud_metadata: ~
```

### Filebeat Configuration for Linux Syslog

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/auth.log
      - /var/log/syslog
    fields:
      log_type: linux_syslog
    multiline.pattern: '^\w{3}\s+\d{1,2}'
    multiline.negate: true
    multiline.match: after

  - type: log
    enabled: true
    paths:
      - /var/log/audit/audit.log
    fields:
      log_type: auditd

filebeat.modules:
  - module: system
    syslog: { enabled: true }
    auth:   { enabled: true }

output.elasticsearch:
  hosts: ["https://elasticsearch.internal:9200"]
  username: "filebeat_writer"
  password: "${FILEBEAT_PASSWORD}"
  ssl.certificate_authorities: ["/etc/pki/ca.crt"]
```

---

## 9. Splunk SPL Query Examples

### Common Detection Queries

**Failed Login Spike:**

```spl
index=windows EventCode=4625
| bucket _time span=5m
| stats count by _time, src_ip, user
| where count > 20
| sort -count
| table _time, src_ip, user, count
```

**New Local Admin Account Created:**

```spl
index=windows (EventCode=4720 OR EventCode=4732)
| eval action=case(EventCode==4720,"Account Created", EventCode==4732,"Added to Group")
| where Group_Name="Administrators" OR EventCode==4720
| stats count by _time, action, user, Account_Name, ComputerName
| sort -_time
```

**PowerShell Encoded Commands:**

```spl
index=windows EventCode=4688 process_name="powershell.exe"
| regex CommandLine="(?i)(-e\s|-en\s|-enc\s|-EncodedCommand\s)"
| eval decoded=urldecode(CommandLine)
| table _time, ComputerName, SubjectUserName, CommandLine
| sort -_time
```

**Lateral Movement — PsExec Detection:**

```spl
index=windows EventCode=7045
| where Service_Name="PSEXESVC" OR match(Service_File_Name, "(?i)psexe")
| stats count by _time, ComputerName, Service_Name, Service_File_Name
```

**Log Cleared (Anti-Forensics):**

```spl
index=windows EventCode=1102
| stats count by _time, ComputerName, SubjectUserName
| sort -_time
```

**Baseline Deviation — Unusual Process Parent:**

```spl
index=windows EventCode=4688
| stats count by ParentProcessName, ProcessName
| eventstats avg(count) as avg_count, stdev(count) as stdev_count by ParentProcessName
| eval z_score=(count - avg_count) / stdev_count
| where z_score > 3
| table ParentProcessName, ProcessName, count, z_score
| sort -z_score
```

---

## 10. Practice Challenge

### Challenge: Build a Brute Force Detection Pipeline

**Objective:** Configure a working log pipeline that detects and alerts on SSH brute force attacks against a Linux host.

**Environment Setup:**

```bash
# On Ubuntu SIEM host — install ELK
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update && sudo apt install elasticsearch logstash kibana filebeat -y

# Start services
sudo systemctl enable --now elasticsearch kibana logstash
```

**Tasks:**

1. **Configure Filebeat** on a Linux target to forward `/var/log/auth.log` to your Elasticsearch instance
2. **Create a Kibana Detection Rule** that fires when more than 10 EventID equivalent SSH failures occur within 2 minutes from the same source IP
3. **Simulate the attack** using `hydra` from a separate VM against the target's SSH service:
   ```bash
   hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://TARGET_IP -t 4
   ```
4. **Verify the alert fires** in Kibana and includes the attacker's IP address
5. **Bonus:** Configure an active response in Wazuh to automatically add the attacker IP to `/etc/hosts.deny`

**Success Criteria:**
- Alert fires within 60 seconds of the attack starting
- Alert contains: attacker IP, target host, failure count, timestamp
- Alert severity is set to "High"

---

*Next: [Threat Hunting](./Threat_Hunting.md)*
