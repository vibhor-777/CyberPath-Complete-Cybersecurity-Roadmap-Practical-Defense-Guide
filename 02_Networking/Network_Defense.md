# Network Defense — Firewalls, IDS/IPS, VLANs, and Segmentation

## Firewalls

### Firewall Types Comparison

| Type | Mechanism | Strengths | Limitations |
|------|-----------|-----------|-------------|
| **Packet Filter** | Inspects IP/TCP headers only | Fast, simple | Cannot inspect payloads; stateless |
| **Stateful Inspection** | Tracks TCP connection state | Blocks out-of-state packets | Limited application awareness |
| **Application/Proxy** | Inspects Layer 7 content | Deep inspection; can detect app attacks | Higher latency; resource intensive |
| **Next-Gen (NGFW)** | Combines all above + IPS + TLS inspection | Comprehensive | Expensive; complex configuration |

### iptables — Linux Firewall

```bash
# View current rules
iptables -L -n -v --line-numbers

# Default policy: Drop everything, then allow what's needed
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow established/related connections (required for stateful operation)
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback interface
iptables -A INPUT -i lo -j ACCEPT

# Allow SSH from specific management IP only
iptables -A INPUT -p tcp --dport 22 -s 192.168.1.100 -j ACCEPT

# Allow HTTPS
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "DROPPED: " --log-level 4

# Save rules (Debian/Ubuntu)
iptables-save > /etc/iptables/rules.v4
```

### Windows Firewall (PowerShell)

```powershell
# View current firewall rules
Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} | Select-Object DisplayName, Direction, Action

# Block inbound traffic on a specific port
New-NetFirewallRule -DisplayName "Block Telnet" -Direction Inbound -Protocol TCP -LocalPort 23 -Action Block

# Allow a specific application
New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow

# Enable logging for dropped packets
Set-NetFirewallProfile -All -LogBlocked True -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
```

---

## Network Segmentation

### Why Segmentation Matters

Without segmentation, a single compromised workstation can reach every other device on the network — including servers, printers, industrial control systems, and other workstations. **Network segmentation limits blast radius.**

### VLANs (Virtual Local Area Networks)

VLANs logically divide a single physical switch into multiple isolated broadcast domains.

```
Physical Network:
  Switch ─── PC-1 (Marketing)
         ─── PC-2 (Finance)
         ─── Server-1 (HR Database)

Without VLANs: All devices in the same broadcast domain
With VLANs:
  VLAN 10 (Marketing): PC-1 only
  VLAN 20 (Finance): PC-2 only
  VLAN 30 (Servers): Server-1 only
  Inter-VLAN routing controlled by firewall/router ACLs
```

**Cisco IOS VLAN Configuration:**
```
! Create VLANs
vlan 10
 name Marketing
vlan 20
 name Finance
vlan 30
 name Servers

! Assign access ports
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 10

! Configure trunk port (carries all VLANs to router)
interface GigabitEthernet0/24
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30
 switchport nonegotiate     ! Disable DTP to prevent VLAN hopping
```

### DMZ (Demilitarized Zone)

A **DMZ** is a network segment that sits between the internet-facing perimeter and the internal network. It hosts services that must be accessible from the internet (web servers, mail relays, VPN gateways) while protecting the internal network if those services are compromised.

```
Internet ──► [External Firewall] ──► DMZ (Web Server, Mail Relay, VPN)
                                         │
                                    [Internal Firewall]
                                         │
                                    Internal Network
                                    (Finance, HR, Dev)
```

**Key Rules:**
- Traffic from Internet → DMZ: Allow only necessary ports (80, 443, 25)
- Traffic from DMZ → Internal: **Block by default**; allow only specific APIs with tight controls
- Traffic from Internal → DMZ: Allow as needed
- Traffic from Internet → Internal: **Block all**

### Micro-Segmentation (Zero Trust Networks)

Traditional VLANs segment at the network boundary. **Micro-segmentation** enforces policy at the workload level — every VM, container, or server has its own firewall policy.

```
Traditional: Firewall ──► VLAN (all VMs in VLAN can talk to each other freely)

Micro-segmented: Each VM has individual policy
  VM-A (Web) → can ONLY talk to VM-B (App Server) on port 8080
  VM-B (App) → can ONLY talk to VM-C (Database) on port 5432
  VM-C (DB)  → can talk to NO other VMs; receives only from VM-B
```

Technologies: VMware NSX, AWS Security Groups, Azure NSGs, Kubernetes Network Policies.

---

## IDS/IPS — Intrusion Detection and Prevention Systems

### Detection Methodologies

| Method | How it Works | Advantage | Limitation |
|--------|-------------|-----------|------------|
| **Signature-based** | Matches traffic against database of known attack patterns | Low false positives for known threats | Cannot detect zero-days |
| **Anomaly-based** | Establishes baseline of normal traffic; alerts on deviations | Can detect unknown threats | Higher false positive rate |
| **Behavioral** | Analyzes sequences of actions rather than individual packets | Detects advanced persistent threats | Complex tuning required |

### IDS vs. IPS

| | IDS (Detection) | IPS (Prevention) |
|-|-----------------|-----------------|
| **Position** | Out-of-band (receives copy of traffic) | Inline (traffic passes through it) |
| **Response** | Alerts only; cannot block | Can drop, reset, or block connections |
| **Risk of misconfiguration** | Lower (can't break legitimate traffic) | Higher (false positive = blocked business traffic) |

### Suricata IDS Configuration Example

```yaml
# /etc/suricata/suricata.yaml (key settings)
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"

# Rule example: Detect SQL injection attempt
# /etc/suricata/rules/local.rules
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS \
    (msg:"SQL Injection Attempt - UNION SELECT"; \
     flow:to_server,established; \
     http.uri; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; within:20; \
     classtype:web-application-attack; sid:9000001; rev:1;)

# Start Suricata
suricata -c /etc/suricata/suricata.yaml -i eth0

# View alerts
tail -f /var/log/suricata/fast.log
```

---

## Vulnerability Mapping with Nmap

```bash
# ⚠️ Lab Environment Only — Only scan systems you own or have permission to test

# Basic host discovery
nmap -sn 192.168.1.0/24

# Service version detection
nmap -sV -p 1-65535 192.168.1.50

# OS detection + service versions + script scanning (comprehensive)
nmap -sV -sC -O 192.168.1.50

# Output to file for analysis
nmap -sV -oN scan_results.txt 192.168.1.50

# Map results to NVD:
# Take the service name and version (e.g., "Apache httpd 2.4.49")
# Search at: https://nvd.nist.gov/vuln/search
```

---

## Practice Challenge

**Vulnerability Mapping Task:**

1. In a lab environment with a deliberately vulnerable VM (Metasploitable or DVWA):
2. Run: `nmap -sV -oN lab_scan.txt <target_IP>`
3. Review the output and identify 3 services with version numbers
4. For each service, search the NVD (`nvd.nist.gov`) for known vulnerabilities
5. For each CVE you find, answer:
   - What is the CVSS score?
   - What type of vulnerability is it?
   - What is the remediation (patch, configuration change)?
6. Document your findings as a mini vulnerability report in your `Writeup/` folder
