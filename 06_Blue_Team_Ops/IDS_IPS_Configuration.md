# IDS/IPS Configuration — Intrusion Detection and Prevention Systems

## Beginner Explanation

An **Intrusion Detection System (IDS)** is like a security camera with a motion alarm: it watches network traffic and alerts you when something suspicious happens, but it doesn't stop it. An **Intrusion Prevention System (IPS)** is more like a security guard: it sits in the path of traffic and can actively block threats in real time.

Choosing where to place these systems, how to write rules, and how to tune them to reduce false alarms is a core Blue Team skill.

---

## Snort vs. Suricata

| Feature | Snort 3 | Suricata |
|---------|---------|---------|
| **Threading** | Single-threaded (legacy), multi-threaded in v3 | Multi-threaded natively |
| **Performance** | Good for small networks | Excellent for high-throughput |
| **Protocol support** | TCP/UDP/ICMP + application decoders | Full application-layer inspection (HTTP, DNS, TLS, SMB, etc.) |
| **Rule format** | Snort rules | Snort-compatible + Suricata extensions |
| **File extraction** | Via preprocessors | Built-in file extraction and hashing |
| **TLS/JA3** | Limited | Full TLS metadata and JA3 fingerprinting |
| **Output** | Unified2, syslog | EVE JSON (ideal for ELK/Splunk integration) |
| **Community** | Large, mature | Rapidly growing; OISF-backed |

**Recommendation:** For new deployments, **Suricata** is generally preferred due to multi-threading, richer protocol support, and excellent JSON logging.

---

## Suricata — Installation and Configuration

### Installation

```bash
# Ubuntu/Debian
sudo apt-get install -y suricata

# Verify version
suricata --build-info | head -5

# Update rules (using suricata-update)
sudo suricata-update
sudo suricata-update list-sources
sudo suricata-update enable-source et/open   # Emerging Threats Open rules (free)
sudo suricata-update update-sources
sudo suricata-update
```

### Key Configuration — /etc/suricata/suricata.yaml

```yaml
# Network variables — define your internal network
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    HTTPS_PORTS: "443"
    SHELLCODE_PORTS: "!80"
    SSH_PORTS: "22"

# Logging — EVE JSON for SIEM integration
outputs:
  - eve-log:
      enabled: yes
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-printable: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: yes
        - smtp:
        - flow

# Interface detection (IDS mode - copy of traffic)
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

# For IPS mode (inline), use NFQ or AF_PACKET with copy-mode:
# af-packet:
#   - interface: eth0
#     copy-mode: ips
#     copy-iface: eth1
```

### Running Suricata

```bash
# IDS mode (read-only, monitoring)
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Run as service
sudo systemctl enable suricata
sudo systemctl start suricata

# Monitor alerts in real time
sudo tail -f /var/log/suricata/fast.log

# Query EVE JSON for HTTP alerts
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert") | {timestamp, src_ip, dest_ip, alert}'
```

---

## Writing Suricata Rules

### Rule Anatomy

```
action  proto  src_ip  src_port  direction  dest_ip  dest_port  (options)
  │       │       │        │         │         │         │
alert   http  $EXTERNAL_NET  any  ->  $HTTP_SERVERS  $HTTP_PORTS  (msg:"..."; sid:1000001; rev:1;)
```

**Actions:**
- `alert` — Generate an alert (IDS mode)
- `drop` — Drop the packet and alert (IPS mode only)
- `reject` — Drop + send TCP RST / ICMP unreachable
- `pass` — Whitelist (no alert, no drop)

### Rule Options Reference

| Option | Purpose | Example |
|--------|---------|---------|
| `msg` | Alert message | `msg:"SQL Injection Attempt";` |
| `flow` | Connection direction | `flow:to_server,established;` |
| `content` | Byte pattern match | `content:"UNION SELECT"; nocase;` |
| `http.uri` | Match on HTTP URI | `http.uri; content:"/etc/passwd";` |
| `http.header` | Match on HTTP header | `http.header; content:"cmd.exe";` |
| `pcre` | Perl-compatible regex | `pcre:"/select.+from/i";` |
| `threshold` | Rate limiting | `threshold:type limit,track by_src,count 5,seconds 60;` |
| `classtype` | Alert category | `classtype:web-application-attack;` |
| `sid` | Unique rule ID | `sid:9000001;` |
| `rev` | Rule revision | `rev:1;` |
| `metadata` | Extra info | `metadata:created_at 2024_01_01;` |

### Example Rules

```
# SQL Injection — UNION SELECT
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS \
    (msg:"DETECT SQL Injection UNION SELECT"; \
     flow:to_server,established; \
     http.uri; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; within:30; \
     classtype:web-application-attack; sid:9000001; rev:1;)

# XSS Attempt — <script> in URI
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS \
    (msg:"DETECT XSS Script Tag in URI"; \
     flow:to_server,established; \
     http.uri; content:"<script"; nocase; \
     classtype:web-application-attack; sid:9000002; rev:1;)

# Directory Traversal
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS \
    (msg:"DETECT Path Traversal Attempt"; \
     flow:to_server,established; \
     http.uri; pcre:"/(\.\.[\/\\\\]){2,}/"; \
     classtype:web-application-attack; sid:9000003; rev:1;)

# Outbound Reverse Shell — PowerShell download cradle
alert http $HOME_NET any -> $EXTERNAL_NET any \
    (msg:"DETECT Suspicious PowerShell Download Cradle"; \
     flow:to_server,established; \
     http.user_agent; content:"PowerShell"; nocase; \
     classtype:trojan-activity; sid:9000004; rev:1;)

# Port Scan Detection — SYN to many ports
alert tcp $EXTERNAL_NET any -> $HOME_NET any \
    (msg:"DETECT Horizontal Port Scan"; \
     flags:S; \
     threshold:type threshold,track by_src,count 20,seconds 10; \
     classtype:network-scan; sid:9000005; rev:1;)

# Rogue DHCP Offer (place on internal monitoring interface)
alert udp any 67 -> any 68 \
    (msg:"DETECT Rogue DHCP Offer from Unauthorized Server"; \
     content:"|02|"; offset:0; depth:1; \
     threshold:type limit,track by_src,count 1,seconds 60; \
     classtype:bad-unknown; sid:9000006; rev:1;)

# DNS Tunneling — Unusually long DNS query
alert dns $HOME_NET any -> any 53 \
    (msg:"DETECT Possible DNS Tunneling - Long Query"; \
     dns.query; pcre:"/^.{50,}\./"; \
     classtype:bad-unknown; sid:9000007; rev:1;)

# Mimikatz via HTTP User-Agent
alert http $HOME_NET any -> $EXTERNAL_NET any \
    (msg:"DETECT Mimikatz User-Agent"; \
     flow:to_server,established; \
     http.user_agent; content:"NirCmd"; nocase; \
     classtype:trojan-activity; sid:9000008; rev:1;)
```

---

## Tuning Rules — Reducing False Positives

False positives are the #1 enemy of an effective IDS deployment. A noisy IDS gets ignored.

### Tuning Strategy

```bash
# Step 1: Run in alert-only mode for 1 week; collect all alerts
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert") | .alert.signature' | sort | uniq -c | sort -rn | head -20

# Step 2: Identify high-volume, low-fidelity rules
# Step 3: For each noisy rule, decide:
#   a) Suppress for specific trusted IPs
#   b) Increase threshold
#   c) Add exception for legitimate traffic patterns
#   d) Disable entirely if irrelevant to your environment
```

### Suppression and Thresholding

```yaml
# /etc/suricata/threshold.conf

# Suppress alerts from a trusted scanner IP
suppress gen_id 1, sig_id 9000005, track by_src, ip 192.168.1.200

# Limit alert rate — alert at most once per minute per source IP
threshold gen_id 1, sig_id 9000001, type limit, track by_src, count 1, seconds 60

# Only alert after 10 occurrences within 30 seconds
threshold gen_id 1, sig_id 9000005, type threshold, track by_src, count 10, seconds 30
```

### Rule Management with suricata-update

```bash
# Disable a noisy rule by SID
echo "9000005" | sudo tee -a /etc/suricata/disable.conf

# Modify a rule (override)
# /etc/suricata/modify.conf
# "9000001" "alert" "drop"   # Escalate from alert to drop for this rule

# Re-apply rules after changes
sudo suricata-update
sudo systemctl reload suricata
```

---

## IDS/IPS Positioning

### Network TAP vs SPAN Port

| Method | How it Works | Advantage | Limitation |
|--------|-------------|-----------|------------|
| **Network TAP** | Physical device inserted inline; passes copy of all traffic to IDS | Passive; won't affect traffic; captures all frames including errors | Cost; physical installation required |
| **SPAN/Mirror Port** | Switch mirrors traffic from monitored port to IDS port | No additional hardware; easy to configure | Can drop packets under high load; adds switch CPU overhead |

```
Network TAP deployment:
  Internet ──► [Firewall] ──► [TAP] ──► [Switch] ──► Internal Network
                                │
                                └──► [Suricata IDS]

SPAN Port deployment:
  Switch ──► Port 1 (production)
         ──► Port 2 (SPAN mirror) ──► [Suricata IDS]
```

---

## Zeek (Bro) — Network Security Monitoring

Zeek is not a signature-based IDS — it creates **structured logs** of all network activity, providing rich context for threat hunting and incident response.

```bash
# Install Zeek
sudo apt-get install zeek

# Configure interface
# /etc/zeek/node.cfg
[zeek]
type=standalone
host=localhost
interface=eth0

# Start Zeek
sudo zeekctl deploy

# Key log files generated by Zeek
ls /opt/zeek/logs/current/
# conn.log     — all TCP/UDP/ICMP connections (src, dst, duration, bytes)
# http.log     — all HTTP requests (method, URI, user-agent, response code)
# dns.log      — all DNS queries and answers
# ssl.log      — TLS sessions (JA3 fingerprints, certificates, version)
# files.log    — extracted file metadata (hash, MIME type)
# weird.log    — protocol anomalies

# Example: Find all connections to unusual ports
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration | awk '$4=="tcp" && $3 > 1024' | sort -k3 -n | tail -20
```

---

## SIEM Integration

```bash
# Filebeat configuration to ship Suricata EVE JSON to Elasticsearch
# /etc/filebeat/filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/suricata/eve.json
    json.keys_under_root: true
    json.add_error_key: true
    json.message_key: log

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "suricata-%{+yyyy.MM.dd}"

# Kibana: Import Suricata dashboards from the Elastic integrations catalog
# Provides: alert volume, top signatures, top source IPs, geographic mapping
```

---

## Real-World Relevance

In the **2021 Microsoft Exchange ProxyLogon attacks**, threat actors exploited CVE-2021-26855 (SSRF) and CVE-2021-27065 (post-auth file write) to deploy webshells on thousands of on-premises Exchange servers. Organizations with properly configured IDS/IPS running Emerging Threats rules received alerts on the exploitation HTTP requests hours before patches were available, enabling early containment. Those without IDS were often unaware until ransomware deployed weeks later.

---

## Defensive Measures

1. **Deploy Suricata in IDS mode first** — Collect and tune for 2–4 weeks before enabling IPS/drop mode
2. **Subscribe to Emerging Threats Open ruleset** — Free, community-maintained, highly effective
3. **Enable EVE JSON logging** and ship to your SIEM for correlation
4. **Write custom rules** for your specific environment (internal applications, unusual protocols)
5. **Review fast.log daily** and track alert trends week-over-week

---

## Practice Challenge

**Detection Engineering Task:**

1. Set up Suricata in IDS mode on a lab VM monitoring traffic from a DVWA (Damn Vulnerable Web Application) instance.
2. From a separate VM, perform a SQL injection attempt against DVWA (e.g., `?id=1' UNION SELECT 1,2,3--`).
3. Verify the alert appears in `/var/log/suricata/fast.log`.
4. Parse the EVE JSON to extract: timestamp, source IP, destination IP, alert signature.
5. Write a **custom Suricata rule** that catches a path traversal attempt (`../../etc/passwd`).
6. Test your rule and document the result in your `Writeup/` folder.
