# N — Network Segmentation

## Beginner Explanation
Network segmentation divides a network into isolated zones so a compromise in one area cannot spread everywhere. Like watertight ship compartments — if one floods, the others stay dry.

## Technical Deep Dive

### VLAN Design
```
VLAN 10: Workstations   192.168.10.0/24
VLAN 20: Servers        192.168.20.0/24
VLAN 30: IoT / OT       192.168.30.0/24
VLAN 40: DMZ            192.168.40.0/24
VLAN 99: Management     192.168.99.0/24
```

### DMZ Architecture
```
Internet → [External FW] → DMZ (Web/Mail) → [Internal FW] → Internal Network
Rule: DMZ servers NEVER initiate connections inward
```

### iptables Inter-VLAN Rules
```bash
iptables -A FORWARD -i vlan10 -o vlan20 -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -i vlan10 -o vlan20 -d 192.168.20.50 -j DROP
iptables -A FORWARD -i vlan10 -o vlan20 -j DROP
```

### AWS Security Group Micro-Segmentation
```
Web SG  → allows inbound 443 from Internet; outbound 8080 to App SG
App SG  → allows inbound 8080 from Web SG; outbound 5432 to DB SG
DB SG   → allows inbound 5432 from App SG only
```

## Real-World Relevance
**Target (2013):** HVAC vendor credentials weren't isolated from POS systems. Proper VLAN segmentation would have prevented access to 40 million card numbers.

## Defensive Measures
1. Deny inter-VLAN traffic by default; allow only explicit flows
2. Place all internet-facing services in a DMZ
3. Monitor inter-VLAN traffic for unexpected lateral movement
4. Apply micro-segmentation to domain controllers and financial databases

## Practice Challenge
1. Configure two VLANs in GNS3 or EVE-NG and verify isolation.
2. Write three iptables rules implementing your desired inter-VLAN policy.
