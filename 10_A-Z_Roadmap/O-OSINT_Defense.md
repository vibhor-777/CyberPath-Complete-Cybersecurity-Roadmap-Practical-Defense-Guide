# O — OSINT Defense

## Beginner Explanation
OSINT (Open Source Intelligence) is publicly available information attackers use to research targets before attacking. Defenders use defensive OSINT to find their own exposure and reduce it.

## Technical Deep Dive

### Attacker OSINT Sources
| Source | Data Found | Defense |
|--------|-----------|---------|
| LinkedIn | Employee names, roles, org chart | Limit details; social engineering training |
| Shodan | Open ports, software versions | Reduce internet-facing attack surface |
| GitHub | Leaked credentials, internal configs | Secret scanning; developer training |
| HaveIBeenPwned | Breached employee emails | Forced password resets; MFA |

### Finding Your Own Exposure
```bash
# Google dorks against your domain
# site:yourcompany.com filetype:pdf confidential
# site:yourcompany.com inurl:admin
# site:yourcompany.com ext:env

# GitHub search for leaked credentials
# github.com/search?q="yourcompany.com"+password&type=code
```

### Shodan API Monitoring
```python
import shodan
api = shodan.Shodan("YOUR_API_KEY")
results = api.search("net:203.0.113.0/24")
for r in results["matches"]:
    print(f"IP: {r['ip_str']} | Port: {r['port']} | Product: {r.get('product','?')}")
```

## Real-World Relevance
**Twitter Hack (2020):** Attackers used LinkedIn to identify specific Twitter employees with internal admin tool access, then social-engineered them. Limiting public role information is a defensive OSINT control.

## Defensive Measures
1. Run quarterly OSINT scans against your own organization
2. Enable GitHub secret scanning and push protection
3. Subscribe to HaveIBeenPwned domain notifications
4. Use Shodan Monitor for alerts on newly exposed services

## Practice Challenge
1. Run Google dorks against your personal domain.
2. Check your email on HaveIBeenPwned.
3. Search Shodan for your home IP and document what's visible.
