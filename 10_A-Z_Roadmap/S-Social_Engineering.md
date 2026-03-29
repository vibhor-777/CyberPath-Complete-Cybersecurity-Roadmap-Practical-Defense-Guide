# S — Social Engineering

## Beginner Explanation
Social engineering exploits human psychology rather than technical vulnerabilities. An attacker tricks a person into revealing credentials, opening a malicious file, or granting unauthorized access. No firewall blocks a person who willingly opens the door.

## Technical Deep Dive

### Social Engineering Taxonomy
| Attack Type | Method | Example |
|-------------|--------|---------|
| **Phishing** | Mass email mimicking trusted sender | Fake IT helpdesk password reset |
| **Spear Phishing** | Targeted, personalized email | Email to CFO from spoofed CEO domain |
| **Vishing** | Voice call impersonation | "I'm from IT, I need your VPN credentials" |
| **Smishing** | SMS-based lure | Fake parcel delivery link |
| **Pretexting** | Fabricated scenario to build trust | "I'm the auditor, I need system access" |
| **Baiting** | Leaving infected USB in target area | USB labeled "Salary_Q4_2024.xlsx" |
| **Quid Pro Quo** | Offering help in exchange for access | "I'll fix your computer — just give me your password" |

### Phishing Email Indicators
```
Red Flags:
  ✗ Sender domain mismatch: From: it-helpdesk@c0mpany.com (zero, not 'o')
  ✗ Generic greeting: "Dear Valued User"
  ✗ Urgent pressure: "Your account will be suspended in 24 hours"
  ✗ Mismatched URLs: hover shows different domain than displayed text
  ✗ Unexpected attachment from known contact
  ✗ SPF/DKIM/DMARC failures (check email headers)

Verify:
  ✓ Check full sender email address — not just display name
  ✓ Call the sender via a known, separate channel to verify
  ✓ Never enter credentials via a link in email — navigate directly
```

### Email Authentication Headers Analysis
```
Received-SPF: fail (IP not authorized to send for domain)
Authentication-Results: dkim=fail; dmarc=fail action=reject

These indicate spoofed sender — DMARC policy should have rejected this
```

### Security Awareness Training — Key Topics
1. How to identify phishing emails (inspect sender, hover links, check urgency)
2. Verification procedures before granting access or sharing information
3. Proper password hygiene and MFA usage
4. Physical security — tailgating, clean desk policy
5. Reporting procedures — how to report suspicious contact without fear of embarrassment

### Simulated Phishing Programs
```
Tools: GoPhish (open source), KnowBe4, Proofpoint Security Awareness
Process:
  1. Send simulated phishing campaign to employees
  2. Track click rate, credential entry rate, report rate
  3. Immediately enroll clickers in targeted training
  4. Measure improvement quarter-over-quarter
  Target: <5% click rate, >80% report rate
```

## Real-World Relevance
**Twitter (2020):** Attackers called Twitter employees via phone (vishing), impersonating IT staff, and tricked them into providing access to internal tools. 130 high-profile accounts were compromised. No technical control was broken — only human trust.

## Defensive Measures
1. Run quarterly simulated phishing campaigns with immediate training for clickers
2. Implement DMARC (p=reject) to prevent email spoofing of your domain
3. Establish a verification procedure for any out-of-band credential request
4. Train employees to report suspicious contact without embarrassment
5. Apply MFA everywhere — even if credentials are phished, MFA limits the damage

## Practice Challenge
1. Set up GoPhish in a lab and send a test phishing campaign to yourself.
2. Analyze the email headers and identify SPF, DKIM, and DMARC results.
3. Write a 1-page "Phishing Identification Quick Guide" for non-technical staff.
4. Identify your organization's current DMARC policy: `dig TXT _dmarc.yourcompany.com`
