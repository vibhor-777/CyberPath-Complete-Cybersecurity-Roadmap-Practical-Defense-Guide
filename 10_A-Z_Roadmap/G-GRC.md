# G — Governance, Risk, and Compliance (GRC)

## Beginner Explanation
GRC is the organizational framework that ensures security is not just a technical activity but a business discipline. Governance sets the rules, Risk management identifies and prioritizes threats, and Compliance ensures those rules meet legal and regulatory requirements. Without GRC, security becomes reactive and disorganized.

## Technical Deep Dive

### Governance
Governance defines the policies, procedures, and accountability structures:
- **Information Security Policy** — Top-level document defining the organization's security posture
- **Standards** — Specific mandatory requirements (e.g., "All passwords must be minimum 12 characters")
- **Procedures** — Step-by-step instructions for implementing standards
- **Guidelines** — Recommended but not mandatory practices

### Key Frameworks

#### NIST SP 800-53
The National Institute of Standards and Technology control catalog for US federal systems, widely adopted by private sector:
- Organized into 20 control families (Access Control, Audit, Incident Response, etc.)
- Each control has baseline assignments (Low/Moderate/High impact systems)
- Maps to NIST Cybersecurity Framework (Identify, Protect, Detect, Respond, Recover)

#### ISO 27001
International standard for Information Security Management Systems (ISMS):
- 114 controls across 14 domains (Annex A)
- Requires risk assessment as the foundation for control selection
- Certification involves third-party audit

#### CIS Controls v8
18 prioritized controls for cyber defense:
- Group 1 (Basic): Controls every organization must implement
- Group 2 (Foundational): Next priority for most organizations
- Group 3 (Organizational): For mature security programs

### Risk Management Process
```
1. IDENTIFY: What assets exist? What threats face them?
2. ASSESS: What is the likelihood and impact of each threat?
3. TREAT:
   - Accept (risk within tolerance)
   - Mitigate (implement controls to reduce risk)
   - Transfer (cyber insurance)
   - Avoid (stop the risky activity)
4. MONITOR: Track residual risk and control effectiveness
5. REVIEW: Repeat annually or when environment changes
```

### Risk Calculation
```
ALE = SLE × ARO
  ALE = Annualized Loss Expectancy
  SLE = Single Loss Expectancy (value of one incident)
  ARO = Annualized Rate of Occurrence (how many times per year)

Example:
  Data breach: SLE = $500,000, ARO = 0.2 (once every 5 years)
  ALE = $500,000 × 0.2 = $100,000 per year
  Security control cost: $30,000/year
  Decision: Implement the control (saves $70,000/year in expected loss)
```

## Real-World Relevance
**GDPR enforcement (2018–present):** British Airways was fined £183M (later reduced to £20M) for a data breach affecting 500,000 customers. The breach involved compromised credentials and poor access controls — issues that a mature GRC program with regular risk assessments and control reviews would have identified and remediated.

## Defensive Measures
1. Implement an ISMS aligned to ISO 27001 or NIST CSF
2. Conduct annual risk assessments with documented results
3. Assign explicit ownership to each security control
4. Track compliance status in a GRC platform (ServiceNow GRC, OneTrust, etc.)
5. Conduct management reviews of security posture at least quarterly

## Practice Challenge
1. Choose one CIS Control from Group 1 (e.g., CIS Control 1: Inventory of Enterprise Assets).
2. Assess your current compliance with each sub-control.
3. Identify gaps.
4. Write a one-page remediation plan with owner and timeline.
5. Estimate the cost of remediation vs. the risk it addresses.
