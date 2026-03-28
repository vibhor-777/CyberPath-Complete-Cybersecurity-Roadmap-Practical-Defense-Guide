# R — Risk Assessment

## Beginner Explanation
A risk assessment is a structured process for identifying what can go wrong, how likely it is, and how bad it would be. You can't protect everything equally — risk assessment tells you where to spend your limited security budget first.

## Technical Deep Dive

### Risk Calculation
```
Risk = Likelihood × Impact

Qualitative:    High/Medium/Low ratings
Quantitative:   ALE = SLE × ARO
  ALE = Annualized Loss Expectancy (expected annual cost)
  SLE = Single Loss Expectancy (cost of one incident)
  ARO = Annualized Rate of Occurrence (incidents per year)

Example:
  Data breach: SLE = $2,000,000 | ARO = 0.1 (once per 10 years)
  ALE = $200,000/year
  Security control cost = $50,000/year → Justified (saves $150,000/year)
```

### Risk Assessment Process
```
1. SCOPE:    Define what systems/processes are in scope
2. IDENTIFY: List assets, threats, and vulnerabilities
3. ANALYZE:  Rate likelihood and impact for each threat/asset pair
4. EVALUATE: Prioritize risks (risk matrix: likelihood × impact)
5. TREAT:    Accept / Mitigate / Transfer / Avoid
6. MONITOR:  Track residual risk; reassess annually
```

### Risk Matrix (5×5)
```
Impact →   Negligible  Minor  Moderate  Major  Catastrophic
Likelihood
Almost Certain    M      H       H       C        C
Likely            L      M       H       H        C
Possible          L      M       M       H        H
Unlikely          L      L       M       M        H
Rare              L      L       L       M        M

C=Critical, H=High, M=Medium, L=Low
```

### Threat Modeling (STRIDE)
| Threat | Example | Mitigation |
|--------|---------|-----------|
| **S**poofing | Attacker impersonates user | Authentication + MFA |
| **T**ampering | Attacker modifies data in transit | Integrity checks (HMAC, TLS) |
| **R**epudiation | User denies performing an action | Audit logging |
| **I**nformation Disclosure | Sensitive data exposure | Encryption at rest and in transit |
| **D**enial of Service | Service made unavailable | Rate limiting, redundancy |
| **E**levation of Privilege | User gains admin access | Least privilege, input validation |

## Real-World Relevance
**Colonial Pipeline (2021):** A risk assessment would have identified: single point of failure (one VPN account without MFA), ransomware as a high-likelihood/high-impact threat, and OT network exposure as catastrophic impact. Treating that risk — even just enabling MFA — would have prevented the $4.4M ransom and 5-day fuel shortage.

## Defensive Measures
1. Conduct formal risk assessments annually and after major infrastructure changes
2. Use threat modeling (STRIDE, PASTA, MITRE ATT&CK) for new systems during design
3. Maintain a risk register with owner, treatment status, and residual risk
4. Report top risks to leadership quarterly — security must be a business conversation
5. Align risk thresholds to business risk appetite (documented in policy)

## Practice Challenge
1. Choose one system in your lab (e.g., a web application).
2. Apply STRIDE — list at least one threat per category.
3. Rate each threat's likelihood and impact (1–5).
4. Identify the highest-priority risk and describe the most cost-effective mitigation.
