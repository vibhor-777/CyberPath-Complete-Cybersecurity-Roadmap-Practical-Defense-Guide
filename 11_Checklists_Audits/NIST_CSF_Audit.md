# NIST Cybersecurity Framework (CSF) Audit Template

The NIST Cybersecurity Framework organizes security controls into five core functions: **Identify, Protect, Detect, Respond, Recover**. Use this template for self-assessment and as the basis for board-level security posture reporting.

## Scoring Guide
| Score | Meaning |
|-------|---------|
| 0 | Not implemented |
| 1 | Partially implemented — significant gaps |
| 2 | Mostly implemented — minor gaps |
| 3 | Fully implemented and verified |
| N/A | Not applicable to this environment |

---

## Function 1: IDENTIFY (ID)
*Understand the business context, assets, and risks.*

### ID.AM — Asset Management
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| ID.AM-1 | Physical devices and systems are inventoried | | |
| ID.AM-2 | Software and applications are inventoried | | |
| ID.AM-3 | Organizational communication and data flows are mapped | | |
| ID.AM-5 | Resources are prioritized based on classification, criticality, and business value | | |
| ID.AM-6 | Cybersecurity roles and responsibilities are established | | |

### ID.BE — Business Environment
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| ID.BE-5 | Resilience requirements are established | | |

### ID.GV — Governance
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| ID.GV-1 | Organizational cybersecurity policy is established | | |
| ID.GV-2 | Information security roles and responsibilities are coordinated | | |
| ID.GV-4 | Governance and risk management processes address cybersecurity risks | | |

### ID.RA — Risk Assessment
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| ID.RA-1 | Asset vulnerabilities are identified and documented | | |
| ID.RA-3 | Threats are identified and documented | | |
| ID.RA-5 | Threats, vulnerabilities, likelihoods, and impacts are used to determine risk | | |
| ID.RA-6 | Risk responses are identified and prioritized | | |

### ID.SC — Supply Chain Risk Management
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| ID.SC-1 | Supply chain risk management processes are identified and established | | |
| ID.SC-3 | Contracts with suppliers include cybersecurity requirements | | |

**IDENTIFY Sub-total: ___ / 42**

---

## Function 2: PROTECT (PR)
*Implement safeguards to ensure delivery of critical services.*

### PR.AC — Identity Management and Access Control
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| PR.AC-1 | Identities and credentials are issued and managed | | |
| PR.AC-2 | Physical access is managed | | |
| PR.AC-3 | Remote access is managed | | |
| PR.AC-4 | Access permissions are managed, incorporating PoLP | | |
| PR.AC-5 | Network integrity is protected (network segmentation) | | |
| PR.AC-6 | Identities are proofed and bound to credentials | | |
| PR.AC-7 | Users, devices, and assets are authenticated | | |

### PR.AT — Awareness and Training
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| PR.AT-1 | All users are informed and trained | | |
| PR.AT-2 | Privileged users understand their roles and responsibilities | | |
| PR.AT-3 | Third-party stakeholders understand their roles | | |

### PR.DS — Data Security
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| PR.DS-1 | Data-at-rest is protected | | |
| PR.DS-2 | Data-in-transit is protected | | |
| PR.DS-3 | Assets are formally managed throughout removal, transfer, and disposal | | |
| PR.DS-5 | Protections against data leaks are implemented | | |
| PR.DS-6 | Integrity checking mechanisms are used to verify software/firmware integrity | | |

### PR.IP — Information Protection Processes
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| PR.IP-1 | A baseline configuration exists and is maintained | | |
| PR.IP-3 | Configuration change control processes are in place | | |
| PR.IP-4 | Backups are conducted, maintained, and tested | | |
| PR.IP-9 | Response plans and recovery plans are in place | | |
| PR.IP-11 | Cybersecurity is included in HR practices | | |
| PR.IP-12 | A vulnerability management plan is developed and implemented | | |

### PR.MA — Maintenance
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| PR.MA-1 | Maintenance of assets is performed and logged | | |
| PR.MA-2 | Remote maintenance is approved, logged, and performed in a secure manner | | |

### PR.PT — Protective Technology
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| PR.PT-1 | Audit/log records are determined, documented, implemented, and reviewed | | |
| PR.PT-3 | PoLP is incorporated into systems and services | | |
| PR.PT-4 | Communications and control networks are protected | | |

**PROTECT Sub-total: ___ / 78**

---

## Function 3: DETECT (DE)
*Identify the occurrence of a cybersecurity event.*

### DE.AE — Anomalies and Events
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| DE.AE-1 | A baseline of network operations and expected data flows is established | | |
| DE.AE-2 | Detected events are analyzed to understand attack targets and methods | | |
| DE.AE-3 | Event data are aggregated and correlated from multiple sources | | |
| DE.AE-5 | Incident alert thresholds are established | | |

### DE.CM — Security Continuous Monitoring
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| DE.CM-1 | The network is monitored for potential cybersecurity events | | |
| DE.CM-2 | Physical environment is monitored for potential events | | |
| DE.CM-3 | Personnel activity is monitored for potential events | | |
| DE.CM-4 | Malicious code is detected | | |
| DE.CM-5 | Unauthorized mobile code is detected | | |
| DE.CM-6 | External service provider activity is monitored | | |
| DE.CM-7 | Monitoring for unauthorized personnel, connections, devices, and software | | |
| DE.CM-8 | Vulnerability scans are performed | | |

### DE.DP — Detection Processes
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| DE.DP-1 | Roles and responsibilities for detection are well defined | | |
| DE.DP-2 | Detection activities comply with applicable requirements | | |
| DE.DP-4 | Event detection information is communicated to appropriate parties | | |
| DE.DP-5 | Detection processes are continuously improved | | |

**DETECT Sub-total: ___ / 48**

---

## Function 4: RESPOND (RS)
*Take action regarding a detected cybersecurity incident.*

### RS.RP — Response Planning
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| RS.RP-1 | Response plan is executed during or after an incident | | |

### RS.CO — Communications
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| RS.CO-1 | Personnel know their roles during a response | | |
| RS.CO-2 | Incidents are reported consistent with established criteria | | |
| RS.CO-3 | Information is shared consistent with response plans | | |
| RS.CO-5 | Voluntary information sharing with external stakeholders | | |

### RS.AN — Analysis
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| RS.AN-1 | Notifications from detection systems are investigated | | |
| RS.AN-2 | The impact of the incident is understood | | |
| RS.AN-4 | Incidents are categorized consistent with response plans | | |

### RS.MI — Mitigation
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| RS.MI-1 | Incidents are contained | | |
| RS.MI-2 | Incidents are mitigated | | |
| RS.MI-3 | Newly identified vulnerabilities are mitigated or documented as accepted | | |

### RS.IM — Improvements
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| RS.IM-1 | Response plans incorporate lessons learned | | |
| RS.IM-2 | Response strategies are updated | | |

**RESPOND Sub-total: ___ / 39**

---

## Function 5: RECOVER (RC)
*Maintain plans for resilience and restore capabilities after an incident.*

### RC.RP — Recovery Planning
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| RC.RP-1 | Recovery plan is executed during or after an incident | | |

### RC.IM — Improvements
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| RC.IM-1 | Recovery plans incorporate lessons learned | | |
| RC.IM-2 | Recovery strategies are updated | | |

### RC.CO — Communications
| # | Control | Score (0–3) | Notes / Evidence |
|---|---------|-------------|-----------------|
| RC.CO-1 | Public relations are managed | | |
| RC.CO-2 | Reputation is repaired after an incident | | |
| RC.CO-3 | Recovery activities are communicated to stakeholders | | |

**RECOVER Sub-total: ___ / 18**

---

## Summary Scorecard

| Function | Max Score | Your Score | % |
|----------|-----------|-----------|---|
| Identify (ID) | 42 | | |
| Protect (PR) | 78 | | |
| Detect (DE) | 48 | | |
| Respond (RS) | 39 | | |
| Recover (RC) | 18 | | |
| **Total** | **225** | | |

## Maturity Tier Mapping
| Score % | NIST Tier | Description |
|---------|-----------|-------------|
| 0–25% | Tier 1: Partial | Ad hoc, reactive, limited awareness |
| 26–50% | Tier 2: Risk Informed | Risk management practices exist but not org-wide |
| 51–75% | Tier 3: Repeatable | Formally approved, consistently applied |
| 76–100% | Tier 4: Adaptive | Adapts based on lessons learned and threat intelligence |

## Remediation Prioritization
After completing the assessment:
1. List all controls scored 0 or 1
2. Cross-reference with your risk register — prioritize controls that address your highest-rated risks
3. Assign an owner and target completion date to each gap
4. Re-assess in 6–12 months and track maturity improvement over time

## References
- [NIST CSF Official Documentation](https://www.nist.gov/cyberframework)
- [NIST SP 800-53 Control Catalog](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [CISA CSF Resources](https://www.cisa.gov/cybersecurity-framework)
- [CIS Controls v8](https://www.cisecurity.org/controls/)
