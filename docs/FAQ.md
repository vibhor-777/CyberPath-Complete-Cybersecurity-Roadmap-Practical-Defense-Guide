# ❓ Frequently Asked Questions

> Answers to the most common questions from new users and contributors.

---

## Table of Contents

- [General Questions](#general-questions)
- [Learning Path Questions](#learning-path-questions)
- [Script & Technical Questions](#script--technical-questions)
- [Contributing Questions](#contributing-questions)
- [Lab Setup Questions](#lab-setup-questions)

---

## General Questions

### What is CyberPath?

CyberPath is a free, open-source cybersecurity learning repository that provides:
- Structured educational content organized into 11 topic modules
- A 26-concept A–Z encyclopedic reference
- Real, usable Python and PowerShell defensive scripts
- Certification alignment and learning tracks from beginner to expert

### Who is CyberPath for?

CyberPath is designed for:
- **Students** preparing for CompTIA Security+, CySA+, or similar certifications
- **IT professionals** transitioning into cybersecurity roles (SOC Analyst, IR Engineer)
- **Security practitioners** who want a quick-reference defensive encyclopedia
- **Organizations** building internal security training programs

No experience is required to start — the Beginner Track begins with computing fundamentals.

### Is CyberPath free?

Yes. CyberPath is licensed under the [MIT License](../LICENSE). All content is free to use, adapt, and redistribute with attribution.

### Does CyberPath teach offensive hacking?

No. CyberPath is **exclusively defensive**. All content is framed from the defender's perspective: how to detect threats, prevent attacks, harden systems, and respond to incidents. Attack techniques are described only when necessary to understand how to defend against them.

### Is this repository affiliated with any vendor or certification body?

No. CyberPath is an independent community project. Certification references (Security+, CySA+, CISSP, etc.) are for guidance only and do not imply endorsement by CompTIA, ISC², GIAC, or any other organization.

---

## Learning Path Questions

### Where should I start?

If you're new to cybersecurity:
1. Start with [LEARNING.md](../LEARNING.md) to understand the full progression
2. Begin with the **Beginner Track** → `01_Foundations/`
3. Set up a lab environment following [docs/INSTALLATION.md](INSTALLATION.md)

If you have some experience, use the **Milestone Checks** in [LEARNING.md](../LEARNING.md) to find your starting point.

### How long will it take to complete everything?

The tracks are designed for these approximate timelines:

| Track | Time | Commitment |
|-------|------|------------|
| Beginner | 3 months | ~10 hours/week |
| Intermediate | 6 months | ~10 hours/week |
| Advanced | 9 months | ~10 hours/week |
| Expert | Ongoing | Continuous |

These are estimates — your pace may vary based on prior experience and available time.

### Do I need a virtual lab to follow along?

For the conceptual modules (`01–08`, `10–11`), no lab is required — you can read and study the materials anywhere.

For the practical labs in [LEARNING.md](../LEARNING.md) and the scripts in `09_Defensive_Tooling/`, a lab environment is strongly recommended. See [INSTALLATION.md](INSTALLATION.md) for setup instructions.

### Which certifications does CyberPath prepare me for?

See the [Certification Alignment table](../LEARNING.md#certification-alignment) in LEARNING.md. CyberPath content aligns with:

- CompTIA Security+, CySA+, CASP+
- BTL1 (Blue Team Labs)
- GCIA, GCIH, GREM, GCFE
- CISM, CISSP (expert level)

CyberPath does not include offensive content aligned with OSCP.

---

## Script & Technical Questions

### What Python version do I need?

Python 3.8 or higher. All scripts are tested against Python 3.8, 3.10, and 3.11.

### Do the Python scripts require external packages?

No. All Python scripts use only the Python standard library. No `pip install` is required.

### What PowerShell version do I need?

PowerShell 5.1 (built into Windows 10/11) is the minimum. PowerShell 7+ is recommended and is required to run the scripts on Linux or macOS.

### Do the PowerShell scripts work on Linux/macOS?

Most scripts are Windows-specific because they interact with Windows-specific subsystems (Event Log, Registry, Scheduled Tasks). They can be run on Linux/macOS via PowerShell 7, but only on Windows will they produce meaningful results.

### `fim.py` says "baseline not found" — what do I do?

You must create a baseline before monitoring. Run:

```bash
python3 fim.py --baseline --dirs /etc /usr/bin
python3 fim.py --monitor
```

### Can I use these scripts on my employer's systems?

Only with **explicit written permission** from your employer. Using monitoring scripts on systems without authorization may violate company policy, computer crime laws, or both. Always get written authorization first.

### How do I schedule `fim.py` to run automatically?

**Linux/macOS (cron):**

```bash
# Edit crontab
crontab -e

# Add (runs every 15 minutes)
*/15 * * * * /usr/bin/python3 /path/to/fim.py --monitor --log /var/log/fim.log
```

**Windows (Task Scheduler):**

```powershell
$action = New-ScheduledTaskAction -Execute "python3" -Argument "C:\cyberpath\fim.py --monitor --log C:\logs\fim.log"
$trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 15) -Once -At (Get-Date)
Register-ScheduledTask -TaskName "CyberPath FIM" -Action $action -Trigger $trigger -RunLevel Highest
```

---

## Contributing Questions

### How do I contribute to CyberPath?

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full guide. The short version:

1. Fork the repository
2. Create a branch (`git checkout -b feature/my-improvement`)
3. Make your changes following the style guide
4. Submit a pull request

### I found a typo / broken link. Should I open an issue or just fix it?

For small fixes (typos, broken links), feel free to submit a pull request directly — no issue required. For larger changes, open an issue first to discuss.

### Can I contribute a guide on penetration testing or offensive tools?

No. CyberPath is defensive-only. Contributions must be framed from the defender's perspective. See the [Prime Directive](../CONTRIBUTING.md#-the-prime-directive-defensive-only) in CONTRIBUTING.md.

### How long does PR review take?

Maintainers aim to review PRs within 7 days. Complex changes may take longer. If your PR hasn't received a review after 10 days, feel free to leave a comment on it.

### I'm a beginner — can I still contribute?

Absolutely. Great beginner contributions include:
- Fixing typos or grammar
- Improving clarity in existing explanations
- Adding practice challenge ideas
- Reporting broken links as issues

---

## Lab Setup Questions

### I don't have a powerful computer for VMs — what are my options?

Use cloud-based labs instead:
- [TryHackMe](https://tryhackme.com) — Browser-based, no local install needed
- [HackTheBox](https://hackthebox.com) — Browser-based VPN labs
- [LetsDefend](https://letsdefend.io) — Blue team SOC labs
- [CyberDefenders](https://cyberdefenders.org) — DFIR challenges

All of these work on any device with a web browser.

### What's the minimum RAM for a home lab?

| Setup | RAM Needed |
|-------|-----------|
| Single Linux VM (Ubuntu Server) | 2 GB (host needs 4 GB+) |
| Linux + Windows pair | 8 GB host RAM recommended |
| Full stack (Kali + Ubuntu + Windows) | 16 GB host RAM recommended |

### Do I need to install Kali Linux to use CyberPath?

No. Kali Linux is a penetration testing distribution. CyberPath is focused on defense, so a standard Ubuntu Server or Windows VM is sufficient for all labs.

### Where can I get free vulnerable VMs to practice on?

- [VulnHub](https://www.vulnhub.com/) — Downloadable intentionally vulnerable VMs
- [DVWA](https://github.com/digininja/DVWA) — Damn Vulnerable Web Application (Docker/WAMP)
- [Metasploitable](https://sourceforge.net/projects/metasploitable/) — Intentionally vulnerable Linux VM

> ⚠️ **Important:** Only run these VMs in an isolated, internal-only network. Never expose them to the internet.

---

*Still have a question? [Open an issue](https://github.com/vibhor-777/CyberPath-Complete-Cybersecurity-Roadmap-Practical-Defense-Guide/issues/new/choose) or check the [Discussions](https://github.com/vibhor-777/CyberPath-Complete-Cybersecurity-Roadmap-Practical-Defense-Guide/discussions) tab.*
