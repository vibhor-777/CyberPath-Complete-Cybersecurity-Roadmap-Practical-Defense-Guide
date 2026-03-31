## 📋 Pull Request Summary

**What does this PR add or change?**

<!-- Provide a clear, concise description of what you've added or changed. -->

**Related issue(s):** Closes #<!-- issue number, if applicable -->

---

## 🛡️ Defensive-Only Checklist

> All contributions to CyberPath must be defensive in nature. Please confirm:

- [ ] This PR contains **only** defensive content (hardening, detection, monitoring, education)
- [ ] If attack techniques are described, they are framed exclusively from the **defender's perspective** (how to detect, prevent, or mitigate)
- [ ] No offensive exploitation tools, weaponized payloads, or step-by-step attack tutorials are included

---

## ✅ Quality Checklist

### For Documentation / Markdown

- [ ] Content follows the [CyberPath style guide](CONTRIBUTING.md#style-guide)
- [ ] Headings use correct hierarchy (`##`, `###`)
- [ ] Code blocks have language specifiers (` ```bash `, ` ```python `, etc.)
- [ ] All internal links have been verified
- [ ] "⚠️ Lab Environment Only" warnings are added where needed
- [ ] No personally identifiable information (PII) included
- [ ] Proper attribution for any third-party content or research

### For Python Scripts

- [ ] Script runs in Python 3.8+ without external dependencies (or dependencies are documented)
- [ ] Tested in a safe lab environment
- [ ] Docstring / usage comment at the top of the file
- [ ] No hardcoded credentials or sensitive values
- [ ] Errors are handled gracefully

### For PowerShell Scripts

- [ ] Script tested in PowerShell 5.1+ (and/or PowerShell 7+ if applicable)
- [ ] Uses `Verb-Noun` naming convention
- [ ] `#Requires` statement at the top if elevated privileges are needed
- [ ] No hardcoded credentials or sensitive values
- [ ] Comment-based help provided (`.SYNOPSIS`, `.DESCRIPTION`, `.EXAMPLE`)

---

## 🧪 Testing

How did you verify that your changes work correctly?

- [ ] Ran the script in a local lab environment
- [ ] Previewed Markdown rendering in VS Code or GitHub
- [ ] Verified all links are functional
- [ ] Other: <!-- describe -->

---

## 📸 Screenshots / Output (optional)

If applicable, add screenshots or sample output demonstrating the change.

---

## 📝 Additional Notes

<!-- Anything else reviewers should know? -->
