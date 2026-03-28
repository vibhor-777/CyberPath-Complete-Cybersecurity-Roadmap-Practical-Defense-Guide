# D — Data Loss Prevention (DLP)

## Beginner Explanation
Data Loss Prevention is a set of technologies and processes that detect and prevent sensitive data from leaving an organization without authorization. Imagine a security guard at the exit door who checks everything going out — not just what comes in. DLP watches data moving across networks, being copied to USB drives, or being emailed, and blocks unauthorized transfers.

## Technical Deep Dive

### DLP Inspection Methods
| Method | How it Works | Example Use Case |
|--------|-------------|-----------------|
| **Content Inspection** | Scans content for patterns matching sensitive data | Finding credit card numbers in email attachments |
| **Contextual Analysis** | Considers who, what, when, and where | Flagging unusual large transfers of HR data |
| **Fingerprinting** | Creates a digital fingerprint of sensitive documents | Detecting copies of a confidential contract |
| **Machine Learning** | Classifies content by learned patterns | Identifying proprietary source code in uploads |

### Common Sensitive Data Patterns (Regex)
```python
import re

# Credit card number (Luhn-valid patterns)
CREDIT_CARD = re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b')

# US Social Security Number
SSN = re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b')

# Email address
EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

# AWS Access Key
AWS_KEY = re.compile(r'\b(AKIA[0-9A-Z]{16})\b')

# Generic API key pattern
API_KEY = re.compile(r'(?i)(api[_-]?key|apikey|secret)["\s:=]+([A-Za-z0-9]{20,})')
```

### DLP Deployment Points
```
Data at Rest:    Storage-level DLP — scans file servers, databases, cloud storage
Data in Motion:  Network DLP — inspects email, web proxy, API traffic
Data in Use:     Endpoint DLP — monitors clipboard, USB, print, screen capture
```

### Microsoft Purview DLP (Example Policy)
```
Policy: "Block Credit Card Numbers in External Email"
Conditions:
  - Content contains: Credit card number patterns
  - Recipient: External (outside the organization)
Actions:
  - Block the email
  - Notify the sender: "This email contains sensitive payment data and cannot be sent externally"
  - Alert security team
Exceptions:
  - Sender in group: Finance-Approved-External-Senders
```

## Real-World Relevance
**The Capital One Breach (2019):** A misconfigured WAF allowed a former cloud provider employee to execute SSRF, accessing AWS metadata credentials and downloading 100 million customer records. A properly configured cloud DLP policy monitoring for large S3 bucket reads by non-standard IAM roles could have detected and alerted on this exfiltration.

## Defensive Measures
1. Classify your data first — you can't protect what you haven't identified
2. Deploy endpoint DLP to block USB transfer and unauthorized cloud uploads
3. Implement email DLP scanning for common PII patterns (SSN, credit cards, PHI)
4. Monitor and alert on large data transfers to unusual destinations
5. Implement data labeling (Microsoft Sensitivity Labels, AWS Macie) to tag sensitive data automatically

## Practice Challenge
1. Write a Python script that scans a directory of text files for SSN and credit card patterns using regex.
2. Test it against sample files you create (use fake/test data — never real PII).
3. Log found patterns with the file name and line number (but not the actual sensitive value).
4. Extend it to alert if a file's size exceeds 10MB (potential bulk exfiltration).
