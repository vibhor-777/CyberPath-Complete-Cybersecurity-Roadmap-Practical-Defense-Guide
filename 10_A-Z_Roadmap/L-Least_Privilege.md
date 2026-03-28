# L — Least Privilege

## Beginner Explanation
The Principle of Least Privilege (PoLP) means every user, service, and system should have only the minimum access needed to do their job — nothing more. If an account is compromised, PoLP limits how far the attacker can move.

## Technical Deep Dive

### Role-Based Access Control (RBAC)
```
User: Alice  → Role: HR_Analyst  → Permissions: Read HR_DB, Write HR_Reports
Service: Web → Role: WebApp      → Permissions: Read Products_DB only
```

### Auditing Privileged AD Accounts
```powershell
Get-ADGroupMember "Domain Admins" | Select-Object Name, SamAccountName
Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount | Select-Object Name
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires
```

### Just-In-Time (JIT) Access
Grant time-limited elevated privileges on demand; revoke automatically. Tools: Azure PIM, CyberArk, BeyondTrust.

### Sudo Hardening (Linux)
```bash
# Grant ONLY specific commands
alice ALL=(ALL) /usr/bin/systemctl restart nginx

# Require password; short timeout
Defaults timestamp_timeout=5
Defaults logfile=/var/log/sudo.log
```

### AWS: Least-Privilege IAM Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"],
    "Resource": "arn:aws:s3:::my-bucket/uploads/*"}]
}
```

## Real-World Relevance
**SolarWinds (2020):** Orion service accounts held Domain Admin rights in customer environments. When SUNBURST activated, attackers immediately had unrestricted AD access. Proper PoLP would have contained the blast radius to monitored systems only.

## Defensive Measures
1. Audit privileged group memberships quarterly
2. Implement JIT access for all administrative roles
3. Use Group Managed Service Accounts (gMSA) for service accounts
4. Apply PoLP to cloud IAM roles and API keys — not only human users
5. Use dedicated Privileged Access Workstations (PAWs) for admin tasks

## Practice Challenge
1. Enumerate Domain Admins in a lab AD; identify any that shouldn't be there.
2. Write a sudoers rule allowing restart of nginx only.
3. Create an AWS IAM policy granting read-only access to exactly one S3 bucket prefix.
