# IAM Hardening — AWS and Azure

> **Module:** [05 Cloud Security](./README.md) | **Back to root:** [Repository Root](../README.md)

Identity and Access Management (IAM) is the most critical security control in cloud environments. Attackers who compromise credentials or exploit IAM misconfigurations can move laterally to any resource the identity has access to. This guide covers hardening IAM in both AWS and Azure with practical, implementable controls.

---

## Table of Contents

1. [Eliminating Long-Lived Credentials](#1-eliminating-long-lived-credentials)
2. [IAM Roles vs Users vs Groups](#2-iam-roles-vs-users-vs-groups)
3. [Principle of Least Privilege in Cloud](#3-principle-of-least-privilege-in-cloud)
4. [AWS IAM Hardening](#4-aws-iam-hardening)
5. [Azure IAM Hardening](#5-azure-iam-hardening)
6. [Service Accounts and Workload Identity](#6-service-accounts-and-workload-identity)
7. [MFA Enforcement](#7-mfa-enforcement)
8. [Key Rotation and Secrets Management](#8-key-rotation-and-secrets-management)

---

## 1. Eliminating Long-Lived Credentials

### Beginner Explanation

Long-lived credentials (access keys that never expire, passwords without rotation) are like leaving a key permanently in your lock. If stolen, an attacker has indefinite access. The goal is to use temporary, short-lived credentials wherever possible.

### Technical Deep Dive

**Types of long-lived credentials and their risks:**

| Credential Type | Default Expiry | Risk if Stolen | Replacement |
|----------------|---------------|----------------|-------------|
| AWS IAM Access Keys | Never | Permanent account access | IAM roles with STS temporary tokens |
| Azure Service Principal secret | Up to 2 years | Extended access | Managed Identities |
| GCP Service Account keys | Never | Permanent access | Workload Identity Federation |
| Static database passwords | Never | DB access until rotated | Secrets Manager with auto-rotation |
| SSH keys (no passphrase) | Never | Server access | AWS Systems Manager Session Manager |

**Detecting long-lived AWS access keys:**

```bash
# Find all IAM users with access keys and their age
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d | \
  python3 -c "
import csv, sys
from datetime import datetime, timezone

reader = csv.DictReader(sys.stdin)
for row in reader:
    for key_num in ['1', '2']:
        key_active = row.get(f'access_key_{key_num}_active', 'false')
        last_rotated = row.get(f'access_key_{key_num}_last_rotated', 'N/A')
        
        if key_active == 'true' and last_rotated != 'N/A':
            last_rotated_dt = datetime.fromisoformat(last_rotated.replace('Z', '+00:00'))
            age_days = (datetime.now(timezone.utc) - last_rotated_dt).days
            
            if age_days > 90:
                print(f'⚠️  {row[\"user\"]}: key_{key_num} is {age_days} days old')
"

# Find access keys not used in 90+ days (candidates for deletion)
aws iam generate-credential-report
aws iam get-credential-report --output text --query Content | base64 -d | \
  awk -F',' '{print $1, $9, $11}' | \
  grep -v "N/A" | grep "access_key_1_last_used_date"
```

**Rotating an AWS access key with zero downtime:**

```bash
# Step 1: Create new access key for the user
NEW_KEY=$(aws iam create-access-key --user-name myapp-service-user \
  --query 'AccessKey.{Key:AccessKeyId,Secret:SecretAccessKey}' \
  --output json)

NEW_ACCESS_KEY=$(echo $NEW_KEY | jq -r '.Key')
NEW_SECRET=$(echo $NEW_KEY | jq -r '.Secret')

# Step 2: Update all consumers (applications, CI/CD secrets) with new key

# Step 3: Verify new key works
AWS_ACCESS_KEY_ID=$NEW_ACCESS_KEY AWS_SECRET_ACCESS_KEY=$NEW_SECRET \
  aws sts get-caller-identity

# Step 4: Deactivate old key (NOT delete yet — allows rollback)
OLD_KEY_ID="AKIAIOSFODNN7EXAMPLE"
aws iam update-access-key \
  --user-name myapp-service-user \
  --access-key-id $OLD_KEY_ID \
  --status Inactive

# Step 5: After confirming new key works (48h), delete old key
aws iam delete-access-key \
  --user-name myapp-service-user \
  --access-key-id $OLD_KEY_ID
```

### Real-World Relevance

- **Uber (2022):** An attacker found AWS credentials in a private GitHub repository and used them to enumerate AWS resources. Leaked credentials in source code (even private repositories) are a persistent threat vector.
- **Tesla (2018):** An unsecured Kubernetes console exposed AWS credentials with broad permissions, used to mine cryptocurrency. No credential rotation meant the keys remained valid indefinitely.

### Defensive Measures

- **Default to IAM roles** — never create long-lived access keys for workloads running on AWS infrastructure.
- **Enforce 90-day key rotation** via AWS Config rule `access-keys-rotated`.
- **GitGuardian / truffleHog** — scan repositories for committed secrets before they become incidents.

```bash
# Scan Git history for secrets
pip install truffleHog3
trufflehog git https://github.com/yourorg/yourrepo.git --json

# Alternatively with gitleaks
gitleaks detect --source . --verbose
```

### Practice Challenge

> ⚠️ **Lab Environment Only** — Audit your sandbox AWS account's IAM credential report. Identify any access keys older than 90 days. Rotate one key using the zero-downtime procedure above. Enable the `access-keys-rotated` AWS Config rule and verify it detects the old key.

---

## 2. IAM Roles vs Users vs Groups

### Beginner Explanation

**IAM Users** are long-term identities with passwords and/or access keys. **IAM Groups** are collections of users that share a set of permissions. **IAM Roles** are temporary identities assumed by services, applications, or federated users — they issue short-lived credentials automatically.

### Technical Deep Dive

**AWS IAM entity comparison:**

| Entity | Credentials | Lifetime | Best For |
|--------|-------------|---------|---------|
| **Root Account** | Password + MFA | Permanent | Emergency break-glass only |
| **IAM User** | Password + Access Keys | Permanent | Human console access (prefer SSO instead) |
| **IAM Group** | None (policy attachment) | N/A | Organizing users with similar permissions |
| **IAM Role** | Temporary tokens (STS) | 15 min – 12 hours | Workloads, services, cross-account, SSO |

**When to use each (decision tree):**

```
Is the identity a human?
├── Yes → Use IAM Identity Center (SSO) → Roles assumed via federation
│         (Avoid creating individual IAM users for humans)
└── No → Is it a workload on AWS?
         ├── Yes → Use IAM Role attached to the service (EC2, Lambda, ECS, etc.)
         └── No → Is it CI/CD or external workload?
                  └── Use OIDC-based Role assumption (GitHub Actions, GitLab, etc.)
                      (Avoid static access keys for CI/CD)
```

**AWS IAM Group example (developer permissions):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DeveloperS3ReadOnly",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::dev-assets-bucket",
        "arn:aws:s3:::dev-assets-bucket/*"
      ]
    },
    {
      "Sid": "DenyProdAccess",
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::prod-*",
        "arn:aws:s3:::prod-*/*"
      ]
    }
  ]
}
```

**Azure RBAC — Built-in vs Custom Roles:**

```bash
# List built-in Azure roles
az role definition list --query '[].{Name:roleName,Type:roleType}' \
  --output table | grep -i built

# Common built-in roles (prefer these over custom):
# Owner           — Full access including role assignment (avoid)
# Contributor     — Full resource management, no role assignment
# Reader          — Read-only
# User Access Administrator — Manage role assignments only
# Storage Blob Data Reader  — Read blob data (not management plane)

# Assign Reader role scoped to a resource group (least privilege scoping)
az role assignment create \
  --assignee "user@example.com" \
  --role "Reader" \
  --scope "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/myRG"
```

**Azure custom role (when built-in roles are too broad):**

```json
{
  "Name": "Restricted VM Operator",
  "IsCustom": true,
  "Description": "Can start/stop VMs but not delete or reconfigure",
  "Actions": [
    "Microsoft.Compute/virtualMachines/start/action",
    "Microsoft.Compute/virtualMachines/restart/action",
    "Microsoft.Compute/virtualMachines/deallocate/action",
    "Microsoft.Compute/virtualMachines/read"
  ],
  "NotActions": [
    "Microsoft.Compute/virtualMachines/delete",
    "Microsoft.Compute/virtualMachines/write"
  ],
  "DataActions": [],
  "NotDataActions": [],
  "AssignableScopes": [
    "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/production-vms"
  ]
}
```

```bash
az role definition create --role-definition restricted-vm-operator.json
```

---

## 3. Principle of Least Privilege in Cloud

### Beginner Explanation

Least privilege means every identity (user, service, role) should have only the permissions needed to perform its specific function—nothing more. In cloud environments this is both more critical (blast radius of a compromise is larger) and more complex (hundreds of available permissions).

### Technical Deep Dive

**AWS: Using IAM Access Analyzer to identify unused permissions:**

```bash
# Enable IAM Access Analyzer
aws accessanalyzer create-analyzer \
  --analyzer-name "AccountAnalyzer" \
  --type ACCOUNT

# List findings (external access findings)
aws accessanalyzer list-findings \
  --analyzer-arn "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/AccountAnalyzer" \
  --query 'findings[?status==`ACTIVE`].[id,resourceType,resource]' \
  --output table

# Generate least-privilege policy based on CloudTrail activity (last 90 days)
aws iam generate-service-last-accessed-details \
  --arn "arn:aws:iam::123456789012:role/MyAppRole"
```

**AWS: Analyzing role permissions with policy simulator:**

```bash
# Simulate whether a role can perform a specific action
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::123456789012:role/MyAppRole" \
  --action-names "s3:DeleteObject" "s3:PutBucketPolicy" "ec2:TerminateInstances" \
  --resource-arns "*" \
  --query 'EvaluationResults[*].[EvalActionName,EvalDecision]' \
  --output table
```

**Building a least-privilege policy from CloudTrail (practical workflow):**

```bash
# Step 1: Run your application for 2-4 weeks with a permissive role
# Step 2: Extract what actions it actually used from CloudTrail

aws logs filter-log-events \
  --log-group-name "aws-cloudtrail-logs" \
  --filter-pattern '{ $.userIdentity.arn = "arn:aws:iam::123456789012:role/MyAppRole" }' \
  --query 'events[*].message' | \
  python3 -c "
import json, sys, collections
events = json.load(sys.stdin)
actions = collections.Counter()
for event_str in events:
    try:
        event = json.loads(event_str)
        service = event.get('eventSource', '').replace('.amazonaws.com', '')
        action = event.get('eventName', '')
        actions[f'{service}:{action}'] += 1
    except:
        pass
for action, count in actions.most_common():
    print(f'{count:6d}  {action}')
"

# Step 3: Build a policy containing only the observed actions
# Step 4: Replace the permissive role with the least-privilege policy
```

**AWS Service Control Policies (SCPs) — account-level guardrails:**

```json
// SCP: Prevent leaving the AWS Organization and disable security services
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyLeavingOrg",
      "Effect": "Deny",
      "Action": ["organizations:LeaveOrganization"],
      "Resource": "*"
    },
    {
      "Sid": "DenyDisablingSecurityServices",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:DeleteDetector",
        "config:DeleteConfigRule",
        "config:StopConfigurationRecorder",
        "securityhub:DisableSecurityHub"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyRootAccountUsage",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        }
      }
    }
  ]
}
```

---

## 4. AWS IAM Hardening

### Technical Deep Dive

**IAM Password Policy:**

```bash
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --allow-users-to-change-password \
  --max-password-age 90 \
  --password-reuse-prevention 24 \
  --hard-expiry
```

**IAM Policy: Force MFA for all actions except MFA setup:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowViewAccountInfo",
      "Effect": "Allow",
      "Action": ["iam:GetAccountPasswordPolicy", "iam:GetAccountSummary", "iam:ListVirtualMFADevices"],
      "Resource": "*"
    },
    {
      "Sid": "AllowManageOwnMFA",
      "Effect": "Allow",
      "Action": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ResyncMFADevice"
      ],
      "Resource": ["arn:aws:iam::*:mfa/${aws:username}", "arn:aws:iam::*:user/${aws:username}"]
    },
    {
      "Sid": "DenyAllExceptListedIfNoMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
      }
    }
  ]
}
```

**AWS CloudTrail — comprehensive audit logging:**

```bash
# Create a multi-region CloudTrail (CIS Benchmark requirement)
aws cloudtrail create-trail \
  --name "OrganizationTrail" \
  --s3-bucket-name "my-cloudtrail-logs-bucket" \
  --include-global-service-events \
  --is-multi-region-trail \
  --enable-log-file-validation   # SHA-256 hash validation of log files

aws cloudtrail start-logging --name "OrganizationTrail"

# Enable CloudTrail Insights (detect unusual API activity)
aws cloudtrail put-insight-selectors \
  --trail-name "OrganizationTrail" \
  --insight-selectors '[{"InsightType": "ApiCallRateInsight"}, {"InsightType": "ApiErrorRateInsight"}]'

# Verify log file integrity
aws cloudtrail validate-logs \
  --trail-arn "arn:aws:cloudtrail:us-east-1:123456789012:trail/OrganizationTrail" \
  --start-time "2024-01-01T00:00:00Z" \
  --end-time "2024-01-31T23:59:59Z"
```

**AWS IAM Identity Center (SSO) configuration:**

```bash
# Enable IAM Identity Center
# (Done via AWS Console or Organizations management account)

# Create a Permission Set (equivalent of IAM role for SSO)
aws sso-admin create-permission-set \
  --instance-arn "arn:aws:sso:::instance/ssoins-example" \
  --name "DeveloperAccess" \
  --description "Developer access to dev accounts" \
  --session-duration "PT8H"   # 8-hour session maximum

# Attach an AWS managed policy to the permission set
aws sso-admin attach-managed-policy-to-permission-set \
  --instance-arn "arn:aws:sso:::instance/ssoins-example" \
  --permission-set-arn "arn:aws:sso:::permissionSet/ssoins-example/ps-example" \
  --managed-policy-arn "arn:aws:iam::aws:policy/PowerUserAccess"
```

**AWS Access Analyzer — detect external access:**

```bash
# List all resources exposed to external principals
aws accessanalyzer list-findings \
  --analyzer-arn "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/AccountAnalyzer" \
  --filter '{"status": {"eq": ["ACTIVE"]}}' \
  --query 'findings[*].{Resource:resource,Type:resourceType,External:principal}' \
  --output table

# Archive a finding after review (mark as expected/accepted)
aws accessanalyzer update-findings \
  --analyzer-arn "arn:aws:access-analyzer:..." \
  --ids '["finding-id"]' \
  --status ARCHIVED
```

### Practice Challenge

> In your AWS sandbox account: (1) Apply the MFA-enforcement policy to your IAM user. (2) Enable multi-region CloudTrail with log validation. (3) Run Access Analyzer and review any external access findings. (4) Use the IAM policy simulator to verify your role cannot `s3:DeleteBucket` on production buckets.

---

## 5. Azure IAM Hardening

### Technical Deep Dive

**Azure Privileged Identity Management (PIM) — just-in-time privileged access:**

```bash
# Enable PIM for a role assignment (requires Azure AD Premium P2)
# Use Azure Portal: Azure AD → Identity Governance → Privileged Identity Management

# Via Azure CLI (requires Az.Resources module and PIM permissions):

# Make a user "eligible" for Global Administrator (not permanently assigned)
az role assignment create \
  --assignee "user@example.com" \
  --role "Owner" \
  --scope "/subscriptions/$(az account show --query id -o tsv)" \
  --condition "PIM eligible" \
  # (PIM eligibility is configured in Azure Portal for full control)

# Key PIM concepts:
# Active assignment:    User has the role right now
# Eligible assignment:  User must explicitly activate (approve, MFA, justification)
# Activation period:    Role active for 1-8 hours then auto-expires
# Approval required:    Activations need manager approval (optional)
```

**Azure Conditional Access Policies:**

```bash
# Conditional Access is configured in Azure Portal:
# Azure AD → Security → Conditional Access → New Policy

# Key policies to implement:
# 1. Require MFA for all users
# 2. Require compliant device for admin access
# 3. Block legacy authentication protocols
# 4. Block access from high-risk sign-in locations
# 5. Require MFA registration from trusted locations only

# Via Microsoft Graph API (PowerShell example):
# Install-Module Microsoft.Graph
# Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"
```

```json
// Conditional Access Policy: Require MFA for All Users
// (Graph API request body)
{
  "displayName": "Require MFA for All Users",
  "state": "enabled",
  "conditions": {
    "users": {
      "includeUsers": ["All"],
      "excludeUsers": ["breakglass-account-object-id"]
    },
    "applications": {
      "includeApplications": ["All"]
    }
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["mfa"]
  }
}
```

**Azure RBAC audit — find over-permissioned assignments:**

```bash
# Find all Owner role assignments (should be minimal)
az role assignment list --all \
  --query "[?roleDefinitionName=='Owner'].{Principal:principalName,Scope:scope,Type:principalType}" \
  --output table

# Find all role assignments at subscription scope (broad permissions)
az role assignment list --all \
  --scope "/subscriptions/$(az account show --query id -o tsv)" \
  --query "[].{Role:roleDefinitionName,Principal:principalName,PrincipalType:principalType}" \
  --output table | sort

# Find service principals with Contributor or higher
az role assignment list --all \
  --query "[?principalType=='ServicePrincipal' && (roleDefinitionName=='Contributor' || roleDefinitionName=='Owner')].{SP:principalName,Role:roleDefinitionName,Scope:scope}" \
  --output table
```

**Azure Entra ID (formerly AAD) — hardening settings:**

```bash
# List all applications with credentials (service principal secrets and certs)
az ad app list --all \
  --query "[].{AppName:displayName,AppID:appId}" \
  --output table

# Check service principal credential expiry
az ad sp list --all \
  --query "[?passwordCredentials[?endDateTime<'2024-12-31']].{SP:displayName,Expiry:passwordCredentials[0].endDateTime}" \
  --output table

# Disable legacy authentication at tenant level
# Azure Portal: Azure AD → Properties → Manage Security defaults → Enable
# Or via Conditional Access: Block "Other clients" (basic auth)
```

---

## 6. Service Accounts and Workload Identity

### Beginner Explanation

Applications running in the cloud need to access other services (databases, queues, storage). The wrong way: give them a static username/password or access key. The right way: use the cloud platform's managed identity mechanism to issue automatic, short-lived credentials.

### Technical Deep Dive

**AWS: EC2 Instance Profiles (IAM Role for EC2):**

```bash
# Create an IAM role for EC2 with S3 read-only permissions
aws iam create-role \
  --role-name "AppServerRole" \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam attach-role-policy \
  --role-name "AppServerRole" \
  --policy-arn "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"

# Create instance profile and attach role
aws iam create-instance-profile --instance-profile-name "AppServerProfile"
aws iam add-role-to-instance-profile \
  --instance-profile-name "AppServerProfile" \
  --role-name "AppServerRole"

# Attach to EC2 instance
aws ec2 associate-iam-instance-profile \
  --instance-id i-1234567890abcdef0 \
  --iam-instance-profile Name=AppServerProfile

# On the EC2 instance — credentials are retrieved automatically
# AWS SDK will use instance metadata service (IMDSv2)
import boto3
s3 = boto3.client('s3')  # No credentials needed! Role provides them automatically
```

**AWS: Lambda function with IAM role:**

```bash
# Lambda execution role — least privilege for the function
aws iam create-role \
  --role-name "OrderProcessorLambdaRole" \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach only necessary permissions
aws iam put-role-policy \
  --role-name "OrderProcessorLambdaRole" \
  --policy-name "OrderProcessorPolicy" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
        "Resource": "arn:aws:sqs:us-east-1:123456789012:order-queue"
      },
      {
        "Effect": "Allow",
        "Action": ["dynamodb:PutItem", "dynamodb:UpdateItem"],
        "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/Orders"
      },
      {
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "arn:aws:logs:*:*:*"
      }
    ]
  }'
```

**AWS: GitHub Actions OIDC (no static credentials in CI/CD):**

```yaml
# .github/workflows/deploy.yml
name: Deploy
on:
  push:
    branches: [main]

permissions:
  id-token: write   # Required for OIDC
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4

      - name: Configure AWS credentials (OIDC - no static keys)
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502  # v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsDeployRole
          aws-region: us-east-1
          # Credentials are temporary STS tokens — no static keys needed

      - name: Deploy
        run: aws s3 sync ./dist/ s3://my-website-bucket/
```

```bash
# Create the IAM role that GitHub Actions can assume via OIDC
aws iam create-role \
  --role-name "GitHubActionsDeployRole" \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:ref:refs/heads/main"
        }
      }
    }]
  }'
```

**Azure: Managed Identity for VMs and services:**

```bash
# Enable System-assigned Managed Identity on a VM
az vm identity assign --name myVM --resource-group myRG

# Get the Managed Identity's object ID
IDENTITY_OID=$(az vm show \
  --name myVM \
  --resource-group myRG \
  --query identity.principalId \
  --output tsv)

# Grant the VM Managed Identity access to Key Vault secrets
az keyvault set-policy \
  --name myKeyVault \
  --object-id $IDENTITY_OID \
  --secret-permissions get list

# In application code on the VM — no credentials needed
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient

credential = ManagedIdentityCredential()
client = SecretClient(vault_url="https://myKeyVault.vault.azure.net/", credential=credential)
secret = client.get_secret("database-password")
```

---

## 7. MFA Enforcement

### Technical Deep Dive

**AWS: Enforce MFA at Organization level via SCP:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyWithoutMFA",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/aws-reserved/*",
            "arn:aws:iam::*:role/OrganizationAccountAccessRole"
          ]
        }
      }
    }
  ]
}
```

**AWS: Check which IAM users don't have MFA:**

```bash
# Users with active passwords but no MFA devices
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d | \
  python3 -c "
import csv, sys
reader = csv.DictReader(sys.stdin)
for row in reader:
    if row['password_enabled'] == 'true' and row['mfa_active'] == 'false':
        print(f'⚠️  No MFA: {row[\"user\"]}')
"
```

**Azure: Require MFA via Conditional Access (recommended over per-user MFA):**

```bash
# Check current MFA status for all users (Microsoft Graph)
# PowerShell: Get-MgUser -All | Select DisplayName, UserPrincipalName | 
#   ForEach { Get-MgUserAuthenticationMethod -UserId $_.UserPrincipalName }

# CLI approach — check users with per-user MFA disabled
az ad user list --query "[].{Name:displayName,UPN:userPrincipalName}" --output table

# Best practice: Use Conditional Access "Require MFA for all users" policy
# rather than per-user MFA (easier to manage, centrally controlled)
```

---

## 8. Key Rotation and Secrets Management

### Beginner Explanation

Secrets (database passwords, API keys, certificates) must be rotated regularly and stored in a dedicated secrets manager—never in code, configuration files, or environment variables baked into container images.

### Technical Deep Dive

**AWS Secrets Manager — automatic rotation:**

```python
# Store a secret
import boto3, json

client = boto3.client('secretsmanager', region_name='us-east-1')

# Create secret
client.create_secret(
    Name='prod/myapp/database',
    Description='Production database credentials',
    SecretString=json.dumps({
        'username': 'app_user',
        'password': 'initial-password-will-be-rotated',
        'host': 'db.internal.example.com',
        'port': 5432,
        'dbname': 'production'
    }),
    Tags=[
        {'Key': 'Environment', 'Value': 'production'},
        {'Key': 'Application', 'Value': 'myapp'},
    ]
)

# Enable automatic rotation (every 30 days)
client.rotate_secret(
    SecretId='prod/myapp/database',
    RotationRules={'AutomaticallyAfterDays': 30},
    RotationLambdaARN='arn:aws:lambda:us-east-1:123456789012:function:SecretsManagerRDSRotation'
)
```

```python
# Retrieve secret in application code
import boto3, json

def get_db_credentials() -> dict:
    client = boto3.client('secretsmanager', region_name='us-east-1')
    secret_value = client.get_secret_value(SecretId='prod/myapp/database')
    return json.loads(secret_value['SecretString'])

# Usage — credentials are always fresh, never hardcoded
creds = get_db_credentials()
conn = psycopg2.connect(
    host=creds['host'],
    database=creds['dbname'],
    user=creds['username'],
    password=creds['password']
)
```

**Azure Key Vault — secrets, keys, and certificates:**

```bash
# Create Key Vault
az keyvault create \
  --name "myapp-prod-kv" \
  --resource-group "myRG" \
  --location "eastus" \
  --sku "standard" \
  --enable-purge-protection true \     # prevents permanent deletion
  --retention-days 90

# Enable soft-delete (default in newer API, but verify)
az keyvault update \
  --name "myapp-prod-kv" \
  --resource-group "myRG" \
  --enable-soft-delete true

# Store a secret
az keyvault secret set \
  --vault-name "myapp-prod-kv" \
  --name "database-password" \
  --value "$(openssl rand -base64 32)"   # random 256-bit password

# Set expiry on the secret (forces rotation review)
az keyvault secret set-attributes \
  --vault-name "myapp-prod-kv" \
  --name "database-password" \
  --expires "2025-01-01T00:00:00Z"

# Grant application access via Managed Identity
az keyvault set-policy \
  --name "myapp-prod-kv" \
  --object-id "$MANAGED_IDENTITY_OBJECT_ID" \
  --secret-permissions get  # minimum: only get, not list
```

```python
# Retrieve Azure Key Vault secret in Python
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient

def get_secret(secret_name: str) -> str:
    credential = ManagedIdentityCredential()
    client = SecretClient(
        vault_url="https://myapp-prod-kv.vault.azure.net/",
        credential=credential
    )
    return client.get_secret(secret_name).value

db_password = get_secret("database-password")
```

**Key rotation checklist:**

```
AWS Secrets Manager
  [ ] All database passwords stored in Secrets Manager
  [ ] Automatic rotation enabled (30-90 days per risk level)
  [ ] Rotation Lambda tested and verified
  [ ] Applications use GetSecretValue API (not cached env vars)
  [ ] Secrets tagged with environment and application

Azure Key Vault
  [ ] Key Vault per environment (dev, staging, prod)
  [ ] Purge protection enabled
  [ ] Access policy: applications have only 'get' permission
  [ ] Secret expiry dates set for all secrets
  [ ] Key Vault diagnostic logs enabled
  [ ] Alerts configured for expiring secrets (30 days warning)
```

### Practice Challenge

> ⚠️ **Lab Environment Only** — Create an AWS Secrets Manager secret for a simulated database password. Write a Lambda rotation function using the provided template. Enable automatic rotation. Verify your application retrieves credentials from Secrets Manager rather than environment variables. Manually trigger a rotation and verify the application continues to function.

---

## 📋 IAM Hardening Summary Checklist

```
Root / Global Admin Account
  [ ] MFA enabled on root/global admin
  [ ] Root access keys deleted (AWS)
  [ ] Root account used only for break-glass scenarios
  [ ] Break-glass procedure documented and tested

Human Access
  [ ] All humans authenticate via SSO/federation (not local IAM users)
  [ ] MFA enforced for all users via policy
  [ ] No shared accounts
  [ ] Privileged access via PIM / temporary elevation

Workload / Service Identity
  [ ] EC2/VM instances use instance profiles/Managed Identity
  [ ] Lambda/Functions use execution roles
  [ ] CI/CD uses OIDC federation (no static keys)
  [ ] No access keys stored in code, configs, or environment variables

Permissions
  [ ] No wildcard (*) action policies in production
  [ ] Access Analyzer findings reviewed and addressed
  [ ] Service-last-accessed data used to right-size permissions
  [ ] SCPs deployed as account-level guardrails (AWS)

Audit
  [ ] CloudTrail / Azure Activity Log enabled in all regions
  [ ] IAM credential report reviewed monthly
  [ ] Access keys older than 90 days alerted
  [ ] Quarterly access reviews documented
```

---

*Part of the [CyberPath Defensive Security Roadmap](../README.md)*
