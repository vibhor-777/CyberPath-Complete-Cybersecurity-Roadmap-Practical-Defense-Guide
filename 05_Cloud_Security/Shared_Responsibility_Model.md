# Cloud Shared Responsibility Model

> **Module:** [05 Cloud Security](./README.md) | **Back to root:** [Repository Root](../README.md)

The shared responsibility model defines who is responsible for securing which aspects of a cloud deployment. Misunderstanding this boundary is the root cause of many of the largest cloud breaches in history. This guide establishes clarity on what each model requires from you as the customer.

---

## Table of Contents

1. [The Model Explained](#1-the-model-explained)
2. [IaaS vs PaaS vs SaaS Responsibility Boundaries](#2-iaas-vs-paas-vs-saas-responsibility-boundaries)
3. [AWS vs Azure vs GCP Model Comparison](#3-aws-vs-azure-vs-gcp-model-comparison)
4. [Common Misconfigurations from Misunderstood Responsibility](#4-common-misconfigurations-from-misunderstood-responsibility)
5. [Real-World Examples](#5-real-world-examples)
6. [Customer Responsibility Checklist](#6-customer-responsibility-checklist)

---

## 1. The Model Explained

### Beginner Explanation

When you rent a server in a data center (colocation), you're responsible for everything: the physical hardware, the operating system, the application, and the data. When you move to the cloud, the cloud provider takes over *some* of those responsibilities—but not all of them.

Think of it like renting an apartment:
- The landlord (cloud provider) is responsible for the building's foundation, exterior walls, and plumbing.
- You (the customer) are responsible for your furniture, locking your door, and not leaving your windows open.

The cloud provider will never be responsible for your data or for how you configure access to it.

### Technical Deep Dive

The core principle: **"Security OF the cloud" vs "Security IN the cloud"**

```
┌─────────────────────────────────────────────────────────────────┐
│                    ALWAYS CUSTOMER RESPONSIBILITY               │
├─────────────────────────────────────────────────────────────────┤
│  Data classification and accountability                         │
│  Identity and access management (who gets access to your data)  │
│  Application-level security                                     │
│  Operating system patching (IaaS)                               │
│  Network and firewall configuration                             │
│  Client-side encryption                                         │
├─────────────────────────────────────────────────────────────────┤
│                    SHARED / MODEL-DEPENDENT                     │
├─────────────────────────────────────────────────────────────────┤
│  Platform OS patching        (Customer: IaaS | Provider: PaaS)  │
│  Network controls            (Customer: IaaS | Shared: PaaS)    │
│  Endpoint protection         (Customer: IaaS | Provider: SaaS)  │
├─────────────────────────────────────────────────────────────────┤
│                    ALWAYS PROVIDER RESPONSIBILITY               │
├─────────────────────────────────────────────────────────────────┤
│  Physical security of data centers                              │
│  Hypervisor and bare metal security                             │
│  Global network infrastructure                                  │
│  Storage hardware durability                                    │
│  Core cloud service availability                                │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. IaaS vs PaaS vs SaaS Responsibility Boundaries

### IaaS — Infrastructure as a Service

**Examples:** AWS EC2, Azure Virtual Machines, GCP Compute Engine

You manage everything above the hypervisor. The provider manages physical infrastructure and the hypervisor layer.

```
CUSTOMER RESPONSIBILITY (IaaS):
  ┌────────────────────────────────┐
  │ Applications                   │ ← You
  │ Runtime / middleware            │ ← You
  │ Operating system (patching!)    │ ← You
  │ Virtual networking / firewalls  │ ← You (with provider tools)
  │ Storage encryption              │ ← You (enable the feature)
  │ Data                           │ ← You
  ├────────────────────────────────┤
  │ Hypervisor                     │ ← Provider
  │ Physical servers               │ ← Provider
  │ Physical network               │ ← Provider
  │ Data center                    │ ← Provider
  └────────────────────────────────┘
```

**IaaS customer responsibilities (concrete):**

```bash
# YOUR responsibility on an EC2 instance:

# 1. OS patching — provider does NOT patch your EC2 instances
sudo yum update -y   # or apt upgrade

# 2. Configure host-based firewall (Security Groups are also your config)
sudo firewall-cmd --permanent --remove-service=telnet
sudo firewall-cmd --reload

# 3. Disable unused services
sudo systemctl disable avahi-daemon
sudo systemctl disable cups

# 4. Enable OS-level audit logging
sudo systemctl enable auditd

# 5. Install endpoint protection
# (The provider does NOT install antimalware on your EC2 instances)
sudo yum install amazon-ssm-agent   # enables patch management
```

### PaaS — Platform as a Service

**Examples:** AWS RDS, Azure App Service, Google App Engine, AWS Lambda

The provider manages the OS, runtime, and platform. You manage your application code and data.

```
CUSTOMER RESPONSIBILITY (PaaS):
  ┌────────────────────────────────┐
  │ Application code               │ ← You
  │ Application configuration      │ ← You
  │ Data                           │ ← You
  │ Access control (who uses app)  │ ← You
  │ Data encryption configuration  │ ← You (must enable)
  ├────────────────────────────────┤
  │ Runtime environment            │ ← Provider manages
  │ Operating system               │ ← Provider manages + patches
  │ Middleware / frameworks        │ ← Provider manages
  │ Physical infrastructure        │ ← Provider manages
  └────────────────────────────────┘
```

**Critical PaaS customer gap:** Encryption at rest for managed databases is often **not enabled by default**. You must explicitly enable it.

```bash
# AWS RDS — verify encryption is enabled (customer must configure)
aws rds describe-db-instances \
  --query 'DBInstances[*].{ID:DBInstanceIdentifier,Encrypted:StorageEncrypted}' \
  --output table

# Azure SQL Database — check Transparent Data Encryption status
az sql db show \
  --name mydb \
  --resource-group myRG \
  --server mysqlserver \
  --query transparentDataEncryption
```

### SaaS — Software as a Service

**Examples:** Microsoft 365, Salesforce, Google Workspace, Slack

The provider manages almost everything. You manage data, user access, and configuration.

```
CUSTOMER RESPONSIBILITY (SaaS):
  ┌────────────────────────────────┐
  │ Data (what you put in the app) │ ← You
  │ User accounts and access       │ ← You
  │ Application configuration      │ ← You (sharing settings, etc.)
  │ Compliance for your data       │ ← You
  ├────────────────────────────────┤
  │ Application security           │ ← Provider (but you config)
  │ Platform, OS, infrastructure   │ ← Provider
  └────────────────────────────────┘
```

**Critical SaaS customer gap:** Default sharing settings in SaaS applications are often permissive. The provider secures the platform; **you are responsible for what you share with whom**.

```
Example: Microsoft SharePoint default "Anyone with the link" sharing
→ Enabled by default in many tenants
→ Customer must disable at tenant level:
   Admin Center → SharePoint → Policies → Sharing → Most restrictive setting
```

---

## 3. AWS vs Azure vs GCP Model Comparison

### Technical Deep Dive

All three major providers follow the same conceptual model but express it differently in documentation and tooling.

**Responsibility matrix comparison:**

| Control | AWS | Azure | GCP |
|---------|-----|-------|-----|
| Physical security | AWS | Microsoft | Google |
| Hypervisor | AWS | Microsoft | Google |
| Guest OS (EC2/VM) | **Customer** | **Customer** | **Customer** |
| Guest OS (managed, e.g., RDS) | AWS | Microsoft | Google |
| Network controls | **Customer** (VPC/SG) | **Customer** (NSG/VNet) | **Customer** (VPC/Firewall) |
| Data encryption at rest | **Customer** (must enable) | **Customer** (must enable) | **Customer** (must enable) |
| Data encryption in transit | **Shared** | **Shared** | **Shared** |
| IAM configuration | **Customer** | **Customer** | **Customer** |
| Patch management (EC2) | **Customer** | **Customer** | **Customer** |
| Compliance certification | **Shared** | **Shared** | **Shared** |

**Key difference — encryption defaults:**

```
AWS S3: Server-side encryption
  Default (January 2023): SSE-S3 enabled by default for all new objects
  (AWS announcement: https://aws.amazon.com/about-aws/whats-new/2023/01/amazon-s3-automatically-encrypts-new-objects/)
  But: bucket policies, ACLs, and public access → still customer's responsibility

Azure Blob Storage:
  Encryption at rest: Always on (Azure-managed keys)
  But: customer-managed keys, access policies → customer's responsibility

GCP Cloud Storage:
  Encryption at rest: Always on (Google-managed keys)
  But: CMEK, IAM policies → customer's responsibility
```

**AWS Shared Responsibility (official summary):**

```
AWS responsible for:
  Compute, Storage, Database, Networking hardware
  AWS global infrastructure (regions, AZs, edge locations)

Customer responsible for:
  Data (encryption, integrity, access control)
  Platform, applications, IAM
  OS, network, firewall configuration
  Client-side and server-side encryption
  Network traffic protection
```

---

## 4. Common Misconfigurations from Misunderstood Responsibility

### Beginner Explanation

The most common cloud security failures happen when customers assume the provider has taken care of something that is actually the customer's responsibility.

### Technical Deep Dive

**Misconfiguration 1: Assuming provider handles OS patching**

```bash
# EC2 instances without Systems Manager Patch Manager
# → OS vulnerabilities accumulate for months/years

# Detection: Find EC2 instances without SSM agent or outdated patches
aws ssm describe-instance-patch-states \
  --query 'InstancePatchStates[?MissingCount>`0`].[InstanceId,MissingCount,InstalledRejectedCount]' \
  --output table

# Remediation: Enable automatic patching
aws ssm create-patch-baseline \
  --name "ProductionLinuxBaseline" \
  --operating-system "AMAZON_LINUX_2" \
  --approval-rules "PatchRules=[{PatchFilterGroup:{PatchFilters=[{Key=SEVERITY,Values=[Critical,High]}]},ApproveAfterDays=3}]"
```

**Misconfiguration 2: Public S3 buckets**

```bash
# Customer responsibility: configure bucket access correctly
# Provider responsibility: offer the controls (they do)

# The infamous "public bucket" pattern
# Customers disabled Block Public Access or set ACL to public-read

# Detection: Find all public S3 buckets in account
aws s3api list-buckets --query 'Buckets[*].Name' --output text | tr '\t' '\n' | \
  while read bucket; do
    public=$(aws s3api get-bucket-policy-status --bucket "$bucket" \
      --query 'PolicyStatus.IsPublic' --output text 2>/dev/null)
    if [ "$public" = "True" ]; then
      echo "PUBLIC BUCKET: $bucket"
    fi
  done

# Remediation: Enable Block Public Access at account level
aws s3control put-public-access-block \
  --account-id "$(aws sts get-caller-identity --query Account --output text)" \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

**Misconfiguration 3: Network Security Groups too permissive (Azure)**

```bash
# Customer must configure NSGs — provider does not restrict by default

# Detection: Find NSG rules allowing 0.0.0.0/0 inbound on sensitive ports
az network nsg list --query '[].name' -o tsv | while read nsg; do
  az network nsg rule list --nsg-name "$nsg" \
    --resource-group "$(az network nsg show --name $nsg --query resourceGroup -o tsv)" \
    --query "[?sourceAddressPrefix=='*' && access=='Allow'].{NSG:'$nsg',Port:destinationPortRange,Direction:direction}" \
    -o table
done
```

**Misconfiguration 4: Overly permissive IAM (customer's responsibility in all models)**

```json
// ❌ DANGEROUS — this policy is 100% customer's fault, not the provider's
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
// A valid IAM policy that AWS will happily apply — but you created it
// The provider cannot know what permissions your application legitimately needs
```

---

## 5. Real-World Examples

### S3 Bucket Exposure Incidents

**Capital One (2019):**
- **What happened:** An EC2 instance with an overly permissive IAM role was exploited via SSRF. The IAM role had `s3:GetObject` on essentially all S3 buckets in the account.
- **Shared responsibility breakdown:** AWS provided the IAM system. Capital One misconfigured the IAM role (customer responsibility) and failed to restrict SSRF via WAF (customer responsibility). AWS's infrastructure was secure.
- **Scale:** 100 million+ customer records.

**Twitch (2021):**
- **What happened:** A misconfigured server exposed the Git repository including source code and creator earnings. Attributed to a server misconfiguration.
- **Shared responsibility:** Server configuration is customer responsibility regardless of cloud provider.

**Power Apps / Microsoft (2021):**
- **What happened:** Default table permissions in Microsoft Dataverse (a SaaS/PaaS product) exposed data publicly unless explicitly changed. NHS contact tracing data, American Airlines employee data, and Indiana voter records were among 38 million exposed records.
- **Shared responsibility breakdown:** Microsoft's default was permissive (provider design decision). Customers were responsible for reviewing and changing defaults but many didn't know about the risk.
- **Lesson:** Even when SaaS providers manage the platform, customers must understand and actively configure security settings.

### Azure Misconfiguration Incidents

**Exposed Azure Blob Storage (multiple incidents):**
```
Organizations repeatedly expose sensitive data via Azure Blob Storage containers
with public access enabled. This requires:
  1. Customer to either: set container access to "Blob" or "Container"
  2. OR fail to restrict via Azure Policy

Azure provides: the storage service and access control mechanisms
Customer provides: the configuration

Detection using Azure CLI:
```

```bash
# Find public Blob containers in a storage account
az storage container list \
  --account-name mystorageaccount \
  --query "[?properties.publicAccess!='None'].{Name:name,Access:properties.publicAccess}" \
  --output table

# Remediation: Disable public access at storage account level
az storage account update \
  --name mystorageaccount \
  --resource-group myRG \
  --allow-blob-public-access false
```

### GCP Misconfiguration Examples

**Cloud Storage buckets with allUsers or allAuthenticatedUsers:**

```bash
# Detection: Find GCS buckets with public IAM bindings
gsutil iam get gs://my-bucket | \
  python3 -c "
import json, sys
policy = json.load(sys.stdin)
for binding in policy.get('bindings', []):
    if 'allUsers' in binding.get('members', []) or \
       'allAuthenticatedUsers' in binding.get('members', []):
        print(f'PUBLIC ACCESS: {binding}')
"

# Remediation: Remove public bindings
gsutil iam ch -d allUsers gs://my-bucket
gsutil iam ch -d allAuthenticatedUsers gs://my-bucket
```

### Lessons Learned

| Incident | Provider's Fault? | Customer's Fault? | Lesson |
|----------|------------------|-------------------|--------|
| Capital One SSRF + S3 | No | Yes (IAM + WAF) | Least privilege IAM + WAF configuration |
| Power Apps defaults | Partially (poor default) | Partially (unchecked) | Review all default settings on new services |
| Public S3 buckets | No | Yes | Enable Block Public Access at account level |
| Unpatched EC2 | No | Yes | Automate patching; provider won't do it for you |

---

## 6. Customer Responsibility Checklist

Use this checklist to audit your cloud environment against common responsibility gaps.

### Identity and Access Management *(Always Customer)*

```
[ ] No root/global administrator accounts used for day-to-day operations
[ ] MFA enabled for all human IAM users/accounts
[ ] MFA enforced via policy (not just recommended)
[ ] No long-lived access keys for human users
[ ] IAM policies follow Principle of Least Privilege
[ ] No wildcard (*) actions in production IAM policies
[ ] Service accounts/roles have minimal required permissions
[ ] IAM access reviewed quarterly (access reviews)
[ ] Privileged access via time-limited elevation (PIM/AWS IAM Identity Center)
```

### Data Protection *(Always Customer)*

```
[ ] All data classified by sensitivity level
[ ] Encryption at rest enabled for all storage (S3, RDS, Blob, etc.)
[ ] Customer-managed keys used for sensitive data (CMK/BYOK)
[ ] Encryption in transit enforced (TLS 1.2+ minimum, TLS 1.3 preferred)
[ ] Backup encryption enabled
[ ] Data retention policies defined and enforced
[ ] Data deletion verified when resources are destroyed
```

### Network Configuration *(Always Customer for IaaS)*

```
[ ] No security groups/NSGs allowing 0.0.0.0/0 to port 22 or 3389
[ ] VPC/VNet flow logs enabled
[ ] Network segmentation: production isolated from dev/test
[ ] Private endpoints used for managed services where available
[ ] Egress filtering to restrict outbound traffic
[ ] NAT Gateway instead of public IP for application servers
```

### Compute / OS *(Customer for IaaS)*

```
[ ] Automated patch management enabled (SSM Patch Manager / Azure Automation)
[ ] No public IP addresses on instances that don't require them
[ ] Host-based firewall enabled
[ ] No default credentials on any service
[ ] Unused ports/services disabled
[ ] IMDSv2 enforced on EC2 instances (AWS)
[ ] Endpoint protection (EDR) installed on all instances
```

### Logging and Monitoring *(Always Customer)*

```
[ ] CloudTrail / Azure Activity Log / GCP Audit Logs enabled in all regions
[ ] Logs shipped to immutable storage (S3 with Object Lock / Immutable Blob)
[ ] Log retention meets compliance requirements (minimum 12 months)
[ ] Threat detection enabled (GuardDuty / Defender for Cloud / Security Command Center)
[ ] Alerts configured for critical events (root login, IAM changes, policy changes)
[ ] Security findings reviewed weekly minimum
```

### SaaS-Specific *(Customer Configuration)*

```
[ ] Default sharing settings reviewed and restricted
[ ] External sharing disabled or explicitly controlled
[ ] User provisioning and deprovisioning process defined
[ ] Admin accounts inventoried and MFA enforced
[ ] Audit logs for admin actions enabled
[ ] Third-party app integrations reviewed and limited
[ ] Data loss prevention (DLP) policies configured
```

### Practice Challenge

> Audit a cloud account (lab/sandbox only) using Prowler or ScoutSuite. Map each finding to the shared responsibility model. Identify which findings represent a customer misconfiguration vs a provider limitation. Remediate the top 5 findings and re-run the tool to verify.

```bash
# Prowler — comprehensive AWS security audit
pip install prowler
prowler aws --region us-east-1 \
  --compliance cis_aws_benchmark_level_1 \
  --output-formats html json

# ScoutSuite — multi-cloud audit
pip install scoutsuite
scout aws --report-dir ./scout-report

# Review the generated HTML report for shared responsibility violations
```

---

*Part of the [CyberPath Defensive Security Roadmap](../README.md)*
