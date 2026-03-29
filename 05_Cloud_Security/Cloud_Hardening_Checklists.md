# Cloud Hardening Checklists — AWS and Azure

> **Module:** [05 Cloud Security](./README.md) | **Back to root:** [Repository Root](../README.md)

This guide provides actionable hardening checklists and technical implementation guidance for AWS and Azure environments, grounded in the CIS Benchmarks, AWS Security Hub, and Azure Defender for Cloud. Every control includes the CLI command or configuration needed to implement it.

---

## Table of Contents

1. [AWS Security Hub and Azure Defender for Cloud Overview](#1-aws-security-hub-and-azure-defender-for-cloud-overview)
2. [CIS Benchmark for AWS and Azure](#2-cis-benchmark-for-aws-and-azure)
3. [S3 Bucket Security](#3-s3-bucket-security)
4. [VPC Security Groups and NACLs](#4-vpc-security-groups-and-nacls)
5. [CloudTrail and GuardDuty Setup](#5-cloudtrail-and-guardduty-setup)
6. [Azure Policy and Defender for Cloud](#6-azure-policy-and-defender-for-cloud)

---

## 1. AWS Security Hub and Azure Defender for Cloud Overview

### Beginner Explanation

Both AWS and Azure provide built-in security posture management tools that continuously assess your environment against security best practices. These tools aggregate findings from multiple security services into a single dashboard and map controls to compliance frameworks like CIS Benchmarks, PCI DSS, and SOC 2.

### Technical Deep Dive

**AWS Security Hub:**

```bash
# Enable Security Hub in a region
aws securityhub enable-security-hub \
  --enable-default-standards \
  --region us-east-1

# Enable specific security standards
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
    StandardsArn=arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0 \
    StandardsArn=arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0

# List failed controls
aws securityhub get-findings \
  --filters '{
    "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}]
  }' \
  --sort-criteria '[{"Field": "SeverityNormalized", "SortOrder": "desc"}]' \
  --query 'Findings[*].{Title:Title,Severity:Severity.Label,Resource:Resources[0].Id}' \
  --output table | head -50

# Enable Security Hub across all accounts in an Organization
aws securityhub enable-organization-admin-account \
  --admin-account-id "123456789012"
```

**Security Hub findings summary:**

```bash
# Get count of findings by severity
aws securityhub get-findings \
  --filters '{"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}' \
  --query 'Findings[*].Severity.Label' \
  --output text | tr '\t' '\n' | sort | uniq -c | sort -rn
```

**AWS Security Hub integrations:**

| Service | What it contributes |
|---------|---------------------|
| AWS Config | Configuration compliance findings |
| Amazon GuardDuty | Threat detection findings |
| Amazon Macie | S3 sensitive data findings |
| AWS IAM Access Analyzer | External access findings |
| Amazon Inspector | Vulnerability findings (EC2, containers, Lambda) |
| AWS Firewall Manager | Firewall policy compliance |

**Azure Defender for Cloud (formerly Security Center):**

```bash
# Enable Defender for Cloud plans
az security pricing create \
  --name "VirtualMachines" \
  --tier "Standard"   # P2 / Standard = paid Defender for Servers

az security pricing create \
  --name "StorageAccounts" \
  --tier "Standard"

az security pricing create \
  --name "SqlServers" \
  --tier "Standard"

az security pricing create \
  --name "AppServices" \
  --tier "Standard"

az security pricing create \
  --name "KeyVaults" \
  --tier "Standard"

# Get Secure Score
az security secure-score-controls list \
  --query "[].{Control:displayName,Score:score.current,Max:score.max,Unhealthy:unhealthyResourceCount}" \
  --output table | sort -t'|' -k3 -rn

# List recommendations by severity
az security task list \
  --query "[?state=='Active'].{Recommendation:name,Severity:securityTaskParameters.severity,Resource:resourceDetails.resourceName}" \
  --output table
```

**Real-World Relevance:**

Security Hub and Defender for Cloud implement continuous compliance monitoring—the alternative is manual, periodic audits that leave gaps between checks. CIS Benchmark compliance checks run continuously and alert on drift within minutes of a misconfiguration occurring.

---

## 2. CIS Benchmark for AWS and Azure

### Beginner Explanation

The Center for Internet Security (CIS) Benchmarks are industry-accepted configuration standards developed by security experts. CIS provides two levels:
- **Level 1:** Foundational security. Low operational impact. Implement these everywhere.
- **Level 2:** Defense-in-depth. May impact performance or usability. Apply to sensitive environments.

### Technical Deep Dive

**Running CIS Benchmark scan with Prowler (AWS):**

```bash
# Install Prowler
pip install prowler

# Run full CIS Level 1 scan
prowler aws \
  --compliance cis_aws_benchmark_level_1 \
  --region us-east-1 \
  --output-formats html json \
  --output-directory ./prowler-reports

# Run CIS Level 2 (includes Level 1)
prowler aws \
  --compliance cis_aws_benchmark_level_2 \
  --output-formats html json

# Run a specific check
prowler aws --check cis_1_1   # 1.1: Root account hardware MFA

# Run checks for a specific service
prowler aws --service iam s3 cloudtrail
```

**Key CIS AWS Level 1 Controls (abbreviated):**

| CIS ID | Control | CLI Check |
|--------|---------|-----------|
| 1.1 | Maintain current contact details | Manual |
| 1.4 | No root access keys | `aws iam get-account-summary` |
| 1.5 | MFA for root account | Credential report |
| 1.14 | Access keys rotated every 90 days | Credential report |
| 2.1.1 | S3 Block Public Access (account level) | `aws s3control get-public-access-block` |
| 2.2.1 | EBS volumes encrypted by default | `aws ec2 get-ebs-encryption-by-default` |
| 3.1 | CloudTrail enabled in all regions | `aws cloudtrail describe-trails` |
| 3.2 | CloudTrail log file validation enabled | Trail configuration |
| 3.3 | CloudTrail S3 bucket not publicly accessible | Bucket ACL check |
| 4.1 | No unrestricted SSH (port 22 from 0.0.0.0/0) | Security Group check |
| 4.2 | No unrestricted RDP (port 3389 from 0.0.0.0/0) | Security Group check |

```bash
# Implement CIS 1.4 — Delete root access keys
aws iam list-access-keys --user-name root
# Should return empty. If not:
aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE

# Implement CIS 2.2.1 — EBS default encryption
aws ec2 enable-ebs-encryption-by-default --region us-east-1
aws ec2 get-ebs-encryption-by-default --region us-east-1
# Output: {"EbsEncryptionByDefault": true}

# Implement CIS 4.1 — Find security groups allowing 0.0.0.0/0 on port 22
aws ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?FromPort==`22` && IpRanges[?CidrIp==`0.0.0.0/0`]]].{ID:GroupId,Name:GroupName,VPC:VpcId}' \
  --output table
```

**Running CIS Benchmark scan with Prowler (Azure):**

```bash
# Prowler supports Azure as well
prowler azure \
  --compliance cis_azure_benchmark_level_1 \
  --subscription-ids "your-subscription-id" \
  --output-formats html json

# Key CIS Azure Level 1 Controls:
# 1.1.1  — Ensure Security Defaults are enabled
# 1.2.2  — Ensure MFA for all privileged users
# 3.1    — Ensure Storage accounts secure transfer required
# 3.7    — Ensure storage account public access disabled
# 4.1.x  — SQL Server security (auditing, TDE, firewall)
# 5.1.x  — Logging (Diagnostic settings, Activity Log)
# 6.x    — Networking (NSG, Network Watcher)
# 7.x    — VMs (antimalware, disk encryption, patching)
```

---

## 3. S3 Bucket Security

### Beginner Explanation

S3 buckets are one of the most commonly misconfigured cloud resources. A single misconfigured bucket can expose millions of records to the public internet. Multiple layers of protection exist—you should enable all of them.

### Technical Deep Dive

**Block Public Access (account-level — the most important control):**

```bash
# Enable Block Public Access for the entire AWS account
# This overrides any bucket-level settings that might allow public access
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

aws s3control put-public-access-block \
  --account-id "$ACCOUNT_ID" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Verify
aws s3control get-public-access-block --account-id "$ACCOUNT_ID"
```

**Per-bucket hardening:**

```bash
BUCKET="my-sensitive-bucket"
REGION="us-east-1"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# 1. Block Public Access at bucket level
aws s3api put-public-access-block \
  --bucket "$BUCKET" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# 2. Enable Server-Side Encryption (SSE-S3 minimum, SSE-KMS for sensitive data)
aws s3api put-bucket-encryption \
  --bucket "$BUCKET" \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:us-east-1:'"$ACCOUNT_ID"':alias/s3-sensitive-data"
      },
      "BucketKeyEnabled": true
    }]
  }'

# 3. Enable versioning (protects against accidental deletion)
aws s3api put-bucket-versioning \
  --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled

# 4. Enable Object Lock (immutable storage for compliance/forensics logs)
# Note: Must be enabled at bucket creation time
aws s3api create-bucket \
  --bucket "immutable-logs-bucket" \
  --region "$REGION" \
  --object-lock-enabled-for-bucket

aws s3api put-object-lock-configuration \
  --bucket "immutable-logs-bucket" \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "GOVERNANCE",
        "Days": 365
      }
    }
  }'

# 5. Enable server access logging
aws s3api put-bucket-logging \
  --bucket "$BUCKET" \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "s3-access-logs-bucket",
      "TargetPrefix": "'"$BUCKET"'/"
    }
  }'

# 6. Block HTTP (require HTTPS)
aws s3api put-bucket-policy \
  --bucket "$BUCKET" \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "DenyHTTP",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::'"$BUCKET"'", "arn:aws:s3:::'"$BUCKET"'/*"],
      "Condition": {
        "Bool": {"aws:SecureTransport": "false"}
      }
    }]
  }'
```

**S3 Bucket Policy — least privilege access:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAppReadAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/AppServerRole"
      },
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::my-sensitive-bucket/app-data/*"
    },
    {
      "Sid": "AllowBackupWrite",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/BackupRole"
      },
      "Action": ["s3:PutObject"],
      "Resource": "arn:aws:s3:::my-sensitive-bucket/backups/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-server-side-encryption": "aws:kms"
        }
      }
    },
    {
      "Sid": "DenyUnencryptedUploads",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-sensitive-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "aws:kms"
        }
      }
    }
  ]
}
```

**Automated S3 compliance scanning:**

```bash
# AWS Config rule — detect public buckets
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "s3-bucket-public-read-prohibited",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
}'

# AWS Config rules to enable for S3:
RULES=(
  "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  "S3_BUCKET_SSL_REQUESTS_ONLY"
  "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  "S3_BUCKET_VERSIONING_ENABLED"
  "S3_BUCKET_LOGGING_ENABLED"
)

for rule in "${RULES[@]}"; do
  aws configservice put-config-rule --config-rule "{
    \"ConfigRuleName\": \"$(echo $rule | tr '[:upper:]' '[:lower:]' | tr '_' '-')\",
    \"Source\": {\"Owner\": \"AWS\", \"SourceIdentifier\": \"$rule\"}
  }"
  echo "Enabled: $rule"
done
```

**Amazon Macie — sensitive data discovery in S3:**

```bash
# Enable Macie
aws macie2 enable-macie --region us-east-1

# Create a classification job to scan for PII and sensitive data
aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --name "PII-Discovery-AllBuckets" \
  --s3-job-definition '{
    "bucketDefinitions": [{
      "accountId": "123456789012",
      "buckets": ["*"]
    }]
  }' \
  --managed-data-identifier-ids \
    "CREDIT_CARD_NUMBER" \
    "AWS_CREDENTIALS" \
    "US_SOCIAL_SECURITY_NUMBER" \
    "EMAIL_ADDRESS"
```

### Practice Challenge

> ⚠️ **Lab Environment Only** — Create a new S3 bucket in your sandbox account. Apply all hardening controls above. Use Prowler or AWS Config to verify compliance. Upload a test file via HTTP (should fail). Upload without KMS encryption (should fail). Verify versioning is active by uploading and deleting a file, then restoring it.

---

## 4. VPC Security Groups and NACLs

### Beginner Explanation

Security Groups (SGs) are stateful firewalls at the instance level. Network Access Control Lists (NACLs) are stateless firewalls at the subnet level. Together they form the network security perimeter for your AWS resources.

### Technical Deep Dive

**Security Group vs NACL comparison:**

| Feature | Security Group | NACL |
|---------|---------------|------|
| Level | Instance/ENI | Subnet |
| State | Stateful (return traffic automatic) | Stateless (must allow return traffic) |
| Rules | Allow only | Allow and Deny |
| Rule evaluation | All rules evaluated | Rules evaluated in order (lowest number first) |
| Default behavior | Deny all inbound, allow all outbound | Allow all inbound and outbound |

**Security Group hardening:**

```bash
# Find overly permissive security groups (0.0.0.0/0 on sensitive ports)
aws ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`] || Ipv6Ranges[?CidrIpv6==`::/0`]]].{ID:GroupId,Name:GroupName,Rules:IpPermissions}' \
  --output json | python3 -c "
import json, sys
sgs = json.load(sys.stdin)
dangerous_ports = {22, 3389, 1433, 3306, 5432, 6379, 27017, 9200}
for sg in sgs:
    for rule in sg.get('Rules', []):
        from_port = rule.get('FromPort', 0)
        to_port = rule.get('ToPort', 65535)
        for port in dangerous_ports:
            if from_port <= port <= to_port:
                print(f'⚠️  {sg[\"Name\"]} ({sg[\"ID\"]}): Port {port} open to world')
"

# Remediate: remove a specific overly-permissive rule
aws ec2 revoke-security-group-ingress \
  --group-id sg-12345678 \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Replace with access only from specific CIDR (your corporate VPN)
aws ec2 authorize-security-group-ingress \
  --group-id sg-12345678 \
  --protocol tcp \
  --port 22 \
  --cidr 10.0.0.0/8 \
  --tag-specifications 'ResourceType=security-group-rule,Tags=[{Key=Description,Value=Corporate VPN SSH access}]'
```

**Reference security group architecture (three-tier):**

```bash
# Create security groups for a three-tier architecture
VPC_ID="vpc-12345678"

# 1. Load Balancer SG — public-facing
ALB_SG=$(aws ec2 create-security-group \
  --group-name "alb-sg" \
  --description "ALB: HTTPS only from internet" \
  --vpc-id "$VPC_ID" \
  --query 'GroupId' --output text)

aws ec2 authorize-security-group-ingress \
  --group-id "$ALB_SG" \
  --protocol tcp --port 443 --cidr 0.0.0.0/0

# 2. App Server SG — only from ALB
APP_SG=$(aws ec2 create-security-group \
  --group-name "app-sg" \
  --description "App servers: only from ALB" \
  --vpc-id "$VPC_ID" \
  --query 'GroupId' --output text)

aws ec2 authorize-security-group-ingress \
  --group-id "$APP_SG" \
  --protocol tcp --port 8080 \
  --source-group "$ALB_SG"   # only allow traffic from the ALB SG

# 3. Database SG — only from App servers
DB_SG=$(aws ec2 create-security-group \
  --group-name "db-sg" \
  --description "Database: only from app servers" \
  --vpc-id "$VPC_ID" \
  --query 'GroupId' --output text)

aws ec2 authorize-security-group-ingress \
  --group-id "$DB_SG" \
  --protocol tcp --port 5432 \
  --source-group "$APP_SG"   # only allow from app servers

echo "ALB SG: $ALB_SG | App SG: $APP_SG | DB SG: $DB_SG"
```

**NACL hardening (defense-in-depth layer):**

```bash
# Create a restrictive NACL for the private (database) subnet
NACL_ID=$(aws ec2 create-network-acl \
  --vpc-id "$VPC_ID" \
  --tag-specifications 'ResourceType=network-acl,Tags=[{Key=Name,Value=private-subnet-nacl}]' \
  --query 'NetworkAcl.NetworkAclId' \
  --output text)

# Inbound: Allow PostgreSQL only from app subnet CIDR
aws ec2 create-network-acl-entry \
  --network-acl-id "$NACL_ID" \
  --rule-number 100 \
  --protocol tcp \
  --port-range From=5432,To=5432 \
  --cidr-block "10.0.10.0/24" \   # app subnet CIDR
  --rule-action allow \
  --ingress

# Inbound: Allow ephemeral return traffic
aws ec2 create-network-acl-entry \
  --network-acl-id "$NACL_ID" \
  --rule-number 200 \
  --protocol tcp \
  --port-range From=1024,To=65535 \
  --cidr-block "0.0.0.0/0" \
  --rule-action allow \
  --ingress

# Inbound: Deny everything else (catch-all)
aws ec2 create-network-acl-entry \
  --network-acl-id "$NACL_ID" \
  --rule-number 32766 \
  --protocol -1 \
  --cidr-block "0.0.0.0/0" \
  --rule-action deny \
  --ingress

# Enable VPC Flow Logs
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids "$VPC_ID" \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name "/aws/vpc/flowlogs" \
  --deliver-logs-permission-arn "arn:aws:iam::123456789012:role/VPCFlowLogsRole"
```

**Analyzing VPC Flow Logs for suspicious traffic:**

```bash
# Athena query — find rejected connections (potential port scans)
# (After setting up Flow Logs in S3 with Athena table)
cat << 'EOF'
SELECT
  srcaddr,
  dstport,
  COUNT(*) as rejected_count
FROM vpc_flow_logs
WHERE action = 'REJECT'
  AND start > to_unixtime(current_timestamp - interval '1' hour)
GROUP BY srcaddr, dstport
HAVING COUNT(*) > 100
ORDER BY rejected_count DESC
LIMIT 20;
EOF
```

### Practice Challenge

> Create a three-tier VPC architecture (ALB → App → DB) with security groups following the reference architecture above. Enable VPC Flow Logs. Use Prowler to check for unrestricted security group rules. Verify that attempting to connect directly to the database security group from the internet is blocked.

---

## 5. CloudTrail and GuardDuty Setup

### Beginner Explanation

CloudTrail logs every API call made in your AWS account—who did what, when, and from where. GuardDuty analyzes CloudTrail logs, VPC Flow Logs, and DNS logs using machine learning and threat intelligence to detect malicious activity automatically.

### Technical Deep Dive

**CloudTrail — complete setup:**

```bash
# Create an S3 bucket for CloudTrail logs with security hardening
TRAIL_BUCKET="cloudtrail-logs-$(aws sts get-caller-identity --query Account --output text)-$(date +%s)"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Create bucket with versioning and encryption
aws s3api create-bucket \
  --bucket "$TRAIL_BUCKET" \
  --region us-east-1

aws s3api put-bucket-versioning \
  --bucket "$TRAIL_BUCKET" \
  --versioning-configuration Status=Enabled

aws s3api put-bucket-encryption \
  --bucket "$TRAIL_BUCKET" \
  --server-side-encryption-configuration '{
    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
  }'

# Block public access on the trail bucket
aws s3api put-public-access-block \
  --bucket "$TRAIL_BUCKET" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Bucket policy — allow CloudTrail to write, deny HTTP
aws s3api put-bucket-policy --bucket "$TRAIL_BUCKET" --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::'"$TRAIL_BUCKET"'"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::'"$TRAIL_BUCKET"'/AWSLogs/'"$ACCOUNT_ID"'/*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
    },
    {
      "Sid": "DenyHTTP",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::'"$TRAIL_BUCKET"'", "arn:aws:s3:::'"$TRAIL_BUCKET"'/*"],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    }
  ]
}'

# Create multi-region trail with all features enabled
aws cloudtrail create-trail \
  --name "SecurityAuditTrail" \
  --s3-bucket-name "$TRAIL_BUCKET" \
  --include-global-service-events \
  --is-multi-region-trail \
  --enable-log-file-validation

aws cloudtrail start-logging --name "SecurityAuditTrail"

# Enable CloudWatch Logs integration for real-time alerting
aws cloudtrail update-trail \
  --name "SecurityAuditTrail" \
  --cloud-watch-logs-log-group-arn "arn:aws:logs:us-east-1:$ACCOUNT_ID:log-group:CloudTrailLogs:*" \
  --cloud-watch-logs-role-arn "arn:aws:iam::$ACCOUNT_ID:role/CloudTrailCloudWatchLogsRole"

# Enable Management Events (write), Data Events (S3), and Insights
aws cloudtrail put-event-selectors \
  --trail-name "SecurityAuditTrail" \
  --event-selectors '[
    {
      "ReadWriteType": "All",
      "IncludeManagementEvents": true,
      "DataResources": [
        {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::"]},
        {"Type": "AWS::Lambda::Function", "Values": ["arn:aws:lambda"]}
      ]
    }
  ]'
```

**CloudTrail metric filters and alarms (CIS Benchmark requirements):**

```bash
LOG_GROUP="CloudTrailLogs"
SNS_TOPIC_ARN="arn:aws:sns:us-east-1:$ACCOUNT_ID:security-alerts"

# Function to create metric filter + alarm
create_security_alarm() {
  local NAME="$1"
  local PATTERN="$2"
  local DESCRIPTION="$3"
  
  aws logs put-metric-filter \
    --log-group-name "$LOG_GROUP" \
    --filter-name "$NAME" \
    --filter-pattern "$PATTERN" \
    --metric-transformations \
      "metricName=$NAME,metricNamespace=CloudTrailMetrics,metricValue=1"
  
  aws cloudwatch put-metric-alarm \
    --alarm-name "$NAME-Alarm" \
    --alarm-description "$DESCRIPTION" \
    --metric-name "$NAME" \
    --namespace "CloudTrailMetrics" \
    --statistic Sum \
    --period 300 \
    --threshold 1 \
    --comparison-operator GreaterThanOrEqualToThreshold \
    --evaluation-periods 1 \
    --alarm-actions "$SNS_TOPIC_ARN" \
    --treat-missing-data notBreaching
}

# CIS 4.1 — Root account usage
create_security_alarm \
  "RootAccountUsage" \
  '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }' \
  "Alert: Root account was used"

# CIS 4.4 — IAM policy changes
create_security_alarm \
  "IAMPolicyChanges" \
  '{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=SetDefaultPolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}' \
  "Alert: IAM policy was modified"

# CIS 4.5 — CloudTrail configuration changes
create_security_alarm \
  "CloudTrailChanges" \
  '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }' \
  "Alert: CloudTrail was modified"

# CIS 4.13 — Security group changes
create_security_alarm \
  "SecurityGroupChanges" \
  '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }' \
  "Alert: Security group was modified"

# Console login without MFA
create_security_alarm \
  "ConsoleSignInWithoutMFA" \
  '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }' \
  "Alert: Console login without MFA"
```

**GuardDuty — enable and configure:**

```bash
# Enable GuardDuty in a region
DETECTOR_ID=$(aws guardduty create-detector \
  --enable \
  --data-sources '{
    "S3Logs": {"Enable": true},
    "EKSAuditLogs": {"Enable": true},
    "MalwareProtection": {"ScanEc2InstanceWithFindings": {"EbsVolumes": true}},
    "RDSLoginEvents": {"Enable": true},
    "RuntimeMonitoring": {"RuntimeConfigurationUpdate": {"AutoEnable": "NONE"}}
  }' \
  --query 'DetectorId' --output text)

echo "GuardDuty Detector ID: $DETECTOR_ID"

# Enable GuardDuty across all Organization accounts (from management account)
aws guardduty create-members \
  --detector-id "$DETECTOR_ID" \
  --account-details "[{\"AccountId\": \"111111111111\", \"Email\": \"account1@example.com\"}]"

aws guardduty enable-organization-admin-account --admin-account-id "$ACCOUNT_ID"

# List active findings
aws guardduty list-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-criteria '{
    "Criterion": {
      "severity": {"Gte": 7},
      "service.archived": {"Eq": ["false"]}
    }
  }' \
  --query 'FindingIds' --output text | \
  xargs -I{} aws guardduty get-findings \
    --detector-id "$DETECTOR_ID" \
    --finding-ids "{}" \
    --query 'Findings[*].{Title:Title,Severity:Severity,Type:Type,Account:AccountId}' \
    --output table
```

**GuardDuty finding types to monitor:**

| Finding Category | Key Finding Types |
|-----------------|-----------------|
| Credential compromise | UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B, CredentialAccess:IAMUser/AnomalousBehavior |
| EC2 instance | Backdoor:EC2/XORDDOS, Trojan:EC2/BlackholeTraffic, CryptoCurrency:EC2/BitcoinTool.B |
| Privilege escalation | PrivilegeEscalation:IAMUser/AdministrativePermissions |
| Data exfiltration | Exfiltration:S3/ObjectRead.Unusual, Exfiltration:IAMUser/AnomalousBehavior |
| Reconnaissance | Recon:EC2/PortProbeUnprotectedPort, Recon:IAMUser/MaliciousIPCaller |

**Automated GuardDuty response with EventBridge:**

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "severity": [{"numeric": [">=", 7]}]
  }
}
```

```python
# Lambda function triggered by EventBridge for high-severity GuardDuty findings
import boto3, json, os

def handler(event, context):
    finding = event['detail']
    severity = finding['severity']
    finding_type = finding['type']
    account_id = finding['accountId']
    
    # Send to Slack
    message = {
        "text": f"🚨 GuardDuty Alert [{severity}]: {finding_type} in account {account_id}",
        "attachments": [{
            "color": "#FF0000" if severity >= 8 else "#FF6600",
            "fields": [
                {"title": "Finding Type", "value": finding_type, "short": True},
                {"title": "Severity", "value": str(severity), "short": True},
                {"title": "Account", "value": account_id, "short": True},
                {"title": "Region", "value": finding.get('region', 'unknown'), "short": True},
                {"title": "Description", "value": finding.get('description', '')[:500]}
            ]
        }]
    }
    
    # For critical findings (>=8), trigger automated response
    if severity >= 8:
        initiate_incident_response(finding)
    
    return {"statusCode": 200}

def initiate_incident_response(finding):
    """Isolate affected EC2 instance for critical findings."""
    if 'instanceDetails' in finding.get('resource', {}):
        instance_id = finding['resource']['instanceDetails']['instanceId']
        ec2 = boto3.client('ec2')
        
        # Create isolation security group (no inbound, no outbound)
        isolation_sg = ec2.create_security_group(
            GroupName=f"isolation-{instance_id}",
            Description=f"Isolation SG for GuardDuty finding",
            VpcId=finding['resource']['instanceDetails']['networkInterfaces'][0]['vpcId']
        )['GroupId']
        
        # Replace all security groups on the instance with the isolation SG
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[isolation_sg]
        )
        
        print(f"Isolated instance {instance_id} with SG {isolation_sg}")
```

---

## 6. Azure Policy and Defender for Cloud

### Technical Deep Dive

**Azure Policy — enforce compliance guardrails:**

```bash
# List built-in Azure Policy definitions related to security
az policy definition list \
  --query "[?contains(displayName, 'security') || contains(displayName, 'encryption')].{Name:displayName,ID:name}" \
  --output table | head 30

# Assign CIS Azure benchmark initiative (built-in)
SUBSCRIPTION_ID=$(az account show --query id -o tsv)

az policy assignment create \
  --name "CIS-Azure-Level-1" \
  --display-name "CIS Microsoft Azure Foundations Benchmark v1.4.0 - Level 1" \
  --policy-set-definition "06f19060-9e68-4070-92ca-f15cc126059e" \
  --scope "/subscriptions/$SUBSCRIPTION_ID" \
  --params '{
    "effect": {"value": "AuditIfNotExists"}
  }'

# Assign a built-in policy: Require storage encryption
az policy assignment create \
  --name "require-storage-encryption" \
  --display-name "Storage accounts should use customer-managed key" \
  --policy "b5ec538c-daa0-4006-8596-35468b9148e8" \
  --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/production-rg" \
  --params '{
    "effect": {"value": "Audit"}
  }'

# Check compliance state
az policy state list \
  --filter "complianceState eq 'NonCompliant'" \
  --query "[].{Resource:resourceId,Policy:policyDefinitionName,State:complianceState}" \
  --output table | head 30
```

**Custom Azure Policy (enforce tagging and deny non-compliant resources):**

```json
{
  "mode": "All",
  "displayName": "Require Environment and Owner tags on resource groups",
  "policyRule": {
    "if": {
      "allOf": [
        {"field": "type", "equals": "Microsoft.Resources/resourceGroups"},
        {
          "anyOf": [
            {"field": "tags['Environment']", "exists": "false"},
            {"field": "tags['Owner']", "exists": "false"}
          ]
        }
      ]
    },
    "then": {
      "effect": "deny"
    }
  }
}
```

```bash
az policy definition create \
  --name "require-rg-tags" \
  --display-name "Require Environment and Owner tags" \
  --mode All \
  --rules require-tags-policy.json

az policy assignment create \
  --name "enforce-rg-tags" \
  --policy "require-rg-tags" \
  --scope "/subscriptions/$SUBSCRIPTION_ID"
```

**Azure Defender for Cloud — configure and remediate:**

```bash
# Enable all Defender for Cloud plans
PLANS=("VirtualMachines" "AppServices" "SqlServers" "StorageAccounts" \
       "KeyVaults" "Arm" "Dns" "Containers" "OpenSourceRelationalDatabases")

for plan in "${PLANS[@]}"; do
  az security pricing create --name "$plan" --tier "Standard"
  echo "Enabled Defender for: $plan"
done

# Get Secure Score
az security secure-score-controls list \
  --query "sort_by([].{Control:displayName,Current:score.current,Max:score.max,Gap:to_number(score.max)-to_number(score.current)}, &Gap)" \
  --output table

# Get all active recommendations
az security assessment list \
  --query "[?status.code=='Unhealthy'].{Assessment:displayName,Resource:resourceDetails.id,Severity:metadata.severity}" \
  --output table

# Remediate a specific recommendation using quick fix
az security assessment create \
  --name "4d1c04de-2172-403d-8af5-441b6f8aced6" \
  --status-code Healthy \
  --resource-id "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/myRG/providers/Microsoft.Storage/storageAccounts/mystorage"
```

**Azure Diagnostic Settings — audit logging:**

```bash
# Enable diagnostic settings for Azure Activity Log → Log Analytics Workspace
LOG_ANALYTICS_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/monitoring-rg/providers/Microsoft.OperationalInsights/workspaces/security-workspace"

az monitor diagnostic-settings create \
  --name "ActivityLogToLA" \
  --resource "/subscriptions/$SUBSCRIPTION_ID" \
  --workspace "$LOG_ANALYTICS_ID" \
  --logs '[
    {"category": "Administrative", "enabled": true},
    {"category": "Security", "enabled": true},
    {"category": "ServiceHealth", "enabled": true},
    {"category": "Alert", "enabled": true},
    {"category": "Recommendation", "enabled": true},
    {"category": "Policy", "enabled": true},
    {"category": "Autoscale", "enabled": true},
    {"category": "ResourceHealth", "enabled": true}
  ]'

# Enable diagnostic settings on Key Vault
az monitor diagnostic-settings create \
  --name "KeyVaultLogs" \
  --resource "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/myRG/providers/Microsoft.KeyVault/vaults/myKeyVault" \
  --workspace "$LOG_ANALYTICS_ID" \
  --logs '[{"category": "AuditEvent", "enabled": true}]' \
  --metrics '[{"category": "AllMetrics", "enabled": true}]'
```

**KQL queries for Azure security monitoring:**

```kql
// Privileged role assignments — detect new Owner/Contributor assignments
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Add member to role"
| extend RoleName = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where RoleName in ("Owner", "Global Administrator", "User Access Administrator")
| project TimeGenerated, InitiatedBy=InitiatedBy.user.userPrincipalName, 
          TargetUser=TargetResources[0].userPrincipalName, RoleName
| order by TimeGenerated desc

// Failed logins with high frequency (brute force indicator)
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize FailureCount=count() by UserPrincipalName, IPAddress
| where FailureCount > 20
| order by FailureCount desc

// Storage account key access (legacy auth indicator)
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has "listKeys"
| where ResourceProviderValue == "MICROSOFT.STORAGE"
| project TimeGenerated, Caller, ResourceGroup, Resource=Resource

// Defender for Cloud security alerts
SecurityAlert
| where TimeGenerated > ago(24h)
| where AlertSeverity in ("High", "Critical")
| project TimeGenerated, AlertName, Description, Entities, RemediationSteps
| order by TimeGenerated desc
```

### Practice Challenge

> ⚠️ **Lab Environment Only** — In your Azure sandbox subscription: (1) Enable Defender for Cloud on all resource types. (2) Assign the CIS Azure Benchmark initiative. (3) Create a custom policy that denies creating storage accounts without encryption. (4) Review the Secure Score and remediate the top 3 findings. Set up a KQL alert for privileged role assignments.

---

## 📋 Complete Cloud Hardening Checklist

### AWS

```
Identity (IAM)
  [ ] Root account access keys deleted
  [ ] Root account MFA enabled (hardware token preferred)
  [ ] All IAM users have MFA
  [ ] No active IAM users for machine workloads (use roles)
  [ ] SCP deployed: deny disabling security services
  [ ] IAM password policy enforced (14+ chars, rotation)
  [ ] Access Analyzer enabled in all regions
  [ ] No policies with Action:* Resource:*

Storage (S3)
  [ ] Block Public Access enabled at account level
  [ ] All buckets encrypted (SSE-KMS for sensitive data)
  [ ] Versioning enabled on critical buckets
  [ ] Object Lock enabled for audit/compliance logs
  [ ] SSL-only bucket policy applied
  [ ] S3 access logging enabled
  [ ] Macie enabled for PII discovery

Compute (EC2)
  [ ] No public IPs on instances that don't need them
  [ ] IMDSv2 enforced on all instances
  [ ] EBS encryption by default enabled
  [ ] No unrestricted 0.0.0.0/0 on SSH or RDP
  [ ] Systems Manager Patch Manager enabled
  [ ] Inspector enabled for vulnerability scanning

Logging and Monitoring
  [ ] CloudTrail multi-region trail enabled
  [ ] CloudTrail log file validation enabled
  [ ] CloudTrail S3 bucket: versioning, encryption, no public access
  [ ] GuardDuty enabled in all regions
  [ ] Security Hub enabled with CIS and FSBP standards
  [ ] CIS metric filters and alarms configured
  [ ] VPC Flow Logs enabled
  [ ] AWS Config enabled in all regions

Networking
  [ ] No default VPC used (or default VPC deleted)
  [ ] No security groups with 0.0.0.0/0 on sensitive ports
  [ ] VPC Flow Logs enabled
  [ ] Private subnets for databases and application servers
  [ ] Egress filtering via NAT Gateway (no direct internet for app servers)
```

### Azure

```
Identity (Entra ID / RBAC)
  [ ] Security Defaults or Conditional Access enabled
  [ ] MFA required for all users via Conditional Access
  [ ] Legacy authentication blocked
  [ ] PIM configured for privileged roles
  [ ] No permanent Owner or Global Admin assignments
  [ ] Service principals use certificates or Managed Identities (no secrets)
  [ ] Guest access reviewed and limited

Storage
  [ ] Public blob access disabled at storage account level
  [ ] Secure transfer required (HTTPS only) on all storage accounts
  [ ] Storage account encryption with CMK for sensitive data
  [ ] Storage account firewall configured (limit to known IPs/VNets)
  [ ] Shared Access Signatures have expiry and limited permissions

Compute
  [ ] Disk encryption enabled on all VMs
  [ ] Endpoint protection (Defender for Servers) installed
  [ ] Update Management configured for all VMs
  [ ] JIT VM access enabled (block RDP/SSH by default)
  [ ] No VMs with public IPs unless explicitly required

Logging and Monitoring
  [ ] Activity Log → Log Analytics Workspace configured
  [ ] Diagnostic settings on Key Vaults, Storage, SQL
  [ ] Defender for Cloud all plans enabled
  [ ] CIS Azure Benchmark policy initiative assigned
  [ ] Alerts configured for privileged role changes
  [ ] Microsoft Sentinel connected (if SOC capability exists)

Networking
  [ ] NSG rules reviewed: no 0.0.0.0/0 on port 3389 or 22
  [ ] Network Watcher enabled in all regions
  [ ] DDoS Standard protection on public-facing resources
  [ ] Private Endpoints for PaaS services where possible
  [ ] Application Gateway or Azure Front Door with WAF for web apps
```

---

*Part of the [CyberPath Defensive Security Roadmap](../README.md)*
