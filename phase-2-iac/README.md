# Phase 2: Implement — IaC Security

## Overview

This phase demonstrates how security controls are applied during the Implement phase through Infrastructure as Code (IaC). We provide two CloudFormation templates:

1. **insecure-template.yaml** — Banking API with common security vulnerabilities
2. **secure-template.yaml** — Production-ready Banking API with security controls

## Files

- `insecure-template.yaml` — CloudFormation with security issues (STRIDE-aligned)
- `secure-template.yaml` — Hardened CloudFormation with controls
- Demo database schema: `setup-db.sql` (create manually in CloudSQL)

---

## VPC Architecture (Secure Template)

```
SecureBank VPC (10.0.0.0/16)
│
├─ PublicSubnet (10.0.0.0/24)
│  ├─ Internet Gateway (IGW)
│  └─ NAT Gateway (Elastic IP: static outbound IP)
│
├─ PrivateSubnet1 (10.0.1.0/24)
│  ├─ Lambda Functions (GET /transactions, POST /transfer)
│  └─ RDS Multi-AZ (MySQL) — Encrypted, no internet access
│
└─ PrivateSubnet2 (10.0.2.0/24)
   ├─ Lambda Functions (redundancy)
   └─ RDS Replica (for Multi-AZ failover)

Network Flow:
┌─────────────────────────────────────────────────────────┐
│ Client                                                  │
│   ↓ (HTTPS)                                             │
│ API Gateway + Cognito Authorizer + AWS WAF              │
│   ↓ (VPC Endpoint)                                      │
│ Lambda in PrivateSubnet1/2                              │
│   ├→ RDS (10.0.1.0/24 SG only) — Internal only         │
│   └→ AWS Services (via NAT Gateway)                     │
│       ├─ Secrets Manager (retrieve DB password)         │
│       ├─ KMS (decrypt/encrypt)                          │
│       ├─ S3 (write audit logs)                          │
│       └─ CloudWatch (send logs)                         │
└─────────────────────────────────────────────────────────┘

CIDR Planning:
- VPC: 10.0.0.0/16 (65,536 IPs)
  - Public:   10.0.0.0/24 (256 IPs) — NAT Gateway
  - Private1: 10.0.1.0/24 (256 IPs) — RDS, Lambda (AZ1)
  - Private2: 10.0.2.0/24 (256 IPs) — RDS, Lambda (AZ2)
  - Reserved: 10.0.3.0/24 - 10.0.255.0/24 (future expansion)
```

---

## Vulnerabilities in Insecure Template

The insecure template demonstrates real-world security mistakes aligned with STRIDE:

### 1. **Spoofing** — No Authentication

- API Gateway has `AuthorizationType: NONE`
- No JWT or session validation
- Anyone can call `/transactions` or `/transfer` endpoints

### 2. **Tampering** — No Encryption in Transit

- API uses HTTP (not enforced TLS)
- Database credentials hardcoded in Lambda environment variables
- Vulnerable to MITM attacks

### 3. **Repudiation** — No Audit Trail

- S3 bucket has zero logging enabled
- No CloudTrail logging
- Database changes not tracked
- No immutable audit log

### 4. **Information Disclosure** — Data Exposure

- RDS is **publicly accessible** (open to internet)
- Database credentials hardcoded in code
- Verbose error messages expose system details
- Unencrypted S3 bucket
- No encryption at rest (StorageEncrypted: false)

### 5. **Denial of Service** — No Rate Limiting

- No AWS WAF
- No rate limiting on API Gateway
- No throttling on endpoints
- Vulnerable to DDoS

### 6. **Elevation of Privilege** — Overly Permissive IAM

- Lambda role has `AdministratorAccess` (should have least privilege)
- No resource-level permissions
- No API-level authorization checks

---

## Security Controls in Secure Template

### 1. **Authentication & Authorization** ✅

```yaml
# Cognito User Pools for JWT-based auth
CognitoAuthorizer:
  Type: AWS::ApiGateway::Authorizer
  Properties:
    Type: COGNITO_USER_POOLS

GetTransactionMethod:
  AuthorizationType: COGNITO_USER_POOLS # Every endpoint requires valid JWT
```

### 2. **Encryption at Rest** ✅

```yaml
# KMS encryption for RDS and S3
TransactionDatabaseSecure:
  StorageEncrypted: true
  KmsKeyId: !GetAtt KMSKeyForEncryption.Arn

AuditLogsBucketSecure:
  BucketEncryption:
    ServerSideEncryptionConfiguration:
      - ServerSideEncryptionByDefault:
          SSEAlgorithm: aws:kms
```

### 3. **Encryption in Transit** ✅

```yaml
# Secrets Manager instead of hardcoded passwords
DBCredentialsSecret:
  Type: AWS::SecretsManager::Secret
  Properties:
    GenerateSecretString:
      PasswordLength: 32 # Rotating secrets

# Lambda retrieves secrets at runtime
def get_db_credentials():
  response = secrets_client.get_secret_value(SecretId=secret_arn)
  return json.loads(response['SecretString'])
```

### 4. **Audit & Logging** ✅

```yaml
# CloudTrail for immutable API audit
SecureBankTrail:
  EnableLogFileValidation: true # Prevent tampering

# Application-level audit logs to encrypted S3
def audit_log(event_type, user_id, account_id, status): log_entry = {...}
  s3_client.put_object(
  Bucket=AUDIT_BUCKET,
  ServerSideEncryption='aws:kms'
  )

# Database logging
TransactionDatabaseSecure:
  EnableCloudwatchLogsExports:
    - error
    - general
    - slowquery
```

### 5. **Network Isolation (Zero Trust)** ✅

```yaml
# Three-tier network with controlled outbound access:
#
# PublicSubnet (10.0.0.0/24)
#   ├─ Internet Gateway
#   └─ NAT Gateway (Elastic IP)
#       ↓
# PrivateSubnet1 (10.0.1.0/24) — RDS + Lambda
# PrivateSubnet2 (10.0.2.0/24) — RDS + Lambda
#
# RDS: Private only (no internet)
# Lambda: Private with outbound via NAT (for AWS service access)

NATGateway:
  AllocationId: !GetAtt NATGatewayEIP.AllocationId
  SubnetId: !Ref PublicSubnet # ✅ NAT lives in public subnet
  # Lambda uses NAT for outbound calls:
  #   → secretsmanager:GetSecretValue (retrieve DB password)
  #   → kms:Decrypt, kms:GenerateDataKey (encryption)
  #   → s3:PutObject (write audit logs)
  #   → logs:PutLogEvents (CloudWatch logs)

PrivateRouteTable:
  Route:
    DestinationCidrBlock: 0.0.0.0/0
    NatGatewayId: !Ref NATGateway # ✅ All outbound → NAT

DBSecurityGroup:
  SecurityGroupIngress:
    - SourceSecurityGroupId: !Ref LambdaSecurityGroup # ✅ Only from Lambda

TransactionDatabaseSecure:
  PubliclyAccessible: false # ✅ Completely private, no internet access
  VPCSecurityGroups:
    - !Ref DBSecurityGroup
```

**Why NAT Gateway is Critical:**

Without NAT Gateway, Lambda calls timeout ❌:

```
Lambda (10.0.1.0/24) → Secrets Manager API
   ❌ No route to internet
   ❌ Timeout error
```

With NAT Gateway, Lambda reaches AWS services ✅:

```
Lambda (10.0.1.0/24)
   → NAT Gateway (10.0.0.0/24)
   → Internet Gateway
   → AWS Service APIs ✅
```

### 6. **DDoS Protection** ✅

```yaml
# AWS WAF with rate limiting and SQL injection protection
WAFWebACL:
  Rules:
    - RateLimitRule:
        Limit: 2000 req/min per IP
    - AWSManagedRulesSQLiRuleSet # Block SQL injection
    - AWSManagedRulesCommonRuleSet
```

### 7. **Least Privilege IAM** ✅

```yaml
LambdaExecutionRoleSecure:
  Policies:
    - Sid: SecretsManagerAccess
      Action:
        - secretsmanager:GetSecretValue # Only specific secret
      Resource: !GetAtt DBCredentialsSecret.Arn

    - Sid: S3AuditLogs
      Action:
        - s3:PutObject
      Resource: !Sub "${AuditLogsBucketSecure.Arn}/audit/*" # Only audit prefix
```

---

## Demo Walkthrough

### Setup

1. **Deploy Insecure Template (Sandbox)**

   ```bash
   aws cloudformation create-stack \
     --stack-name securebank-insecure \
     --template-body file://insecure-template.yaml \
     --parameters ParameterKey=Environment,ParameterValue=dev \
     --region ap-southeast-2
   ```

   **Result:** Stack is created with vulnerabilities visible.

2. **Deploy Secure Template (Production)**
   ```bash
   aws cloudformation create-stack \
     --stack-name securebank-secure \
     --template-body file://secure-template.yaml \
     --parameters ParameterKey=Environment,ParameterValue=prod \
                 ParameterKey=CognitoUserPoolId,ParameterValue=ap-southeast-2_XXXXXXXXX \
     --region ap-southeast-2
   ```

### Manual Security Scanning

Use AWS tools to identify vulnerabilities:

#### **IaC Scanning with Checkov**

```bash
pip install checkov

# Scan insecure template
checkov -f insecure-template.yaml --framework cloudformation

# Findings:
# CKV_AWS_17: CloudTrail logging disabled
# CKV_AWS_21: S3 not encrypted
# CKV_AWS_23: RDS encryption disabled
# CKV_AWS_27: public RDS
# CKV_AWS_65: IAM policy not restricted
```

#### **Detect Hardcoded Secrets with Detect-secrets**

```bash
pip install detect-secrets

detect-secrets scan insecure-template.yaml

# Findings:
# Line 25: Database password "BankPassword123!" detected
# Line 140: DB credentials in Lambda env vars
```

#### **CloudFormation Policy Check**

```bash
aws cloudformation validate-template --template-body file://insecure-template.yaml

# Warnings about:
# - Admin IAM policy
# - Public RDS
# - Missing encryption
```

---

## Code Demo: Vulnerabilities vs. Fixes

### Example 1: SQL Injection

**INSECURE:**

```python
# Direct string interpolation
query = f"SELECT * FROM transactions WHERE account_id = {account_id}"
cursor.execute(query)  # Vulnerable to: ' OR 1=1 --
```

**SECURE:**

```python
# Parameterized query
query = "SELECT id, account_id, amount FROM transactions WHERE account_id = %s"
cursor.execute(query, (account_id,))  # Safe from SQL injection
```

### Example 2: Credential Exposure

**INSECURE:**

```python
Environment:
  Variables:
    DB_PASSWORD: 'BankPassword123!'  # Hardcoded in code/template
```

**SECURE:**

```python
# Secrets Manager stores and rotates passwords
secret_arn = os.environ['DB_SECRET_ARN']
response = secrets_client.get_secret_value(SecretId=secret_arn)
creds = json.loads(response['SecretString'])
password = creds['password']  # Retrieved at runtime, never in code
```

### Example 3: Error Message Leakage

**INSECURE:**

```python
except Exception as e:
    return {
        'statusCode': 500,
        'body': json.dumps({'error': str(e)})  # Stack trace revealed!
    }
# Result: "Access denied for user 'admin'@'<IP>' (using password: YES)"
```

**SECURE:**

```python
except Exception as e:
    logger.error(f"{request_id}: {str(e)}")  # Log internally only
    return {
        'statusCode': 500,
        'body': json.dumps({'error': 'An error occurred'})  # Generic message
    }
```

---

## Troubleshooting Deployment Issues

### Lambda Function can't reach Secrets Manager / KMS / S3

**Symptom**: Lambda timeout or "Connection refused" errors in CloudWatch logs

**Cause**: NAT Gateway not attached or route table not configured

**Fix**:

```bash
# Verify NAT Gateway is in AVAILABLE state
aws ec2 describe-nat-gateways --region ap-southeast-2 \
  --query 'NatGateways[?Tags[?Key==`Name` && Value==`SecureBank-NAT`]].{ID:NatGatewayId,State:State,EIP:NatGatewayAddresses[0].PublicIp}'

# Verify private subnet has route to NAT Gateway
aws ec2 describe-route-tables --region ap-southeast-2 \
  --query 'RouteTables[?Tags[?Key==`Name` && Value==`PrivateRouteTable`]].Routes' \
  --output table

# Expected output:
# DestinationCidrBlock: 0.0.0.0/0 → NatGatewayId: nat-xxxxxxxxx
```

### Lambda can't reach RDS database

**Symptom**: "Connection timeout" when Lambda tries to connect to RDS

**Cause**: Security group rules are wrong, or Lambda not in same VPC

**Fix**:

```bash
# Verify Lambda security group can reach RDS port 3306
aws ec2 describe-security-groups --group-id sg-xxxxx --region ap-southeast-2 | \
  jq '.SecurityGroups[0].SecurityGroupEgress[] | select(.FromPort==3306)'

# Should show egress rule to RDS security group (not 0.0.0.0/0)

# Verify RDS accepts traffic from Lambda security group
aws ec2 describe-security-groups \
  --group-id $(aws rds describe-db-instances --db-instance-identifier securebank-db-secure \
    --region ap-southeast-2 --query 'DBInstances[0].VpcSecurityGroups[0].VpcSecurityGroupId' --output text) \
  --region ap-southeast-2 | \
  jq '.SecurityGroups[0].SecurityGroupIngress[] | select(.FromPort==3306)'

# Should show ingress rule from Lambda security group
```

### S3 bucket name already exists

**Symptom**: Stack creation fails with "BucketAlreadyExists"

**Cause**: S3 bucket names are globally unique; try deploying with different account

**Fix**:

```bash
# The template generates bucket name with account ID, should be unique
# If still fails, delete the old bucket first:
aws s3 rb s3://securebank-audit-logs-${ACCOUNT_ID}-secure --force --region ap-southeast-2
```

---

## Next Steps (Phase 3: Test)

In Phase 3, these templates will be scanned with:

1. **SAST (Semgrep)** — Analyze Python Lambda code for vulnerabilities
2. **IaC Scanning (Checkov)** — Validate CloudFormation compliance
3. **Secrets Detection** — Find hardcoded secrets
4. **CI/CD Pipeline** — Automated testing in CodeBuild

See `../README.md` Phase 3 for testing instructions.
