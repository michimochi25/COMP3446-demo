# COMP3446-demo

# Scenario: Securing a Banking API Across the SDLC

We're building a cloud-native REST API for SecureBank's transaction processing system. Follow each phase to see how security controls are applied — from threat modelling to production monitoring.

# Phase 1: Plan & Design — Threat Modelling with STRIDE

Before writing a single line of code, we identify threats against the SecureBank Transaction API using the STRIDE framework. This gives us a security roadmap before implementation begins.

## System Architecture — What We're Protecting

Internet / Attackers: Mobile Client, Third-Party Partners, Threat Actors

AWS Edge Layer: AWS WAF, Cognito (OAuth2), API Gateway

Application Layer (Private VPC): Transaction Service, Account Service, Audit Service, KMS (Secrets)

Data Layer (Encrypted at Rest): RDS (AES-256), S3 (SSE-KMS), ElastiCache

## STRIDE Model

1. Spoofing: Attacker impersonates legitimate bank customer to initiate transfers
   Mitigation: AWS Cognito MFA, JWT RS256

2. Tampering: Man-in-the-middle modifies transaction amounts in transit
   Mitigation: TLS 1.3, Request Signing

3. Repudiation: Customer denies initiating a wire transfer; no audit trail
   Mitigation: CloudTrail, Immutable Audit Log

4. Info Disclosure: Account numbers and balances exposed via verbose error messages
   Mitigation: Generic Errors, KMS Encryption

5. Denial of Service: Flood of login attempts locks out legitimate customers
   Mitigation: AWS WAF, Rate Limiting

6. Elevation of Privilege: Standard user accesses admin endpoints to modify other accounts
   Mitigation: IAM Least Privilege, RBAC

## Design Decision

- Zero Trust Architecture — No implicit trust inside VPC; every service call authenticated
- Secrets never in code — All DB credentials, API keys stored in AWS Secrets Manager
- Encryption everywhere — TLS 1.3 in transit, AES-256 at rest via KMS
- API versioning strategy — /v1/ prefix enforced; deprecated versions removed in 90 days
- Rate limiting thresholds — TBD per endpoint; to be finalized after load testing

# Phase 2: Implement — IaC Security + SAST + Code Review

Infrastructure as Code is scanned with Checkov before deployment. Application code is scanned with Semgrep for vulnerabilities. Manual security checklist enforced via PR review gates.

## Deliverables

- **CloudFormation Templates:** Insecure vs. Secure banking API infrastructure
  - `insecure-template.yaml` — 6 STRIDE vulnerability categories
  - `secure-template.yaml` — Hardened production-ready deployment
- **Lambda Functions:** Two secure API endpoints
  - GET `/transactions` — Retrieve account transactions (with auth, input validation, audit logging)
  - POST `/transfer` — Transfer funds (with transaction atomicity, replay protection, comprehensive logging)
- **Security Scanning:** SAST + IaC scanning results

## Demo Instructions

### Step 1: Deploy Insecure Template to Understand Vulnerabilities

```bash
# Deploy the insecure banking API to a development environment
aws cloudformation create-stack \
  --stack-name securebank-insecure-dev \
  --template-body file://phase-2-iac/insecure-template.yaml \
  --parameters ParameterKey=Environment,ParameterValue=dev \
  --region ap-southeast-2 \
  --capabilities CAPABILITY_IAM

# Wait for stack creation
aws cloudformation wait stack-create-complete \
  --stack-name securebank-insecure-dev \
  --region ap-southeast-2

# Get outputs (API endpoint, RDS endpoint)
aws cloudformation describe-stacks \
  --stack-name securebank-insecure-dev \
  --query 'Stacks[0].Outputs' \
  --region ap-southeast-2
```

**What's Wrong:**

- RDS is publicly accessible (check VPC security groups)
- Database password hardcoded in CloudFormation
- API Gateway has no authentication (no Cognito authorizer)
- S3 bucket is unencrypted and public
- Lambda role has `AdministratorAccess` (least privilege violation)
- No CloudTrail logging for audit trail

### Step 2: Scan Insecure Template with Checkov (IaC Scanning)

```bash
# Install Checkov
pip install checkov

# Scan the insecure template
checkov -f phase-2-iac/insecure-template.yaml --framework cloudformation

# Expected failures (vulnerabilities detected):
# [FAILED] CKV_AWS_21: "Ensure all data stored in RDS is encrypted" (Line 25)
# [FAILED] CKV_AWS_27: "Ensure all data stored in RDS is backed up" (Line 28)
# [FAILED] CKV_AWS_36: "Ensure S3 bucket has public access blocked" (Line 41)
# [FAILED] CKV_AWS_65: "Ensure IAM policies that allow full \"*:*\" permissions are not created" (Line 56)
# [FAILED] CKV_AWS_70: "Ensure S3 bucket has public access blocked in account level" (Line 41)

# Generate report
checkov -f phase-2-iac/insecure-template.yaml --framework cloudformation --output cli > /tmp/checkov-insecure.txt
```

### Step 3: Scan for Hardcoded Secrets

```bash
# Install detect-secrets
pip install detect-secrets

# Scan for hardcoded secret patterns
detect-secrets scan phase-2-iac/insecure-template.yaml --all-files

# Expected findings:
# Base64 High Entropy String - Line 31: MasterUserPassword
# AWS Key - Line 60: hardcoded literals

# Also scan the Lambda code inline
cat phase-2-iac/insecure-template.yaml | grep -n "password\|secret\|key" | head -20
```

### Step 4: Scan Application Code with Semgrep (SAST)

```bash
# Install Semgrep
pip install semgrep

# Scan for vulnerability patterns in Lambda code
# Extract Lambda code first (inline in CloudFormation)
semgrep --config=p/security-audit phase-2-iac/insecure-template.yaml

# Expected findings:
# SQL Injection (CWE-89): Unparameterized SQL queries
# Hardcoded Passwords (CWE-798): Credentials in environment variables
# Information Exposure (CWE-200): Verbose error messages
```

### Step 5: Deploy Secure Template (Production-Ready)

```bash
# Create Cognito User Pool first (prerequisite)
# For demo purposes, use an existing pool ID or create one:
# aws cognito-idp create-user-pool --pool-name SecureBank

# Deploy secure template
aws cloudformation create-stack \
  --stack-name securebank-secure-prod \
  --template-body file://phase-2-iac/secure-template.yaml \
  --parameters ParameterKey=Environment,ParameterValue=prod \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-southeast-2

# Wait for stack creation
aws cloudformation wait stack-create-complete \
  --stack-name securebank-secure-prod \
  --region ap-southeast-2

# Get outputs
aws cloudformation describe-stacks \
  --stack-name securebank-secure-prod \
  --query 'Stacks[0].Outputs' \
  --region ap-southeast-2
```

### Step 6: Verify Security Controls with Secure Template

```bash
# Check RDS encryption
aws rds describe-db-instances \
  --db-instance-identifier securebank-db \
  --query 'DBInstances[0].StorageEncrypted' \
  --region ap-southeast-2
# Output: true

# Check RDS is private (not publicly accessible)
aws rds describe-db-instances \
  --db-instance-identifier securebank-db \
  --query 'DBInstances[0].PubliclyAccessible' \
  --region ap-southeast-2
# Output: false

# Check S3 encryption
aws s3api get-bucket-encryption \
  --bucket securebank-audit-logs-$(aws sts get-caller-identity --query Account --output text) \
  --query 'ServerSideEncryptionConfiguration' \
  --region ap-southeast-2

# Check S3 public access is blocked
aws s3api get-public-access-block \
  --bucket securebank-audit-logs-$(aws sts get-caller-identity --query Account --output text) \
  --region ap-southeast-2

# Check CloudTrail is enabled
aws cloudtrail describe-trails \
  --trail-name-list SecureBank-CloudTrail \
  --region ap-southeast-2
```

### Step 7: Scan Secure Template with Checkov (Should Pass)

```bash
# Scan the secure template (should have zero critical failures)
checkov -f phase-2-iac/secure-template.yaml --framework cloudformation

# Expected output: Significantly fewer failures (most are PASSED)
# Any failures are informational only (best-practice recommendations)
```

## Vulnerability Categories Demonstrated

| Threat (STRIDE)            | Vulnerability            | Insecure Example                           | Secure Control                                           |
| -------------------------- | ------------------------ | ------------------------------------------ | -------------------------------------------------------- |
| **Spoofing**               | No authentication        | API Gateway with `AuthorizationType: NONE` | Cognito User Pools with JWT validation                   |
| **Tampering**              | No encryption in transit | Hardcoded DB password in env vars          | Secrets Manager with TLS 1.3                             |
| **Repudiation**            | No audit trail           | S3 logging disabled, no CloudTrail         | CloudTrail + immutable S3 audit logs + encrypted storage |
| **Info Disclosure**        | Sensitive data exposed   | Public RDS (0.0.0.0/0) + verbose errors    | Private RDS + network isolation + generic errors         |
| **DoS**                    | No rate limiting         | No WAF, unlimited API calls                | AWS WAF with rate limiting + DDoS protection             |
| **Elevation of Privilege** | Overly permissive IAM    | Lambda has `AdministratorAccess`           | Least privilege + resource-scoped permissions            |

**Network Security Comparison:**

| Component           | Insecure                        | Secure                                |
| ------------------- | ------------------------------- | ------------------------------------- |
| **RDS Access**      | Public: 0.0.0.0/0:3306 (open)   | Private: Lambda SG only               |
| **Lambda Subnets**  | Private (via NAT for outbound)  | Private (via NAT for outbound)        |
| **Egress Control**  | All allowed (0.0.0.0/0)         | Restricted (Secrets Manager, KMS, S3) |
| **Database Backup** | None (BackupRetentionPeriod: 0) | 30-day retention with encryption      |
| **Encryption**      | None (StorageEncrypted: false)  | KMS AES-256 at rest + TLS in transit  |

---

# Phase 3: Test — Automated + Manual Security Testing

Automated security tests in AWS CodeBuild pipeline. Container image scanning with Inspector. Manual penetration testing of STRIDE threats.

## Deliverables

- **CI/CD Pipeline:** AWS CodeBuild with automated security checks
- **SAST Results:** Semgrep findings from Phase 2
- **Container Scanning:** AWS Inspector for image vulnerabilities
- **Penetration Testing Report:** STRIDE threat verification

## Demo Instructions

### Step 1: Set Up CodeBuild Project for Security Testing

```bash
# Create buildspec.yml for security testing
cat > buildspec.yml << 'EOF'
version: 0.2

phases:
  install:
    runtime-versions:
      python: 3.11
    commands:
      - echo "Installing security scanning tools..."
      - pip install checkov semgrep detect-secrets bandit

  build:
    commands:
      - mkdir -p TEST_REPORTS
      - echo "=== Phase 3.1 IaC Scanning with Checkov ==="
      - checkov -f phase-2-iac/secure-template.yaml --framework cloudformation --output cli > TEST_REPORTS/checkov-results.txt

      - echo "=== Phase 3.2 SAST with Semgrep ==="
      # Scan the IaC template
      - semgrep --config=p/security-audit phase-2-iac/secure-template.yaml --json --output TEST_REPORTS/semgrep-iac-results.json
      # Scan the Lambda Python code
      - semgrep --config=p/python phase-2-app/ --json --output TEST_REPORTS/semgrep-app-results.json

      - echo "=== Phase 3.3 Secret Detection ==="
      # Scan the root directory '.' to cover both IaC and App folders
      - detect-secrets scan . --all-files > TEST_REPORTS/secrets-scan.txt

      - echo "=== Phase 3.4 AWS Lambda Code Analysis ==="
      # Syntax check
      - python3 -m py_compile phase-2-app/lambda_functions.py
      # Run Bandit SAST scan on the Lambda code
      - bandit -r phase-2-app/ -f json -o TEST_REPORTS/bandit-results.json

  post_build:
    commands:
      - echo "Build completed successfully!"
      - ls -la TEST_REPORTS/

artifacts:
  files:
    - TEST_REPORTS/**/*
  name: SecurityTestResults
EOF

# Zip and Upload Source Code (buildspec.yml must be at ROOT level)
# Must be at COMP3446-demo
zip -r phase-2-iac.zip buildspec.yml phase-2-iac/ phase-2-app/

aws s3 cp phase-2-iac.zip s3://securebank-source-prod-$(aws sts get-caller-identity --query Account --output text)/phase-2-iac.zip --region ap-southeast-2

# Create CodeBuild project
aws codebuild create-project \
  --name SecureBank-SecurityTesting \
  --source type=S3,location=securebank-source-prod-$(aws sts get-caller-identity --query Account --output text)/phase-2-iac.zip \
  --artifacts type=S3,location=securebank-test-results-prod-$(aws sts get-caller-identity --query Account --output text) \
  --environment type=LINUX_CONTAINER,image=aws/codebuild/standard:5.0,computeType=BUILD_GENERAL1_SMALL \
  --service-role arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/CodeBuildRole-prod \
  --logs-config cloudWatchLogs='{status=ENABLED,groupName=/aws/codebuild/securebank-prod}' \
  --region ap-southeast-2

# Start build
aws codebuild start-build \
  --project-name SecureBank-SecurityTesting \
  --region ap-southeast-2
```

### Step 2: Run Automated Tests Locally

```bash
# Test Phase 2 IaC with Checkov
echo "=== IaC Security Assessment ==="
checkov -f phase-2-iac/secure-template.yaml --framework cloudformation

# Test Phase 2 Application Code with Semgrep
echo "=== SAST Results (Semgrep) ==="
semgrep --config=p/owasp-top-ten phase-2-iac/secure-template.yaml

# Detect hardcoded secrets
echo "=== Secret Detection Results ==="
detect-secrets scan phase-2-iac/
```

### Step 3: Validate IAM Permissions (Manual Security Check)

Since we're using Lambda (serverless), not EC2 or containers, we manually validate IAM permissions instead of using AWS Inspector. This ensures the Lambda execution role follows least-privilege principles.

```bash
# For Lambda (no container), scan IAM permissions instead
echo "=== Lambda IAM Policy Security Check ==="
aws iam get-role-policy \
  --role-name securebank-secure-prod-LambdaExecutionRole-LJovjxcaMlLU \
  --policy-name SecureBankLambdaPolicy \
  --region ap-southeast-2 | jq '.PolicyDocument.Statement[] | {Effect, Action, Resource}'

# Check for overly permissive permissions
# This simulates whether the role would be allowed to perform dangerous actions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/securebank-secure-prod-LambdaExecutionRole-LJovjxcaMlLU \
  --action-names 's3:*' 'rds:*' 'ec2:*' \
  --region ap-southeast-2
```

### Step 4: Automated Response to Findings

```bash
# Create SNS topic for security alerts
aws sns create-topic --name SecureBank-SecurityAlerts --region ap-southeast-2

# Create CloudWatch alarm for failed security checks
# AWS CloudWatch Alarm: Security Build Failures
# ---------------------------------------------------------
# --metric-name / --namespace : Tracks the FailedBuilds metric in CodeBuild
# --period / --statistic      : Sums up failures in 5-minute (300s) windows
# --threshold / --comparison  : Triggers if we hit 1 or more failures
# --evaluation / --datapoints : Requires 3 failing periods out of 5 to alarm (prevent false alarm)
# --alarm-actions             : Sends alert to the SecureBank SNS Topic
# ---------------------------------------------------------
aws cloudwatch put-metric-alarm \
  --alarm-name CodeBuild-SecurityFailures \
  --alarm-description "Alert on security test failures" \
  --metric-name FailedBuilds \
  --namespace AWS/CodeBuild \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:ap-southeast-2:$(aws sts get-caller-identity --query Account --output text):SecureBank-SecurityAlerts \
  --region ap-southeast-2 \
  --evaluation-periods 5 \
  --datapoints-to-alarm 3

# View CodeBuild logs
aws codebuild batch-get-builds \
  --ids $(aws codebuild list-builds-for-project --project-name SecureBank-SecurityTesting --region ap-southeast-2 | jq -r '.ids[0]') \
  --region ap-southeast-2 | jq '.builds[0].logs'
```

## Expected Test Results Summary

| Test                | Tool           | Insecure                  | Secure                | Status  |
| ------------------- | -------------- | ------------------------- | --------------------- | ------- |
| IaC Hard            |                | 8 critical failures       | 0 critical failures   | ✅ PASS |
| Secret Detection    | detect-secrets | 2 hardcoded secrets       | 0 found               | ✅ PASS |
| SAST SQL Injection  | Semgrep        | 2 unparameterized queries | Parameterized queries | ✅ PASS |
| IAM Least Privilege | PolicySim      | `*:*` permissions         | Resource-scoped       | ✅ PASS |
| Encryption          | CheckOV        | No encryption             | KMS + S3-SSE          | ✅ PASS |

---

# Phase 4: Deploy — DAST + CSPM + Sandbox Validation

Deploy to isolated sandbox environment. DAST (OWASP ZAP) performs dynamic security testing. AWS Security Hub validates cloud posture.

## Deliverables

- **Sandbox API Deployment:** Pre-prod environment with full monitoring
- **DAST Scan Results:** OWASP ZAP penetration test findings
- **CSPM Assessment:** AWS Security Hub compliance posture
- **Go/No-Go Decision:** Security validation before production

## Demo Instructions

### Step 1: Deploy to Sandbox Environment

```bash
# Deploy secure template to sandbox
aws cloudformation create-stack \
  --stack-name securebank-sandbox \
  --template-body file://phase-2-iac/secure-template.yaml \
  --parameters ParameterKey=Environment,ParameterValue=staging \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-southeast-2

# Get API endpoint
API_ENDPOINT=$(aws cloudformation describe-stacks \
  --stack-name securebank-sandbox \
  --query 'Stacks[0].Outputs[?OutputKey==`APIEndpoint`].OutputValue' \
  --output text \
  --region ap-southeast-2)

echo "Sandbox API: $API_ENDPOINT"
```

### Step 2: Run DAST (Dynamic Application Security Testing) with OWASP ZAP

```bash
# Install OWASP ZAP (if not already installed)
# Download from: https://www.zaproxy.org/download/

# Create ZAP automation script
cat > zap-scan.yaml << 'EOF'
env:
  failOnError: true
  failOnWarning: false
contexts:
  - name: SecureBank
    urls:
      - https://mn27u1arj1.execute-api.ap-southeast-2.amazonaws.com/staging
tests:
  - testType: passiveScan
  - testType: activeScan
    parameters:
      inScopeOnly: true
      recurse: true
policies:
  - policyDefinitionUrl: https://raw.githubusercontent.com/zaproxy/zap-core-yaml/main/policies/api.yaml
EOF

# Run ZAP scan in Docker
docker run -v $(pwd):/zap/wrk:rw \
  -t zaproxy/zap-stable \
  zap-api-scan.py \
  -t https://mn27u1arj1.execute-api.ap-southeast-2.amazonaws.com/staging \
  -f openapi \
  -r zap-report.html

# Expected vulnerabilities detected:
# - Missing authentication headers (no Cognito token provided)
# - SQL injection attempts (blocked by WAF)
# - XSS payloads (blocked)
# - Rate limit bypass attempts (rate limited)

# View results
ls -lh zap-report.html
```

### Step 3: Set Up Prowler for Cloud Security Posture Management (CSPM)

```bash
# Install Prowler
pip install prowler

# Verify installation
prowler --version

# Configure AWS credentials (if not already set)
export AWS_REGION=ap-southeast-2
export AWS_PROFILE=default

# Configure access and secret key first
aws configure

# Run Prowler scan against SecureBank resources
prowler aws --region ap-southeast-2 \
  --services rds s3 apigateway cloudtrail iam \
  --resource-tags aws:cloudformation:stack-name=securebank-sandbox \
  -o prowler-reports

# Expected findings: Secure template should show PASSED status for all critical checks
```

### Step 4: Review Prowler Assessment Results

```bash
# View Prowler scan results in JSON format
jq '.[] | {Check: .metadata.event_code, Resource: .resources[0].name, Status: .status_code}' prowler-reports/*.json

# Generate summary statistics
jq 'group_by(.status_code) | map({result: .[0].status_code, count: length})' prowler-reports/*.json

# View HTML report for visual inspection
open prowler-reports/*.html  # or use your browser

# Check specific compliance frameworks
prowler aws --region ap-southeast-2 \
  --compliance cis_2.0_aws \
  --output-formats json-ocsf csv \
  -o prowler-reports/cis

# Filter results by severity
cat prowler-reports/cis/*.json | \
  jq '.[] | select(.severity == "Critical") | {Check: .metadata.event_code, Resource: .resources[0].name, Severity: .severity, StatusCode: .status_code}'
```

# Expected: Secure template should show 0 CRITICAL findings, most checks PASSED

### Step 5: Validate Before Production Promotion with Prowler

1. Make an automated script
   cat > validate-script.sh << 'EOF'
   #!/bin/bash

# Production readiness validation using Prowler

echo "=== Production Readiness Checklist with Prowler ==="

# Locate the exact JSON file you already generated

REPORT_JSON=$(ls prowler-reports/\*.json 2>/dev/null | head -n 1)

# Fail fast if the report doesn't exist to prevent 'cat' from hanging

if [ -z "$REPORT_JSON" ]; then
echo "❌ Error: Could not find Prowler report in prowler-reports/"
exit 1
fi

# Check for critical findings

CRITICAL_COUNT=$(jq '[.[] | select((.severity == "Critical" or .severity == "critical") and .status_code == "FAIL")] | length' "$REPORT_JSON")

if [ "$CRITICAL_COUNT" -eq 0 ]; then
echo "✅ 0 critical findings"
else
echo "❌ $CRITICAL_COUNT critical findings found"
fi

echo -e "\n=== Checking Security Controls ==="

# Check RDS encryption

RDS_ENCRYPTION=$(jq -r '.[] | select(.metadata.event_code == "rds_instance_storage_encrypted" and .status_code == "FAIL") | .status_code' "$REPORT_JSON" | head -n 1)
if [ "$RDS_ENCRYPTION" == "FAIL" ]; then
echo "❌ RDS Encryption: FAILED"
else
echo "✅ RDS Encryption: PASSED / NOT_FOUND"
fi

# Check API Gateway Authorization

API_AUTH=$(jq -r '.[] | select(.metadata.event_code == "apigateway_restapi_authorizers_enabled" and .status_code == "FAIL") | .status_code' "$REPORT_JSON" | head -n 1)
if [ "$API_AUTH" == "FAIL" ]; then
echo "❌ API Gateway Authorization: FAILED"
else
echo "✅ API Gateway Authorization: PASSED / NOT_FOUND"
fi

# Check S3 public access blocks

S3_BLOCK=$(jq -r '.[] | select(.metadata.event_code == "s3_bucket_level_public_access_block" and .status_code == "FAIL") | .status_code' "$REPORT_JSON" | head -n 1)
if [ "$S3_BLOCK" == "FAIL" ]; then
echo "❌ S3 Public Access Blocked: FAILED"
else
echo "✅ S3 Public Access Blocked: PASSED / NOT_FOUND"
fi

# Generate compliance summary

COMPLIANCE_JSON=$(ls prowler-reports/cis/\*.json 2>/dev/null | head -n 1)

echo -e "\n=== Compliance Summary ==="
if [ -z "$COMPLIANCE_JSON" ]; then
echo "⚠️ No CIS compliance report found."
else
jq -r '.[] | "\(.metadata.event_code): \(.status_code)"' "$COMPLIANCE_JSON" | sort | uniq -c
fi

echo -e "\n=== Ready for promotion to production ==="
EOF

2. Change the file permission `chmod +x validate-script.sh
3. Run the script `./validate-script.sh`

---

# Phase 5: Maintain — CloudWatch + CloudTrail + AWS Config

Continuous monitoring, anomaly detection, and compliance enforcement post-deployment.

## Deliverables

- **CloudWatch Dashboards:** Real-time security metrics
- **CloudTrail Audit Logs:** Immutable API activity records
- **AWS Config Rules:** Continuous compliance monitoring
- **Incident Response:** Automated remediation workflows

## Demo Instructions

### Step 1: Set Up CloudWatch Monitoring

```bash
# Create CloudWatch namespace for custom metrics
aws cloudwatch put-metric-data \
  --namespace SecureBank \
  --metric-name APIAuthentication \
  --value 100 \
  --unit Percent \
  --region ap-southeast-2

# Create dashboard
cat > dashboard.json << 'EOF'
{
  "DashboardName": "SecureBank-Security",
  "DashboardBody": {
    "widgets": [
      {
        "type": "metric",
        "properties": {
          "metrics": [[
            "AWS/ApiGateway",
            "Count",
            {"stat": "Sum", "label": "Total Requests"}
          ]],
          "period": 300,
          "stat": "Sum",
          "region": "ap-southeast-2",
          "title": "API Requests"
        }
      },
      {
        "type": "metric",
        "properties": {
          "metrics": [[
            "AWS/Lambda",
            "Duration",
            {"stat": "Average"}
          ]],
          "period": 60,
          "stat": "Average",
          "region": "ap-southeast-2",
          "title": "Lambda Execution Time"
        }
      },
      {
        "type": "log",
        "properties": {
          "query": "fields @timestamp, status | stats count() by status",
          "region": "ap-southeast-2",
          "title": "API Status Distribution"
        }
      }
    ]
  }
}
EOF

aws cloudwatch put-dashboard \
  --dashboard-name SecureBank-Security \
  --dashboard-body file://dashboard.json \
  --region ap-southeast-2
```

### Step 2: Create Alarms for Security Events

```bash
# Alarm: Multiple authentication failures
aws cloudwatch put-metric-alarm \
  --alarm-name SecureBank-AuthFailures \
  --alarm-description "Alert on repeated authentication failures" \
  --metric-name 401Errors \
  --namespace AWS/ApiGateway \
  --statistic Sum \
  --period 300 \
  --threshold 10 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:ap-southeast-2:ACCOUNT_ID:SecureBank-SecurityAlerts \
  --region ap-southeast-2

# Alarm: Lambda execution errors
aws cloudwatch put-metric-alarm \
  --alarm-name SecureBank-LambdaErrors \
  --alarm-description "Alert on Lambda execution errors" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --alarm-actions arn:aws:sns:ap-southeast-2:ACCOUNT_ID:SecureBank-SecurityAlerts \
  --region ap-southeast-2

# Alarm: Unauthorized API calls
aws cloudwatch put-metric-alarm \
  --alarm-name SecureBank-UnauthorizedCalls \
  --alarm-description "Alert on unauthorized API calls" \
  --metric-name UnauthorizedOperationCount \
  --namespace CloudTrailMetrics \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:ap-southeast-2:ACCOUNT_ID:SecureBank-SecurityAlerts \
  --region ap-southeast-2
```

### Step 3: Enable Real-Time CloudTrail Forensics

```bash
# Create EventBridge rule for suspicious activity
aws events put-rule \
  --name SecureBank-SuspiciousActivity \
  --event-pattern '{
    "source": ["aws.signin"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["UnauthorizedOperation", "AccessDenied"]
    }
  }' \
  --state ENABLED \
  --region ap-southeast-2

# Send to SNS for real-time alerting
aws events put-targets \
  --rule SecureBank-SuspiciousActivity \
  --targets "Id"="1","Arn"="arn:aws:sns:ap-southeast-2:ACCOUNT_ID:SecureBank-SecurityAlerts" \
  --region ap-southeast-2

# Query CloudTrail for recent events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::RDS::DBInstance \
  --start-time 2024-01-01T00:00:00Z \
  --region ap-southeast-2 | jq '.Events[] | {EventTime, EventName, Username}'

# Filter for high-risk events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteDBInstance \
  --region ap-southeast-2

# Example output: Any DeleteDBInstance events would trigger immediate alert
```

### Step 4: Set Up Prowler for Continuous Compliance Monitoring

```bash
# Install Prowler dependencies
pip install prowler-cloud sqlalchemy flask

# Create Prowler baseline configuration
cat > prowler-config.yaml << 'EOF'
regions: ["ap-southeast-2"]
output_formats: ["json", "csv", "html"]
strategic_frameworks: ["cis_level2", "pci_dss"]
critical_checks_only: false
EOF

# Run scheduled Prowler scans (via cron or AWS Lambda)
# Schedule daily scans
(crontab -l 2>/dev/null; echo "0 2 * * * cd /home/giselle/COMP3446/COMP3446-demo && prowler aws --region ap-southeast-2 -o ~/prowler-reports/daily-\$(date +%Y%m%d)") | crontab -

# Monitor specific compliance frameworks
echo "=== Running CIS Level 2 Benchmark ==="
prowler aws --region ap-southeast-2 --checks cis_level2 -o ~/prowler-reports/cis-benchmark

# Monitor PCI-DSS controls for banking
echo "=== Checking PCI-DSS Compliance ==="
prowler aws --region ap-southeast-2 --checks pci_dss -o ~/prowler-reports/pci-dss

# Generate trend analysis
echo "=== Compliance Trend Analysis ==="
python3 << 'PYTHON'
import json
import os
from pathlib import Path
from collections import defaultdict

report_dir = Path(os.path.expanduser('~/prowler-reports'))
results = defaultdict(lambda: {'PASSED': 0, 'FAILED': 0})

for report_file in report_dir.glob('*/prowler-output.json'):
    with open(report_file) as f:
        data = json.load(f)
        for check in data:
            results[check['Check_ID']][check['Result']] += 1

print("\n=== Compliance Trend ===")
for check_id, counts in sorted(results.items()):
    total = counts['PASSED'] + counts['FAILED']
    pass_rate = (counts['PASSED'] / total * 100) if total > 0 else 0
    print(f"{check_id}: {counts['PASSED']}/{total} PASSED ({pass_rate:.1f}%)")
PYTHON
```

### Step 5: Create Incident Response Automation

```bash
# Create Lambda function for auto-remediation
cat > remediation.py << 'EOF'
import boto3
import json

config = boto3.client('config')
ec2 = boto3.client('ec2')

def lambda_handler(event, context):
    """Auto-remediate security group misconfiguration"""
    config_item = json.loads(event['configurationItem'])
    resource_id = config_item['resourceId']

    if config_item['resourceType'] == 'AWS::EC2::SecurityGroup':
        # Check for overly permissive rules
        sg = ec2.describe_security_groups(GroupIds=[resource_id])['SecurityGroups'][0]

        for rule in sg['IpPermissions']:
            if rule.get('IpRanges', [{}])[0].get('CidrIp') == '0.0.0.0/0':
                # Revoke rule
                ec2.revoke_security_group_ingress(
                    GroupId=resource_id,
                    IpPermissions=[rule]
                )
                print(f"Remediated overly permissive rule in {resource_id}")

    return {'compliance': 'REMEDIATED'}
EOF

# Deploy remediation function
aws lambda create-function \
  --function-name SecureBank-SecurityRemediation \
  --runtime python3.11 \
  --handler remediation.lambda_handler \
  --zip-file fileb://remediation.zip \
  --role arn:aws:iam::ACCOUNT_ID:role/LambdaExecutionRole \
  --region ap-southeast-2

# Create AWS Config Remediation Config Rule
aws configservice put-remediation-configurations \
  --remediation-configurations '{
    "ConfigRuleName": "sg-no-public-access",
    "TargetType": "SSM_DOCUMENT",
    "TargetVersion": "1",
    "TargetIdentifier": "AWS-PublishSNSMessage",
    "Automatic": true,
    "MaximumAutomaticAttempts": 10,
    "AutomaticRemediationRetryAttempt": 300
  }' \
  --region ap-southeast-2
```

### Step 6: Dashboard & Reporting

```bash
# Generate compliance report
aws configservice describe-compliance-by-config-rule \
  --region ap-southeast-2 | jq '.ComplianceByConfigRules[] | {ConfigRuleName, Compliance}'

# Expected output shows compliance with all security controls

# Get detailed findings
aws securityhub get-compliance-summary \
  --region ap-southeast-2 | jq '.ComplianceSummary'

# Store metrics in CloudWatch for trend analysis
aws cloudwatch put-metric-data \
  --namespace SecureBank/Compliance \
  --metric-name ComplianceScore \
  --value 98.5 \
  --unit Percent \
  --region ap-southeast-2
```

---

## Summary: Shift-Left Security Benefits

| Metric                       | Insecure                | Secure             |
| ---------------------------- | ----------------------- | ------------------ |
| **Vulnerabilities Found**    | 47 (9 critical)         | 0 critical         |
| **Time to Find Issues**      | Production (too late)   | Phase 2 (IaC scan) |
| **Average Fix Cost**         | $50K+ per vulnerability | <$1K (shift-left)  |
| **Compliance Score**         | 25%                     | 98%                |
| **Incident Response Time**   | Hours                   | Minutes            |
| **Audit Trail Completeness** | None                    | 100% immutable     |

**Key Lesson:** Security controls applied during implementation (Phase 2) prevent 80% of vulnerabilities before testing, reducing risk and cost significantly.

```

```
