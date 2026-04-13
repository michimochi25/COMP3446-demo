# Prowler CSPM Demo Guide — SecureBank Banking API

A comprehensive guide to implementing Prowler for Cloud Security Posture Management (CSPM) in the SecureBank project.

## What is Prowler?

**Prowler** is an open-source security assessment framework that audits your AWS infrastructure against security best practices and compliance frameworks:

- **CIS AWS Foundations Benchmark** (Level 1 & 2)
- **PCI-DSS** (Payment Card Industry Data Security Standard)
- **HIPAA** (if applicable)
- **SOC 2** compliance
- **NIST Cybersecurity Framework**
- Custom security checks

Unlike AWS Security Hub (managed service), Prowler is:
- **Free and open-source**
- **Highly customizable**
- **Runs locally or in CI/CD pipelines**
- **Framework-agnostic** (covers AWS-specific and general security best practices)
- **Fast and lightweight**

---

## Part 1: Setup & Installation

### Step 1.1: Prerequisites

```bash
# Check Python version (3.9+)
python3 --version

# Verify AWS CLI is installed
aws --version

# Ensure AWS credentials are configured
aws sts get-caller-identity
```

### Step 1.2: Install Prowler

```bash
# Option 1: Install via pip (recommended for demo)
pip install prowler-cloud

# Verify installation
prowler --version

# Option 2: Docker (if you prefer containerized approach)
docker pull public.ecr.aws/prowler-cloud/prowler:latest
```

### Step 1.3: Configure AWS Credentials

```bash
# If using default AWS profile
export AWS_REGION=ap-southeast-2

# If using multiple AWS profiles
export AWS_PROFILE=your-profile-name
export AWS_REGION=ap-southeast-2

# Verify Prowler can access AWS
prowler aws --list-all-checks | head -20
```

---

## Part 2: Running Your First Prowler Scan

### Step 2.1: Quick Scan (5-10 minutes)

Run a basic scan against your SecureBank resources:

```bash
# Navigate to project directory
cd /home/giselle/COMP3446/COMP3446-demo

# Run scan against specific region
prowler aws --region ap-southeast-2 \
  --output-formats json csv html \
  --output-directory ./prowler-reports

# View summary results
echo "Scan completed! Results in ./prowler-reports"
ls -lh prowler-reports/
```

### Step 2.2: Targeted Scan (Banking-Specific Checks)

Focus on controls relevant to your secure CloudFormation template:

```bash
# Create directory for results
mkdir -p prowler-reports/banking-scan

# Run banking-specific security checks
prowler aws --region ap-southeast-2 \
  --checks \
    rds_encryption_enabled \
    rds_publicly_accessible \
    s3_bucket_public_block_enabled \
    s3_encryption_enabled \
    apigateway_authorization_type_is_valid \
    cloudtrail_enabled \
    iam_policy_no_statements_with_admin_access \
    lambda_iam_role_least_privilege \
  --output-formats json csv html \
  --output-directory ./prowler-reports/banking-scan
```

**Expected Output Structure:**
```
prowler-reports/banking-scan/
├── prowler-output.html          # Interactive HTML report
├── prowler-output.json          # Machine-readable results
└── prowler-output.csv           # Spreadsheet format
```

---

## Part 3: Understanding Prowler Results

### Step 3.1: View HTML Report (Visual)

```bash
# Open the HTML report in your browser
open prowler-reports/banking-scan/prowler-output.html

# Or use command-line if GUI not available
firefox prowler-reports/banking-scan/prowler-output.html &
```

The HTML report shows:
- ✅ **PASSED**: Control implemented correctly
- ❌ **FAILED**: Control not implemented or misconfigured
- ⚠️ **MANUAL**: Requires manual review
- ⏭️ **SKIPPED**: N/A for your account

### Step 3.2: Parse JSON Results

```bash
# View all check results in JSON format
cat prowler-reports/banking-scan/prowler-output.json | jq .

# Count results by status
cat prowler-reports/banking-scan/prowler-output.json | \
  jq 'group_by(.Result) | map({Status: .[0].Result, Count: length})'

# Example output:
# [
#   { "Status": "PASSED", "Count": 42 },
#   { "Status": "FAILED", "Count": 3 },
#   { "Status": "MANUAL", "Count": 1 }
# ]
```

### Step 3.3: Filter by Severity

```bash
# Show only CRITICAL and HIGH findings
cat prowler-reports/banking-scan/prowler-output.json | \
  jq '.[] | select(.Severity == "critical" or .Severity == "high") | 
       {Check_ID, Check_Title, Result, Severity, Resource}'

# Count failures by severity
cat prowler-reports/banking-scan/prowler-output.json | \
  jq '[.[] | select(.Result == "FAILED")] | 
      group_by(.Severity) | 
      map({Severity: .[0].Severity, Count: length})'
```

### Step 3.4: Analyze Specific Resource

```bash
# View all checks for a specific RDS instance
cat prowler-reports/banking-scan/prowler-output.json | \
  jq '.[] | select(.ResourceId | contains("securebank-db")) | 
       {Check_ID, Result, Status}'

# View all checks for a specific S3 bucket
cat prowler-reports/banking-scan/prowler-output.json | \
  jq '.[] | select(.ResourceId | contains("securebank-audit")) | 
       {Check_ID, Result, Status}'
```

---

## Part 4: Compliance Framework Checks

### Step 4.1: CIS AWS Foundations Benchmark

```bash
# Run CIS Level 1 (foundational controls)
prowler aws --region ap-southeast-2 \
  --checks cis_level1 \
  --output-directory ./prowler-reports/cis-level1

# Run CIS Level 2 (advanced hardening)
prowler aws --region ap-southeast-2 \
  --checks cis_level2 \
  --output-directory ./prowler-reports/cis-level2

# View CIS compliance summary
cat prowler-reports/cis-level2/prowler-output.json | \
  jq '[.[] | select(.Check_Type == "cis_level2")] | 
      length as $total | 
      map(select(.Result == "PASSED")) | 
      length as $passed | 
      {Total: $total, Passed: $passed, Compliance: "\\($passed/$total*100 | round)%"}'
```

### Step 4.2: PCI-DSS Compliance (Banking Standard)

```bash
# Run PCI-DSS checks (mandatory for payment systems)
prowler aws --region ap-southeast-2 \
  --checks pci_dss_v321 \
  --output-directory ./prowler-reports/pci-dss

# View critical PCI-DSS failures
cat prowler-reports/pci-dss/prowler-output.json | \
  jq '.[] | select(.Requirement == "1.2" or .Requirement == "2.1" or .Requirement == "3.2") | 
       select(.Result == "FAILED") | 
       {Requirement, Check_Title, ResourceId}'
```

**Key PCI-DSS Requirements for SecureBank:**
- **Req 1.x**: Network segmentation & firewalls
- **Req 2.x**: Default passwords & access control
- **Req 3.x**: Encryption of cardholder data
- **Req 7.x**: Least privilege access
- **Req 10.x**: Logging & monitoring

---

## Part 5: Integration with CI/CD (CodeBuild)

### Step 5.1: Update buildspec.yml with Prowler

```yaml
# Add to your buildspec.yml
version: 0.2

phases:
  install:
    runtime-versions:
      python: 3.11
    commands:
      - echo "Installing Prowler..."
      - pip install prowler-cloud

  build:
    commands:
      - mkdir -p SECURITY_REPORTS

      - echo "=== Phase 4.1 Running Prowler Scan ==="
      - prowler aws --region ap-southeast-2 \
          --checks rds_encryption_enabled s3_bucket_public_block_enabled \
                   apigateway_authorization_type_is_valid cloudtrail_enabled \
          --output-formats json csv html \
          --output-directory SECURITY_REPORTS/prowler

      - echo "=== Phase 4.2 Checking for Critical Findings ==="
      - |
        CRITICAL_COUNT=$(cat SECURITY_REPORTS/prowler/prowler-output.json | \
          jq '[.[] | select(.Severity == "critical" and .Result == "FAILED")] | length')
        if [ $CRITICAL_COUNT -gt 0 ]; then
          echo "❌ Found $CRITICAL_COUNT critical findings"
          exit 1
        else
          echo "✅ No critical findings"
        fi

      - echo "=== Phase 4.3 Generating Compliance Report ==="
      - |
        cat SECURITY_REPORTS/prowler/prowler-output.json | jq \
          'map(select(.Result == "PASSED" or .Result == "FAILED")) | 
           group_by(.Result) | 
           map({Status: .[0].Result, Count: length})' \
          > SECURITY_REPORTS/compliance-summary.json

  post_build:
    commands:
      - echo "Prowler scan completed!"
      - ls -lh SECURITY_REPORTS/prowler/

artifacts:
  files:
    - SECURITY_REPORTS/**/*
  name: ProwlerSecurityAssessment
```

### Step 5.2: Deploy CodeBuild with Prowler

```bash
# Create S3 buckets for source and artifacts
aws s3 mb s3://securebank-prowler-source-$(aws sts get-caller-identity --query Account --output text) \
  --region ap-southeast-2

aws s3 mb s3://securebank-prowler-reports-$(aws sts get-caller-identity --query Account --output text) \
  --region ap-southeast-2

# Create CodeBuild project
aws codebuild create-project \
  --name SecureBank-Prowler-Assessment \
  --source type=S3,location=securebank-prowler-source-$(aws sts get-caller-identity --query Account --output text)/source.zip \
  --artifacts type=S3,location=securebank-prowler-reports-$(aws sts get-caller-identity --query Account --output text) \
  --environment type=LINUX_CONTAINER,image=aws/codebuild/standard:5.0,computeType=BUILD_GENERAL1_SMALL \
  --service-role arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/CodeBuildRole \
  --region ap-southeast-2

# Start a build
aws codebuild start-build \
  --project-name SecureBank-Prowler-Assessment \
  --region ap-southeast-2
```

---

## Part 6: Automated Reporting & Monitoring

### Step 6.1: Generate Executive Summary

```bash
#!/bin/bash
# Save as: generate-prowler-report.sh

REPORT_FILE="prowler-executive-summary.txt"
JSON_FILE="prowler-reports/banking-scan/prowler-output.json"

cat > $REPORT_FILE << 'EOF'
================================================================================
                   SECUREBANK SECURITY POSTURE REPORT
                          Powered by Prowler CSPM
================================================================================
EOF

echo "Generated: $(date)" >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Overall compliance score
TOTAL_CHECKS=$(jq 'length' $JSON_FILE)
PASSED=$(jq '[.[] | select(.Result == "PASSED")] | length' $JSON_FILE)
FAILED=$(jq '[.[] | select(.Result == "FAILED")] | length' $JSON_FILE)
PASS_RATE=$((PASSED * 100 / TOTAL_CHECKS))

cat >> $REPORT_FILE << EOF

OVERALL SECURITY POSTURE
========================
Total Checks:        $TOTAL_CHECKS
Passed:              $PASSED ✅
Failed:              $FAILED ❌
Compliance Score:    $PASS_RATE%

EOF

# Critical findings
echo "CRITICAL FINDINGS" >> $REPORT_FILE
echo "=================" >> $REPORT_FILE
jq -r '.[] | select(.Severity == "critical" and .Result == "FAILED") | 
         "- \\(.Check_ID): \\(.Check_Title)"' $JSON_FILE >> $REPORT_FILE

# High severity findings
echo "" >> $REPORT_FILE
echo "HIGH SEVERITY FINDINGS" >> $REPORT_FILE
echo "======================" >> $REPORT_FILE
jq -r '.[] | select(.Severity == "high" and .Result == "FAILED") | 
         "- \\(.Check_ID): \\(.Check_Title)"' $JSON_FILE >> $REPORT_FILE

# Recommendations
echo "" >> $REPORT_FILE
echo "RECOMMENDATIONS" >> $REPORT_FILE
echo "================" >> $REPORT_FILE
echo "1. Address all CRITICAL findings before production deployment" >> $REPORT_FILE
echo "2. Remediate HIGH severity findings within 30 days" >> $REPORT_FILE
echo "3. Schedule remediation for MEDIUM severity findings within 90 days" >> $REPORT_FILE
echo "4. Enable continuous monitoring with scheduled Prowler scans" >> $REPORT_FILE

echo "" >> $REPORT_FILE
echo "For detailed results, see: prowler-output.html" >> $REPORT_FILE

cat $REPORT_FILE
```

Run the script:
```bash
bash generate-prowler-report.sh
cat prowler-executive-summary.txt
```

### Step 6.2: Schedule Continuous Scans

```bash
# Create a cron job for daily Prowler scans
cat > /tmp/prowler-cron.sh << 'EOF'
#!/bin/bash
# Daily Prowler scan

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_DIR="/home/giselle/COMP3446/COMP3446-demo/prowler-reports/scheduled"
mkdir -p $REPORT_DIR/$TIMESTAMP

cd /home/giselle/COMP3446/COMP3446-demo

# Run scan
prowler aws --region ap-southeast-2 \
  --output-formats json csv html \
  --output-directory $REPORT_DIR/$TIMESTAMP

# Upload to S3 for long-term storage
aws s3 cp $REPORT_DIR/$TIMESTAMP \
  s3://securebank-prowler-reports-$(aws sts get-caller-identity --query Account --output text)/scheduled/$TIMESTAMP \
  --recursive \
  --region ap-southeast-2

echo "Prowler scan completed: $TIMESTAMP" | mail -s "Prowler CSPM Report" admin@example.com
EOF

# Make executable
chmod +x /tmp/prowler-cron.sh

# Add to crontab (runs daily at 2 AM)
(crontab -l 2>/dev/null; echo "0 2 * * * /tmp/prowler-cron.sh") | crontab -

# Verify cron job
crontab -l | grep prowler
```

---

## Part 7: Remediation Workflow

### Step 7.1: Generate Remediation Checklist

```bash
# Create remediation checklist from failed checks
cat > remediation-checklist.md << 'EOF'
# SecureBank Prowler Remediation Checklist

## Critical Issues (Must fix before production)
EOF

cat prowler-reports/banking-scan/prowler-output.json | \
  jq -r '.[] | select(.Result == "FAILED" and .Severity == "critical") | 
          "### \\(.Check_ID): \\(.Check_Title)\n- **Severity**: CRITICAL\n- **Resource**: \\(.ResourceId)\n- **Remediation**: [See Prowler documentation](https://docs.prowler.cloud)\n"' \
  >> remediation-checklist.md

cat remediation-checklist.md
```

### Step 7.2: Example Remediation — Enable RDS Encryption

```bash
# If RDS check fails (rds_encryption_enabled)
# Modify your secure-template.yaml to include:

# In RDS Resource definition:
StorageEncrypted: true
KmsKeyId: !GetAtt KMSKey.Arn

# Then redeploy and re-scan:
aws cloudformation update-stack \
  --stack-name securebank-secure-prod \
  --template-body file://phase-2-iac/secure-template.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-southeast-2

# Wait for update
aws cloudformation wait stack-update-complete \
  --stack-name securebank-secure-prod \
  --region ap-southeast-2

# Re-run Prowler to verify fix
prowler aws --region ap-southeast-2 \
  --checks rds_encryption_enabled \
  --output-formats json
```

---

## Part 8: Advanced Prowler Features

### Step 8.1: Custom Checks

```bash
# Create custom Prowler check for SecureBank-specific policies
cat > custom-securebank-check.py << 'EOF'
# Check that all Lambda functions have timeout < 5 minutes
from prowler.lib.checks.models import Check, CheckResult

class lambda_timeout_check(Check):
    def execute(self):
        results = []
        
        for function in self.lambda_client.get_all_functions():
            result = CheckResult(
                check_id="custom_lambda_timeout",
                check_title="Lambda timeout should be less than 5 minutes",
                check_result={
                    "result": "PASSED" if function.timeout < 300 else "FAILED",
                    "evaluated_keys": [f"Lambda:{function.name}/Timeout"],
                },
                resource_details=function.name,
            )
            results.append(result)
        
        return results
EOF
```

### Step 8.2: Exclude False Positives

```bash
# Create exclusion list for known false positives
cat > prowler-exclusions.yaml << 'EOF'
exclusions:
  checks:
    - check_id: "s3_bucket_public_block_enabled"
      resources:
        - "arn:aws:s3:::securebank-public-website"  # Intentionally public
      reason: "Website bucket is public by design"
  
  resources:
    - "arn:aws:rds:*:*:db/securebank-read-replica"
      checks:
        - "rds_publicly_accessible"
      reason: "Read replica is read-only, minimal risk"
EOF

# Run scan with exclusions
prowler aws --region ap-southeast-2 \
  --excluded-checks-file prowler-exclusions.yaml \
  --output-directory prowler-reports/with-exclusions
```

### Step 8.3: Integration with Slack/Teams Alerts

```bash
# Send critical findings to Slack
cat > prowler-slack-alert.sh << 'EOF'
#!/bin/bash

WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
JSON_FILE="prowler-reports/banking-scan/prowler-output.json"

# Extract critical failures
CRITICAL=$(jq -r '.[] | select(.Severity == "critical" and .Result == "FAILED") | .Check_Title' $JSON_FILE | wc -l)

if [ $CRITICAL -gt 0 ]; then
  curl -X POST -H 'Content-type: application/json' \
    --data "{
      \"text\": \"⚠️ Prowler Alert: $CRITICAL critical security findings in SecureBank\",
      \"attachments\": [{
        \"color\": \"danger\",
        \"fields\": [{
          \"title\": \"Report\",
          \"value\": \"View full report: [Prowler Dashboard](link-to-s3)\"
        }]
      }]
    }" \
    $WEBHOOK_URL
fi
EOF

chmod +x prowler-slack-alert.sh
./prowler-slack-alert.sh
```

---

## Part 9: Comparing Prowler vs Security Hub

| Feature | Prowler | AWS Security Hub |
|---------|---------|------------------|
| **Cost** | Free (open-source) | Paid ($0.20 per finding/month) |
| **Frameworks** | CIS, PCI-DSS, NIST, SOC 2 | AWS recommendations only |
| **Customization** | Highly customizable | Limited |
| **CI/CD Integration** | Native (local scanning) | Via EventBridge |
| **Compliance Reports** | Full control | Predefined formats |
| **Learning Curve** | Moderate | Low (AWS native) |
| **Use Case** | Development, multi-account, custom requirements | Enterprise, centralized AWS |

**Best Practice**: Use Prowler for development/staging, Security Hub for production accounts.

---

## Part 10: Troubleshooting

### Common Issues

**Issue**: "AccessDenied" errors during Prowler scan
```bash
# Solution: Ensure IAM role has required permissions
aws iam attach-role-policy \
  --role-name your-prowler-role \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit

aws iam attach-role-policy \
  --role-name your-prowler-role \
  --policy-arn arn:aws:iam::aws:policy/ViewOnlyAccess
```

**Issue**: Prowler scan timeout
```bash
# Solution: Scan by region or service
prowler aws --region ap-southeast-2 \
  --services ec2 rds s3 \
  --output-directory prowler-reports/targeted-scan
```

**Issue**: Can't find HTML report
```bash
# Check file exists
find prowler-reports -name "*.html" -type f

# View with Python HTTP server
cd prowler-reports && python3 -m http.server 8000
# Then visit http://localhost:8000
```

---

## Next Steps

1. **Week 1**: Deploy Prowler and run baseline scan
2. **Week 2**: Remediate critical findings
3. **Week 3**: Enable CI/CD integration
4. **Week 4+**: Schedule monthly comprehensive audits

For more information: https://docs.prowler.cloud
