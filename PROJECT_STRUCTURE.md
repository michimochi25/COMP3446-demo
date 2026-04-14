# COMP3446 Cloud SDLC Demo — Project Structure

## Overview

This demonstration project shows how security is applied across all phases of the Cloud SDLC (Secure Development Lifecycle) using AWS services and a realistic banking API scenario. We're building a cloud-native REST API for SecureBank's transaction processing system, following each phase to see how security controls are applied — from threat modelling to production monitoring.

## Project Layout

```
COMP3446-demo/
├── README.md                          # Main project guide with Phase 1-5 instructions
├── index.html                         # Interactive web UI demonstrating all phases
├── buildspec.yml                      # AWS CodeBuild spec for automated security pipeline
├── zap-scan.yaml                      # OWASP ZAP automation config for DAST
├── prowler-config.yaml                # Prowler baseline configuration for CSPM
├── validate-script.sh                 # Production readiness validation script (Prowler-based)
├── dashboard.json                     # CloudWatch dashboard definition
│
├── phase-2-iac/                       # Infrastructure as Code (CloudFormation)
│   ├── README.md                      # Phase 2 IaC instructions & vulnerability analysis
│   ├── insecure-template.yaml         # CloudFormation with 6 STRIDE vulnerabilities
│   └── secure-template.yaml           # Production-ready hardened CloudFormation
│
└── phase-2-app/                       # Application Code (Lambda Functions)
    ├── README.md                      # Lambda development guide
    ├── lambda_functions.py            # GET /transactions & POST /transfer implementations
    └── requirements.txt               # Python dependencies for scanning & deployment
```

---

## System Architecture — What We're Protecting

```
Internet / Attackers
  └── Mobile Client, Third-Party Partners, Threat Actors
        │
        ▼
AWS Edge Layer
  ├── AWS WAF               (DDoS protection, rate limiting, SQL injection blocking)
  ├── Amazon Cognito        (OAuth2 / JWT RS256 authentication with MFA)
  └── API Gateway           (REST API entry point, Cognito authorizer attached)
        │
        ▼
Application Layer (Private VPC)
  ├── Transaction Service   (GET /transactions Lambda)
  ├── Account Service       (POST /transfer Lambda)
  ├── Audit Service         (immutable S3 audit log writer)
  └── AWS KMS               (encryption key management / secrets)
        │
        ▼
Data Layer (Encrypted at Rest)
  ├── Amazon RDS MySQL      (AES-256, private subnet, no public access)
  ├── Amazon S3             (SSE-KMS for audit logs, public access blocked)
  └── Amazon ElastiCache    (session/cache layer)
```

### VPC Network Layout (Secure Template)

```
VPC
├── Public Subnet
│   ├── Internet Gateway (IGW)       — Inbound/outbound internet access
│   └── NAT Gateway                  — Outbound-only egress for private subnets
│
└── Private Subnets
    ├── Lambda Functions             — Egress via NAT to Secrets Manager, KMS, S3, CloudWatch
    └── RDS MySQL                    — Accessible only from Lambda security group
```

**Region:** ap-southeast-2 (Sydney)

---

## Phase-by-Phase Walkthrough

### Phase 1: Plan & Design ✅

**Focus**: Threat modelling, architecture design
**Deliverables**: STRIDE analysis, architecture diagrams, design decisions
**Location**: Main `README.md` Phase 1 section + `index.html`

#### STRIDE Threat Model

| Threat (STRIDE)            | Attack Scenario                                            | Mitigation                                               |
| -------------------------- | ---------------------------------------------------------- | -------------------------------------------------------- |
| **Spoofing**               | Attacker impersonates legitimate bank customer to transfer | AWS Cognito MFA, JWT RS256                               |
| **Tampering**              | MITM modifies transaction amounts in transit               | TLS 1.3, Request Signing                                 |
| **Repudiation**            | Customer denies initiating a wire transfer; no audit trail | CloudTrail, Immutable Audit Log                          |
| **Info Disclosure**        | Account numbers/balances exposed via verbose errors        | Generic Errors, KMS Encryption                           |
| **Denial of Service**      | Flood of login attempts locks out legitimate customers     | AWS WAF, Rate Limiting                                   |
| **Elevation of Privilege** | Standard user accesses admin endpoints to modify accounts  | IAM Least Privilege, RBAC                                |

#### Design Decisions

- **Zero Trust Architecture** — No implicit trust inside VPC; every service call authenticated
- **Secrets never in code** — All DB credentials and API keys stored in AWS Secrets Manager
- **Encryption everywhere** — TLS 1.3 in transit, AES-256 at rest via KMS
- **API versioning strategy** — `/v1/` prefix enforced; deprecated versions removed in 90 days
- **Rate limiting thresholds** — To be finalised per endpoint after load testing

---

### Phase 2: Implement ✅

**Focus**: Secure coding, IaC best practices, vulnerability scanning
**Deliverables**: CloudFormation templates, Lambda code, SAST reports
**Location**: `phase-2-iac/` and `phase-2-app/` directories

#### API Endpoints

| Method | Endpoint           | Description                                                        |
| ------ | ------------------ | ------------------------------------------------------------------ |
| GET    | `/v1/transactions` | Retrieve account transactions (auth, input validation, audit log)  |
| POST   | `/v1/transfer`     | Transfer funds (atomicity, replay protection, comprehensive log)   |

#### Security Controls per Endpoint

```
GET /transactions
├─ Cognito JWT authentication
├─ Input validation (account_id format)
├─ Parameterized SQL query
├─ Audit logging to S3
└─ Generic error responses

POST /transfer
├─ Cognito JWT authentication
├─ Comprehensive input validation
├─ Transaction atomicity (all-or-nothing)
├─ Balance verification before debit
├─ Recipient verification before credit
├─ Immutable audit trail
└─ Request ID for tracing
```

#### Insecure Template Vulnerabilities (Educational)

- Hardcoded database password in CloudFormation environment variables
- RDS publicly accessible (`0.0.0.0/0:3306`)
- API Gateway with `AuthorizationType: NONE` (no Cognito authorizer)
- Unencrypted, public S3 bucket
- Lambda role with `AdministratorAccess` (least privilege violation)
- No CloudTrail logging or audit trail
- Vulnerable SQL queries (unparameterized — SQL injection risk)
- Verbose error messages exposing internal details
- No RDS backup (`BackupRetentionPeriod: 0`)

#### Secure Template Controls (Production-Ready)

- AWS Secrets Manager for all database credentials
- Private VPC with security groups; RDS accessible only from Lambda SG
- Internet Gateway (public subnet) + NAT Gateway for Lambda outbound egress
- Cognito User Pools JWT authentication on all API endpoints
- KMS AES-256 encryption for RDS and S3
- Least privilege IAM role (resource-scoped, no wildcard `*:*` permissions)
- CloudTrail + immutable S3 audit logs with SSE-KMS encryption
- Parameterized SQL queries
- Generic error messages
- 30-day RDS backup retention with encryption

#### Vulnerability Comparison

| Threat (STRIDE)            | Insecure Example                             | Secure Control                                           |
| -------------------------- | -------------------------------------------- | -------------------------------------------------------- |
| **Spoofing**               | `AuthorizationType: NONE` on API Gateway     | Cognito User Pools with JWT validation                   |
| **Tampering**              | Hardcoded DB password in env vars            | Secrets Manager with TLS 1.3                             |
| **Repudiation**            | S3 logging disabled, no CloudTrail           | CloudTrail + immutable S3 audit logs + encrypted storage |
| **Info Disclosure**        | Public RDS (`0.0.0.0/0`) + verbose errors    | Private RDS + network isolation + generic errors         |
| **DoS**                    | No WAF, unlimited API calls                  | AWS WAF with rate limiting + DDoS protection             |
| **Elevation of Privilege** | Lambda has `AdministratorAccess`             | Least privilege + resource-scoped permissions            |

#### Network Security Comparison

| Component           | Insecure                        | Secure                                     |
| ------------------- | ------------------------------- | ------------------------------------------ |
| **RDS Access**      | Public: `0.0.0.0/0:3306` (open) | Private: Lambda SG only                    |
| **Lambda Subnets**  | No VPC isolation                | Private subnet (via NAT for outbound)      |
| **Egress Control**  | All allowed (`0.0.0.0/0`)       | Restricted (Secrets Manager, KMS, S3, CloudWatch) |
| **Database Backup** | None (`BackupRetentionPeriod: 0`) | 30-day retention with encryption          |
| **Encryption**      | None (`StorageEncrypted: false`) | KMS AES-256 at rest + TLS in transit      |

#### Checkov Expected Findings (Insecure Template)

```
[FAILED] CKV_AWS_21  — RDS storage not encrypted (Line 25)
[FAILED] CKV_AWS_27  — RDS backup not enabled (Line 28)
[FAILED] CKV_AWS_36  — S3 bucket public access not blocked (Line 41)
[FAILED] CKV_AWS_65  — IAM policy allows full *:* permissions (Line 56)
[FAILED] CKV_AWS_70  — S3 public access not blocked at account level (Line 41)
```

#### detect-secrets Expected Findings (Insecure Template)

```
Base64 High Entropy String — Line 31: MasterUserPassword
AWS Key                    — Line 60: hardcoded literals
```

#### Semgrep Expected Findings (Insecure Template)

```
SQL Injection (CWE-89)         — Unparameterized SQL queries
Hardcoded Passwords (CWE-798)  — Credentials in environment variables
Information Exposure (CWE-200) — Verbose error messages
```

---

### Phase 3: Test ✅

**Focus**: Automated security testing, SAST, DAST preparation
**Deliverables**: CodeBuild pipeline, Checkov/Semgrep/Bandit scan results, IAM policy validation
**Location**: Main `README.md` Phase 3 section

#### Testing Tools

- **Checkov** — IaC scanning; detects 8+ critical issues in insecure template
- **Semgrep** — SAST for Lambda code (detects SQL injection, secrets, info exposure)
- **Bandit** — Python-specific SAST for Lambda functions (`phase-2-app/`)
- **detect-secrets** — Scans both IaC and application directories for hardcoded secrets
- **AWS CodeBuild** — Automated CI/CD pipeline running all scans against `phase-2-iac/` and `phase-2-app/`
- **IAM Policy Simulator** — Validates Lambda execution role is least-privilege (no `s3:*`, `rds:*`, `ec2:*`)

#### CodeBuild Pipeline Stages (`buildspec.yml`)

```
install    → pip install checkov semgrep detect-secrets bandit
build 3.1  → Checkov scan of secure-template.yaml → TEST_REPORTS/checkov-results.txt
build 3.2  → Semgrep scan of IaC + app code → semgrep-iac-results.json, semgrep-app-results.json
build 3.3  → detect-secrets scan of full repo → secrets-scan.txt
build 3.4  → Python syntax check + Bandit SAST on lambda_functions.py → bandit-results.json
post_build → Artifacts uploaded to S3 as SecurityTestResults
```

#### CloudWatch Alerting

- SNS topic `SecureBank-SecurityAlerts` for notification delivery
- CloudWatch alarm `CodeBuild-SecurityFailures`: triggers when `FailedBuilds ≥ 1` across 3 of 5 evaluation periods (300s windows) — prevents false positives

#### Expected Test Results Summary

| Test                | Tool           | Insecure                    | Secure                | Status  |
| ------------------- | -------------- | --------------------------- | --------------------- | ------- |
| IaC Hardening       | Checkov        | 8 critical failures         | 0 critical failures   | ✅ PASS |
| Secret Detection    | detect-secrets | 2 hardcoded secrets         | 0 found               | ✅ PASS |
| SAST SQL Injection  | Semgrep        | 2 unparameterized queries   | Parameterized queries | ✅ PASS |
| IAM Least Privilege | PolicySim      | `*:*` permissions           | Resource-scoped       | ✅ PASS |
| Encryption          | Checkov        | No encryption               | KMS + S3-SSE          | ✅ PASS |

---

### Phase 4: Deploy ✅

**Focus**: DAST penetration testing, cloud posture verification (CSPM)
**Deliverables**: Sandbox deployment, OWASP ZAP results, Prowler CSPM report, Go/No-Go validation
**Location**: Main `README.md` Phase 4 section

#### Deployment Target

- Stack: `securebank-sandbox` (Environment=staging) deployed to `ap-southeast-2`
- Uses the same `secure-template.yaml` as production

#### DAST: OWASP ZAP (`zap-scan.yaml`)

- Runs passive and active scans against the sandbox API endpoint
- API scan policy sourced from `zaproxy/zap-core-yaml` (OpenAPI profile)
- Expected WAF-blocked findings: SQL injection attempts, XSS payloads, rate limit bypass, missing auth headers

#### CSPM: Prowler (`prowler-config.yaml`)

- Scans services: `rds`, `s3`, `apigateway`, `cloudtrail`, `iam`
- Compliance frameworks: `cis_level2`, `pci_dss`
- Outputs: `json`, `csv`, `html` reports to `prowler-reports/`
- Region: `ap-southeast-2`

#### Production Readiness Validation (`validate-script.sh`)

Automated script verifying:
- 0 critical Prowler findings
- RDS encryption PASSED (`rds_instance_storage_encrypted`)
- API Gateway authorizer PASSED (`apigateway_restapi_authorizers_enabled`)
- S3 public access blocked PASSED (`s3_bucket_level_public_access_block`)
- CIS 2.0 compliance summary report

#### Compliance Score Target

- Secure template: **≥ 98%** (0 critical findings)
- Insecure template: **~25%** (47 findings, 9 critical)

---

### Phase 5: Maintain ✅

**Focus**: Production monitoring, incident response, continuous compliance automation
**Deliverables**: CloudWatch dashboards, CloudTrail audit logs, EventBridge rules, scheduled Prowler scans
**Location**: Main `README.md` Phase 5 section

#### CloudWatch Dashboard (`dashboard.json`)

Widgets:
- API Gateway total request count (5-minute sum)
- Lambda execution duration (1-minute average)
- API status code distribution (log insights query)

#### CloudWatch Alarms

| Alarm Name                       | Metric                              | Threshold       | Window        |
| --------------------------------- | ----------------------------------- | --------------- | ------------- |
| `SecureBank-AuthFailures`         | `AWS/ApiGateway → 401Errors`        | > 10 in 5 min   | 1 period      |
| `SecureBank-LambdaErrors`         | `AWS/Lambda → Errors`               | > 5 (3 of 5)    | 5 min windows |
| `SecureBank-UnauthorizedCalls`    | `CloudTrailMetrics → UnauthorizedOperationCount` | ≥ 5 (3 of 5) | 5 min windows |
| `CodeBuild-SecurityFailures`      | `AWS/CodeBuild → FailedBuilds`      | ≥ 1 (3 of 5)   | 5 min windows |

All alarms route to SNS topic `SecureBank-SecurityAlerts`.

#### CloudTrail Forensics

- EventBridge rule `SecureBank-SuspiciousActivity`: captures `UnauthorizedOperation` and `AccessDenied` events from `aws.signin` via CloudTrail
- Routes to SNS for real-time alerting
- High-risk event filter: `DeleteDBInstance` triggers immediate alert

#### Automated Compliance: Cloud-Native Prowler Monitoring

Scheduled daily compliance scan using a Lambda + EventBridge architecture:

| Component                          | Details                                                   |
| ----------------------------------- | --------------------------------------------------------- |
| **S3 Bucket** (`securebank-compliance-reports-*`) | Immutable, versioned, encrypted (AES-256), public access blocked |
| **IAM Role** (`SecureBank-ProwlerLambdaRole`)     | Least-privilege: scoped to RDS, S3, API GW, CloudTrail, IAM reads |
| **Lambda Function** (`SecureBank-ProwlerCompliance`) | Python 3.11, 512 MB, 300s timeout; runs Prowler, uploads reports, sends SNS alert |
| **EventBridge Rule** (`SecureBank-ProwlerSchedule`) | `cron(0 2 ? * * *)` — daily at 2:00 AM ap-southeast-2 |
| **SNS Topic** (`SecureBank-ComplianceAlerts`)     | Email alerts for CRITICAL findings or scan failures       |

---

## How to Use This Demo

### For Instructors/Presenters

1. **Start with `index.html`** — Interactive UI showing all phases visually
2. **Phase 1**: Explain STRIDE threat model and architecture
3. **Phase 2**: Deploy insecure template, run Checkov, show vulnerabilities
4. **Phase 2**: Deploy secure template, compare Checkov/Semgrep/detect-secrets results
5. **Phase 3**: Run `buildspec.yml` via CodeBuild; review all scan reports
6. **Phase 4**: Deploy sandbox, run OWASP ZAP and Prowler CSPM
7. **Phase 5**: Demonstrate CloudWatch dashboard, alarms, CloudTrail forensics, and scheduled Prowler compliance

### For Students/Learners

1. **Read** main `README.md` for full context
2. **Study** `phase-2-iac/insecure-template.yaml` to understand common misconfigurations
3. **Compare** with `phase-2-iac/secure-template.yaml` to learn security controls
4. **Review** `phase-2-app/lambda_functions.py` inline comments for secure coding patterns
5. **Hands-on**: Deploy both templates to AWS, run Checkov/Semgrep, compare findings
6. **Experiment**: Introduce vulnerabilities, run scans to detect them

### For Security Teams

1. **Baseline**: Insecure template represents typical audit findings (47 issues, 9 critical)
2. **Hardening**: Secure template shows required controls for compliance (0 critical)
3. **Tooling**: Demonstrates Checkov, Semgrep, Bandit, detect-secrets, OWASP ZAP, Prowler
4. **Policy**: Security controls form the basis for IaC policy enforcement
5. **Testing**: End-to-end example of SAST → IaC scanning → DAST → CSPM

---

## Technology Stack

| Component      | Technology                | Purpose                                        |
| -------------- | ------------------------- | ---------------------------------------------- |
| **IaC**        | AWS CloudFormation        | Define infrastructure securely                 |
| **Compute**    | AWS Lambda (Python 3.11)  | Serverless API endpoints                       |
| **Database**   | Amazon RDS MySQL          | Transactional database (private subnet)        |
| **Cache**      | Amazon ElastiCache        | Session/cache layer                            |
| **Storage**    | Amazon S3 + KMS           | Encrypted audit logs and compliance reports    |
| **Auth**       | Amazon Cognito            | OAuth2 / JWT RS256 user authentication         |
| **Secrets**    | AWS Secrets Manager       | Credential management (no hardcoded secrets)   |
| **Encryption** | AWS KMS                   | Encryption key management (AES-256)            |
| **API**        | API Gateway + WAF         | REST API with DDoS protection + rate limiting  |
| **Network**    | VPC + NAT Gateway + IGW   | Network isolation + outbound egress routing    |
| **Routing**    | Route Tables              | Public/private subnet routing                  |
| **Monitoring** | CloudWatch                | Metrics, dashboards, alarms                    |
| **Audit**      | CloudTrail                | Immutable API audit logs                       |
| **Compliance** | Prowler (Lambda-scheduled)| Continuous CSPM (CIS 2.0, PCI-DSS)            |
| **Alerting**   | SNS + EventBridge         | Security alerts and automated remediation      |
| **CI/CD**      | AWS CodeBuild             | Automated security scanning pipeline           |
| **SAST**       | Checkov, Semgrep, Bandit  | Static analysis for IaC and application code   |
| **Secret Scan**| detect-secrets            | Hardcoded credential detection                 |
| **DAST**       | OWASP ZAP                 | Dynamic penetration testing                    |

---

## Key Files to Review

### For Understanding Vulnerabilities

1. `phase-2-iac/insecure-template.yaml` (Lines 1–150) — Database security issues (public RDS, no encryption)
2. `phase-2-iac/insecure-template.yaml` (Lines 151–200) — IAM overpermission (`AdministratorAccess`)
3. `phase-2-iac/insecure-template.yaml` (Lines 200–250) — No API authentication (`AuthorizationType: NONE`)
4. `phase-2-iac/insecure-template.yaml` (Lines 250+) — Lambda inline code with SQL injection

### For Understanding Solutions

1. `phase-2-iac/secure-template.yaml` (Lines 1–50) — VPC & Internet Gateway setup
2. `phase-2-iac/secure-template.yaml` (Lines 50–150) — Public subnet, NAT Gateway, route tables
3. `phase-2-iac/secure-template.yaml` (Lines 150–200) — Private subnets for RDS & Lambda
4. `phase-2-iac/secure-template.yaml` (Lines 200–350) — KMS encryption & Secrets Manager
5. `phase-2-iac/secure-template.yaml` (Lines 350–550) — Secure Lambda with input validation
6. `phase-2-iac/secure-template.yaml` (Lines 550–700) — API Gateway + Cognito authorizer
7. `phase-2-iac/secure-template.yaml` (Lines 700+) — CloudTrail + WAF

### For Code Security Patterns

1. `phase-2-app/lambda_functions.py` — Inline comments explaining all security controls
2. `buildspec.yml` — Complete CodeBuild security pipeline definition
3. `validate-script.sh` — Prowler-based production readiness gate

---

## Demo Scenarios

### Scenario 1: "Find the Vulnerabilities" (30 mins)

1. Deploy insecure template
2. Attendees list security issues
3. Run Checkov to validate findings
4. Discuss impact of each vulnerability

**Learning**: Common misconfigurations found in production

### Scenario 2: "Fix the Issues" (45 mins)

1. Review insecure vs. secure templates side-by-side
2. Explain each security control addition
3. Deploy secure template
4. Compare Checkov/Semgrep/Bandit results

**Learning**: How to implement security controls

### Scenario 3: "Attack the API" (30 mins)

1. Deploy insecure API to accessible endpoint
2. Demonstrate SQL injection, authentication bypass
3. Deploy secure API
4. Show WAF and Cognito auth protecting against the same attacks

**Learning**: Real-world exploitation and prevention

### Scenario 4: "Incident Response" (40 mins)

1. Simulate suspicious activity detected via CloudTrail
2. EventBridge triggers alert; SNS sends notification
3. Investigate using CloudWatch logs and CloudTrail forensics
4. Create incident report
5. Show Config/Prowler rules for automated remediation

**Learning**: Detection, investigation, and remediation workflow

---

## Estimated Time

| Phase     | Activity                                | Time        |
| --------- | --------------------------------------- | ----------- |
| 1         | STRIDE threat modelling discussion      | 20 min      |
| 2         | Deploy templates + security scans       | 30 min      |
| 2         | Code review (secure vs. insecure)       | 20 min      |
| 3         | Run CodeBuild pipeline, review findings | 15 min      |
| 4         | Deploy sandbox, OWASP ZAP + Prowler     | 20 min      |
| 4         | Prowler CSPM review + validate script   | 10 min      |
| 5         | CloudWatch dashboard + alarms           | 15 min      |
| 5         | CloudTrail forensics + EventBridge      | 10 min      |
| **Total** | **Full demo**                           | **140 min** |

---

## Shift-Left Security Summary

| Metric                       | Insecure                | Secure             |
| ---------------------------- | ----------------------- | ------------------ |
| **Vulnerabilities Found**    | 47 (9 critical)         | 0 critical         |
| **Time to Find Issues**      | Production (too late)   | Phase 2 (IaC scan) |
| **Average Fix Cost**         | $50K+ per vulnerability | <$1K (shift-left)  |
| **Compliance Score**         | 25%                     | 98%                |
| **Incident Response Time**   | Hours                   | Minutes            |
| **Audit Trail Completeness** | None                    | 100% immutable     |

**Key Lesson:** Security controls applied during implementation (Phase 2) prevent 80% of vulnerabilities before testing, reducing risk and cost significantly.

---

## Customization Tips

### To Add New Threats

1. Add new entry to STRIDE table in Phase 1 README
2. Add vulnerability to `insecure-template.yaml`
3. Add mitigation to `secure-template.yaml`
4. Update Checkov findings list

### To Add New Services

1. Add resource to CloudFormation template
2. Update Lambda code to use the service
3. Add IAM policy for Lambda role
4. Add CloudWatch metrics/alarms
5. Update audit logging if needed

### To Scale to Multiple Environments

1. Use CloudFormation parameters for env-specific values
2. Create separate stacks for dev/staging/prod
3. Use AWS Systems Manager for orchestration
4. Enable drift detection in CloudFormation

---

## Troubleshooting

### Stack Deployment Fails

```bash
aws cloudformation describe-stack-events \
  --stack-name securebank-secure-prod \
  --query 'StackEvents[?ResourceStatus==`CREATE_FAILED`]'
```

### Lambda Function Errors

```bash
aws logs tail /aws/lambda/transfer-funds-secure --follow
```

### RDS Connection Issues

```bash
aws rds describe-db-instances \
  --db-instance-identifier securebank-db-secure \
  --query 'DBInstances[0].DBInstanceStatus'
```

### Prowler Scan Failures

```bash
aws lambda invoke \
  --function-name SecureBank-ProwlerCompliance \
  --region ap-southeast-2 \
  /tmp/response.json

aws s3 ls s3://securebank-compliance-reports-<ACCOUNT_ID>/prowler-scans/ \
  --recursive --human-readable --summarize --region ap-southeast-2
```

---

## Next Steps

1. **Extend the demo** — Add payment processing, notification service
2. **Add compliance** — PCI-DSS, SOC2 control mappings
3. **Implement SSO** — Integrate with corporate Okta/Azure AD
4. **Scale to HA** — Multi-region failover, global distribution
5. **ML/Analytics** — Anomaly detection on transaction patterns

---

## References & Further Learning

- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [STRIDE Threat Modeling](https://en.wikipedia.org/wiki/STRIDE_(security))
- [AWS Secrets Manager Best Practices](https://docs.aws.amazon.com/secretsmanager/)
- [CloudFormation Security Best Practices](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/)
- [Lambda Security Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Prowler Cloud Security](https://github.com/prowler-cloud/prowler)
