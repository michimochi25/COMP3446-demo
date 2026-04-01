# COMP3446 Cloud SDLC Demo — Project Structure

## Overview

This demonstration project shows how security is applied across all phases of the Cloud SDLC (Secure Development Lifecycle) using AWS services and a realistic banking API scenario.

## Project Layout

```
COMP3446-demo/
├── README.md                          # Main project guide with Phase 1-5 instructions
├── index.html                         # Interactive web UI demonstrating all phases
│
├── phase-2-iac/                       # Infrastructure as Code (CloudFormation)
│   ├── README.md                      # Phase 2 IaC instructions & vulnerability analysis
│   ├── insecure-template.yaml         # CloudFormation with 6 STRIDE vulnerabilities
│   └── secure-template.yaml           # Production-ready hardened CloudFormation
│
├── phase-2-app/                       # Application Code (Lambda Functions)
    ├── README.md                      # Lambda development guide
    ├── lambda_functions.py            # GET /transactions & POST /transfer implementations
    └── requirements.txt               # Python dependencies for scanning & deployment

```

## Phase-by-Phase Walkthrough

### Phase 1: Plan & Design ✅

**Focus**: Threat modelling, architecture design
**Deliverables**: STRIDE analysis, architecture diagrams, design decisions
**Location**: Main `README.md` Phase 1 section + `index.html`

**Key Decisions**:

- Zero Trust Architecture — No implicit trust inside VPC
- Secrets Manager for all credentials — Never hardcoded
- Encryption everywhere — TLS 1.3 in transit, AES-256 at rest
- API versioning — /v1/ prefix with deprecation policy
- Least privilege IAM — Role-based access control

### Phase 2: Implement ✅

**Focus**: Secure coding, IaC best practices, vulnerability scanning
**Deliverables**: CloudFormation templates, Lambda code, SAST reports
**Location**: `phase-2-iac/` and `phase-2-app/` directories

**What's in the Code**:

#### Insecure Version (Educational)

- Hardcoded database password
- Publicly accessible RDS
- No authentication on API endpoints
- Unencrypted S3 bucket
- Overly permissive IAM role
- No audit logging
- Vulnerable SQL queries
- Verbose error messages

#### Secure Version (Production-Ready)

- Secrets Manager for credentials
- Private VPC with security groups
- Cognito User Pools authentication
- KMS encryption for RDS & S3
- Least privilege IAM role
- CloudTrail + immutable S3 audit logs
- Parameterized SQL queries
- Generic error messages

**Security Controls**:

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

### Phase 3: Test ✅

**Focus**: Automated security testing, SAST, DAST preparation
**Deliverables**: CodeBuild pipeline, Checkov/Semgrep scan results
**Location**: Main `README.md` Phase 3 section

**Testing Tools**:

- **Checkov** — IaC scanning (finds 8+ critical issues in insecure template)
- **Semgrep** — SAST for Lambda code (detects SQL injection patterns)
- **detect-secrets** — Find hardcoded secrets
- **AWS CodeBuild** — Automated pipeline for continuous testing

### Phase 4: Deploy ✅

**Focus**: DAST penetration testing, cloud posture verification
**Deliverables**: Sandbox deployment, OWASP ZAP results, Security Hub findings
**Location**: Main `README.md` Phase 4 section

**Validation**:

- Deploy to staging environment
- Run DAST with OWASP ZAP
- Enable AWS Security Hub for CSPM
- Verify encryption, authentication, logging
- Compliance score > 95%

### Phase 5: Maintain ✅

**Focus**: Production monitoring, incident response, compliance automation
**Deliverables**: CloudWatch dashboards, CloudTrail audit logs, Config rules
**Location**: Main `README.md` Phase 5 section

**Monitoring Stack**:

- CloudWatch for real-time metrics & alarms
- CloudTrail for immutable API audit logs
- AWS Config for continuous compliance
- EventBridge for automated remediation
- SNS for security alerts

---

## How to Use This Demo

### For Instructors/Presenters

1. **Start with `index.html`** — Interactive UI showing all phases visually
2. **Phase 1**: Explain STRIDE threat model and architecture
3. **Phase 2**: Deploy insecure template, run Checkov, show vulnerabilities
4. **Phase 2**: Deploy secure template, compare Checkov results
5. **Phase 3**: Run automated security scans
6. **Phase 4**: Deploy to sandbox, show DAST and Security Hub
7. **Phase 5**: Demonstrate CloudWatch monitoring and ClusterTrail logs

### For Students/Learners

1. **Read** main `README.md` for full context
2. **Study** `phase-2-iac/insecure-template.yaml` to understand common mistakes
3. **Compare** with `phase-2-iac/secure-template.yaml` to learn best practices
4. **Review** comments in `phase-2-app/lambda_functions.py` for secure coding patterns
5. **Hands-on**: Deploy templates to AWS account, run security scans
6. **Experiment**: Introduce vulnerabilities, run scans to detect them

### For Security Teams

1. **Baseline**: Insecure template represents typical findings in audits
2. **Hardening**: Secure template shows required controls for compliance
3. **Tooling**: Demonstrates integration of Checkov, Semgrep, DAST, CSPM
4. **Policy**: Security controls show what to enforce in IaC policy
5. **Testing**: Example of comprehensive security testing approach

---

## Technology Stack

| Component      | Technology            | Purpose                        |
| -------------- | --------------------- | ------------------------------ |
| **IaC**        | AWS CloudFormation    | Define infrastructure securely |
| **Compute**    | AWS Lambda            | Serverless API endpoints       |
| **Database**   | Amazon RDS MySQL      | Transactional database         |
| **Storage**    | Amazon S3 + KMS       | Encrypted audit logs           |
| **Auth**       | Amazon Cognito        | User authentication (JWT)      |
| **Secrets**    | AWS Secrets Manager   | Credential management          |
| **Encryption** | AWS KMS               | Encryption key management      |
| **API**        | API Gateway + WAF     | REST API with DDoS protection  |
| **Network**    | VPC + Security Groups | Network isolation              |
| **Monitoring** | CloudWatch            | Metrics, logs, alarms          |
| **Audit**      | CloudTrail            | Immutable API logs             |
| **Compliance** | Security Hub + Config | Posture & compliance           |
| **Testing**    | CodeBuild             | Automated security pipeline    |
| **SAST**       | Checkov, Semgrep      | Static analysis                |
| **DAST**       | OWASP ZAP             | Dynamic penetration testing    |

---

## Key Files to Review

### For Understanding Vulnerabilities

1. `phase-2-iac/insecure-template.yaml` (Lines 1-150) — Database security issues
2. `phase-2-iac/insecure-template.yaml` (Lines 151-200) — IAM overpermission
3. `phase-2-iac/insecure-template.yaml` (Lines 200-250) — No authentication
4. `phase-2-iac/insecure-template.yaml` (Lines 250+) — Lambda inline code with SQL injection

### For Understanding Solutions

1. `phase-2-iac/secure-template.yaml` (Lines 1-100) — VPC & network isolation
2. `phase-2-iac/secure-template.yaml` (Lines 100-200) — KMS encryption & Secrets Manager
3. `phase-2-iac/secure-template.yaml` (Lines 200-400) — Secure Lambda with input validation
4. `phase-2-iac/secure-template.yaml` (Lines 400-500) — API Gateway + Cognito authorizer
5. `phase-2-iac/secure-template.yaml` (Lines 500+) — CloudTrail + WAF

### For Code Security Patterns

1. `phase-2-app/lambda_functions.py` — Comprehensive inline comments explaining security controls

---

## Demo Scenarios

### Scenario 1: "Find the Vulnerabilities" (30 mins)

1. Deploy insecure template
2. Attendees list security issues
3. Run Checkov to validate findings
4. Discuss impact of each vulnerability

**Learning**: Common misconfigurations in production

### Scenario 2: "Fix the Issues" (45 mins)

1. Review insecure vs. secure templates side-by-side
2. Explain each security control addition
3. Deploy secure template
4. Compare Checkov/Semgrep results

**Learning**: How to implement security controls

### Scenario 3: "Attack the API" (30 mins)

1. Deploy insecure API to accessible endpoint
2. Demonstrate SQL injection, authentication bypass
3. Deploy secure API
4. Show WAF/auth protecting against same attacks

**Learning**: Real-world exploitation and prevention

### Scenario 4: "Incident Response" (40 mins)

1. Simulate suspicious activity in CloudTrail
2. Alert via CloudWatch alarm
3. Investigate using logs
4. Create incident report
5. Show Config rules for remediation

**Learning**: Detection, investigation, remediation workflow

---

## Estimated Time

| Phase     | Activity                             | Time        |
| --------- | ------------------------------------ | ----------- |
| 1         | STRIDE threat modeling discussion    | 20 min      |
| 2         | Deploy templates + security scans    | 30 min      |
| 2         | Code review (secure vs. insecure)    | 20 min      |
| 3         | Run automated tests, review findings | 15 min      |
| 4         | Deploy to sandbox, DAST scan         | 20 min      |
| 4         | Security Hub review                  | 10 min      |
| 5         | Monitoring dashboard + alerts        | 15 min      |
| 5         | CloudTrail forensics                 | 10 min      |
| **Total** | **Full demo**                        | **140 min** |

---

## Customization Tips

### To Add New Threats

1. Add new entry to STRIDE table in Phase 1 README
2. Add vulnerability to insecure-template.yaml
3. Add mitigation to secure-template.yaml
4. Update Checkov findings list

### To Add New Services

1. Add resource to CloudFormation template
2. Update Lambda code to use service
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

---

## Next Steps

1.  **Extend the demo** — Add payment processing, notification service
2.  **Add compliance** — PCI-DSS, SOC2 control mappings
3.  **Implement SSO** — Integrate with corporate Okta/Azure AD
4.  **Scale to HA** — Multi-region failover, global distribution
5.  **ML/Analytics** — Anomaly detection on transaction patterns

---

## References & Further Learning

- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [STRIDE Threat Modeling](<https://en.wikipedia.org/wiki/STRIDE_(security)>)
- [AWS Secrets Manager Best Practices](https://docs.aws.amazon.com/secretsmanager/)
- [CloudFormation Security Best Practices](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/)
- [Lambda Security Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)

---

**Last Updated**: April 2024  
**Author**: COMP3446 Cloud SDLC Instructors  
**License**: Educational Use
