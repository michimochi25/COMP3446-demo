# COMP3446-demo

I am making a demonstration on the topic of Cloud SDLC AWS. The format will be making a small project where I apply every phase of Cloud SDLC.

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

## TODO PROMPT

Build secure and insecure AWS CloudFormation IaC for the project based on this PRD. The API endpoints are get_transaction and transfer_funds for simplicity. Create the insecure and secure ones.

# Phase 3: Test — Automated + Manual Security Testing

AWS CodeBuild runs the test pipeline. AWS Inspector scans the container image for CVEs. Manual penetration testing targets the STRIDE threats identified in Phase 1.

# Phase 4: Deploy — DAST + CSPM + Sandbox Validation

Before production, the API is deployed to an isolated sandbox environment. DAST (OWASP ZAP) attacks it like a real adversary. CSPM (AWS Security Hub) validates cloud configuration posture.

# Phase 5: Maintain — CloudWatch + CloudTrail + AWS Config

Production monitoring detects anomalies in real time. CloudTrail logs every API call for forensics. AWS Config ensures infrastructure stays compliant after deployment.
