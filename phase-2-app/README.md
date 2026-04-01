# Phase 2 Application - SecureBank Transaction API

## Overview

This directory contains the Python Lambda function code for the two main API endpoints of the SecureBank Transaction Processing System:

1. **GET /transactions** — Retrieve account transaction history
2. **POST /transfer** — Transfer funds between accounts

Each endpoint demonstrates comprehensive security controls aligned with the STRIDE threat model from Phase 1.

## Files

- `lambda_functions.py` — Implementation of both Lambda handlers with detailed security comments
- `requirements.txt` — Python dependencies for local development and scanning
- `README.md` — This file

## Security Controls Implemented

### Authentication & Authorization (Anti-Spoofing)

- **Cognito User Pools Integration**: Every endpoint requires a valid JWT from Cognito
- **User Identity Extraction**: Request context claims provide authenticated user ID
- **Authorization Checks**: User ownership verification before accessing account data

```python
# Example: User authentication check
claims = event['requestContext']['authorizer']['claims']
user_id = claims.get('sub')  # from JWT
if not user_id:
    return {'statusCode': 401, 'body': json.dumps({'error': 'Unauthorized'})}
```

### Input Validation & Parameterized Queries (Anti-Tampering, Anti-Injection)

- **Type Checking**: Validate input types match expectations
- **Length Validation**: Enforce maximum lengths on IDs
- **Parameterized Queries**: Use `%s` placeholders to prevent SQL injection

```python
# INSECURE: Vulnerable to SQL injection
query = f"SELECT * FROM accounts WHERE id = {account_id}"

# SECURE: Parameterized query prevents injection
query = "SELECT * FROM accounts WHERE id = %s"
cursor.execute(query, (account_id,))
```

### Secrets Management (Anti-Info Disclosure)

- **Secrets Manager**: Retrieve credentials at runtime, never hardcoded
- **No Environment Variables**: Don't expose secrets via Lambda env vars
- **Automatic Rotation**: Secrets Manager can auto-rotate credentials

```python
def get_db_credentials():
    secret_arn = os.environ['DB_SECRET_ARN']
    response = secrets_client.get_secret_value(SecretId=secret_arn)
    return json.loads(response['SecretString'])
```

### Audit Logging (Anti-Repudiation)

- **Immutable S3 Logs**: All transactions logged to encrypted, versioned S3 bucket
- **KMS Encryption**: Audit logs encrypted with customer-managed KMS key
- **Request Tracking**: Unique request IDs for correlation and forensics

```python
def audit_log(event_type, user_id, account_id, status):
    log_entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'event_type': event_type,
        'user_id': user_id,
        'account_id': account_id,
        'status': status,
        'request_id': str(uuid.uuid4())
    }
    s3_client.put_object(
        Bucket=AUDIT_BUCKET,
        ServerSideEncryption='aws:kms',
        SSEKMSKeyId=KMS_KEY_ID
    )
```

### Transaction Atomicity (Anti-Tampering)

- **Database Transactions**: All-or-nothing fund transfers using START TRANSACTION
- **Conflict Detection**: Check balances before debit, verify recipient exists before credit
- **Automatic Rollback**: Failed operations are rolled back to maintain consistency

```python
cursor.execute("START TRANSACTION")
cursor.execute("UPDATE accounts SET balance = balance - %s WHERE id = %s AND balance >= %s", (...))
if cursor.rowcount == 0:
    conn.rollback()  # Insufficient funds
    return error_response
# ... continue with credit operation ...
conn.commit()  # Only if all operations succeed
```

### Error Handling (Anti-Info Disclosure)

- **Generic Error Messages**: Don't expose stack traces or database details to clients
- **Internal Logging**: Detailed errors logged server-side for debugging
- **RequestID Tracking**: Include request ID in response for support investigation

```python
# INSECURE: Exposes database internals
return {'error': "Access denied for user 'admin'@'<IP>' (using password: YES)"}

# SECURE: Generic message, detailed logging
logger.error(f"{request_id}: {str(e)}")  # Logged internally
return {'error': 'An error occurred'}  # Generic to user
```

## API Endpoint Specifications

### GET /transactions

**Purpose**: Retrieve transaction history for an account

**Authentication**: Required (JWT from Cognito)

**Request**:

```bash
curl -H "Authorization: Bearer <JWT_TOKEN>" \
  https://api.securebank.example.com/prod/transactions?account_id=1001
```

**Response (Success)**:

```json
{
  "data": [
    {
      "id": 1,
      "account_id": "1001",
      "amount": 500.0,
      "timestamp": "2024-01-15T10:30:00"
    },
    {
      "id": 2,
      "account_id": "1001",
      "amount": -100.0,
      "timestamp": "2024-01-14T15:45:00"
    }
  ]
}
```

**Response (Error)**:

```json
{
  "error": "Invalid request" // Generic message
}
```

**Query Parameters**:

- `account_id` (required): Account ID to retrieve transactions for (format: digits, max 10 chars)

### POST /transfer

**Purpose**: Transfer funds between accounts with audit trail

**Authentication**: Required (JWT from Cognito)

**Request**:

```bash
curl -X POST \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "from_account": "1001",
    "to_account": "1002",
    "amount": 100.00,
    "idempotency_key": "unique-key-for-this-transfer"
  }' \
  https://api.securebank.example.com/prod/transfer
```

**Response (Success)**:

```json
{
  "status": "success",
  "transaction_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "amount": "100.00"
}
```

**Response (Error - Insufficient Funds)**:

```json
{
  "error": "Insufficient funds"
}
```

**Request Body**:

- `from_account` (required): Source account ID
- `to_account` (required): Destination account ID
- `amount` (required): Amount to transfer (positive number, max 1,000,000)
- `idempotency_key` (optional): Unique identifier for request idempotency

## Database Schema

### accounts table

```sql
CREATE TABLE accounts (
    id VARCHAR(10) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    balance DECIMAL(15, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_user_id (user_id)
);
```

### transactions table (immutable audit log)

```sql
CREATE TABLE transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    from_account VARCHAR(10) NOT NULL,
    to_account VARCHAR(10) NOT NULL,
    amount DECIMAL(15, 2) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_from_account (from_account),
    INDEX idx_to_account (to_account),
    INDEX idx_timestamp (timestamp)
);
```

## Local Development Setup

### Prerequisites

- Python 3.11+
- Docker (for local MySQL testing)
- AWS CLI configured with credentials
- Cognito User Pool

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start Local MySQL Database (Docker)

```bash
docker run -d \
  --name securebank-mysql \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=secure_bank \
  -p 3306:3306 \
  mysql:8.0

# Wait for container to start
sleep 10

# Initialize database schema
mysql -h 127.0.0.1 -u root -proot secure_bank << 'EOF'
CREATE TABLE accounts (
    id VARCHAR(10) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    balance DECIMAL(15, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    from_account VARCHAR(10) NOT NULL,
    to_account VARCHAR(10) NOT NULL,
    amount DECIMAL(15, 2) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO accounts VALUES ('1001', 'user-001', 10000.00, NOW(), NOW());
INSERT INTO accounts VALUES ('1002', 'user-002', 5000.00, NOW(), NOW());
EOF
```

### 3. Test Locally with Lambda Handler Simulation

```bash
# Create test event
cat > test-event-get.json << 'EOF'
{
  "requestContext": {
    "authorizer": {
      "claims": {
        "sub": "user-001"
      }
    }
  },
  "queryStringParameters": {
    "account_id": "1001"
  }
}
EOF

# Invoke handler (requires AWS SAM or manual simulation)
python -c "
import json
import os
os.environ['DB_HOST'] = '127.0.0.1'
os.environ['DB_SECRET_ARN'] = 'arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:test'
os.environ['DB_NAME'] = 'secure_bank'

# This would require mocking Secrets Manager, Lambda handler invocation, etc.
# See: https://docs.aws.amazon.com/lambda/latest/dg/python-handler.html
"
```

## Security Scanning

### IaC Scanning with Checkov

```bash
checkov -f ../phase-2-iac/secure-template.yaml --framework cloudformation
```

### SAST with Semgrep

```bash
semgrep --config=p/owasp-top-ten lambda_functions.py
```

### Secret Detection

```bash
detect-secrets scan .
```

## Deployment to AWS

### Option 1: CloudFormation (Recommended for Demo)

See `../phase-2-iac/` for secure and insecure CloudFormation templates.

### Option 2: AWS SAM (For Development)

```bash
sam init --location <s3-uri>
sam build
sam deploy --guided
```

### Option 3: Manual Lambda Creation

```bash
# Package function
zip function.zip lambda_functions.py

# Create role
aws iam create-role --role-name lambda-role \
  --assume-role-policy-document file://trust-policy.json

# Create Lambda function
aws lambda create-function \
  --function-name get-transaction-secure \
  --runtime python3.11 \
  --handler lambda_functions.handler \
  --zip-file fileb://function.zip \
  --role arn:aws:iam::ACCOUNT:role/lambda-role
```

## Monitoring & Logging

### CloudWatch Logs

```bash
aws logs tail /aws/lambda/get-transaction-secure --follow
aws logs tail /aws/lambda/transfer-funds-secure --follow
```

### Request Tracing

```bash
# Find logs for specific request ID
aws logs filter-log-events \
  --log-group-name /aws/lambda/transfer-funds-secure \
  --filter-pattern "request-id-xyz"
```

### Audit Log Review

```bash
# List audit logs in S3
aws s3 ls s3://securebank-audit-logs-<account>/audit/

# Retrieve specific log
aws s3 cp s3://securebank-audit-logs-<account>/audit/2024/01/15/<file>.json -
```

## Best Practices Applied

✅ **Never hardcode credentials** — Use Secrets Manager
✅ **Always validate input** — Type and length checks
✅ **Use parameterized queries** — SQL injection prevention
✅ **Implement transaction control** — Atomicity for financial operations
✅ **Comprehensive audit logging** — Immutable S3 with encryption
✅ **Generic error messages** — No information leakage
✅ **Request tracking** — Unique IDs for correlation
✅ **No verbose logs** — Sensitive data protection
✅ **Least privilege IAM** — Only necessary permissions
✅ **Defense in depth** — Multiple layers of security

## Common Issues & Troubleshooting

### Issue: "Connection refused" to RDS

```
Check that Lambda has correct security group and RDS is in same VPC
aws ec2 describe-security-groups --group-ids sg-xxxxx
```

### Issue: "Access denied" to Secrets Manager

```
Verify Lambda IAM role has secretsmanager:GetSecretValue on the secret ARN
aws iam get-role-policy --role-name LambdaExecutionRoleSecure --policy-name SecureBankLambdaPolicy
```

### Issue: "Unauthorized" from API Gateway

```
Check Cognito authorizer is attached to API method
aws apigateway get-method --rest-api-id api-id --resource-id resource-id --http-method GET
```

## Further Reading

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [AWS Lambda Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [AWS Secrets Manager Rotation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets.html)
- [AWS WAF SQL Injection Protection](https://docs.aws.amazon.com/waf/latest/developerguide/sql-injection.html)
