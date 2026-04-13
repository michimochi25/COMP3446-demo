#!/bin/bash

# Production readiness validation using Prowler
echo "=== Production Readiness Checklist with Prowler ==="

# Locate the exact JSON file you already generated
REPORT_JSON=$(ls prowler-reports/*.json 2>/dev/null | head -n 1)

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
COMPLIANCE_JSON=$(ls prowler-reports/cis/*.json 2>/dev/null | head -n 1)

echo -e "\n=== Compliance Summary ==="
if [ -z "$COMPLIANCE_JSON" ]; then
  echo "⚠️ No CIS compliance report found."
else
  jq -r '.[] | "\(.metadata.event_code): \(.status_code)"' "$COMPLIANCE_JSON" | sort | uniq -c
fi

echo -e "\n=== Ready for promotion to production ==="
