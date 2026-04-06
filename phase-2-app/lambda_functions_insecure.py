"""
Phase 2 Application Code: Insecure Lambda Functions for SecureBank API

This file demonstrates insecure implementation patterns for the demo:
- No authentication or authorization
- Hardcoded credentials / environment-based unsafe secrets
- No input validation
- Unparameterized SQL construction
- No audit logging or secure error handling
- No transaction atomicity or balance verification
"""

import json
import mysql.connector
import os
import logging
import uuid

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Insecure configuration: credentials may be hardcoded or stored in plain environment vars
DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_NAME = os.environ.get('DB_NAME', 'secure_bank')
DB_USER = os.environ.get('DB_USER', 'admin')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'BankPassword123!')


def get_db_connection():
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )


def handler(event, context):
    """GET /transactions insecure handler."""
    request_id = str(uuid.uuid4())

    try:
        query_params = event.get('queryStringParameters') or {}
        account_id = query_params.get('account_id')

        if not account_id:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing account_id parameter'})
            }

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # INSECURE: direct string formatting without parameterization
        query = f"SELECT id, account_id, amount, timestamp FROM transactions WHERE account_id = '{account_id}' LIMIT 100"
        cursor.execute(query)
        results = cursor.fetchall()

        cursor.close()
        conn.close()

        logger.info(f"{request_id}: Retrieved {len(results)} transactions for account {account_id}")

        return {
            'statusCode': 200,
            'body': json.dumps({'data': results}),
            'headers': {
                'Content-Type': 'application/json'
            }
        }

    except Exception as e:
        logger.error(f"{request_id}: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }



def transfer_handler(event, context):
    """POST /transfer insecure handler."""
    request_id = str(uuid.uuid4())

    try:
        try:
            body = json.loads(event.get('body') or '{}')
        except json.JSONDecodeError:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid JSON'})
            }

        from_account = body.get('from_account')
        to_account = body.get('to_account')
        amount = body.get('amount')
        user_id = body.get('user_id', 'anonymous')

        if not from_account or not to_account or amount is None:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing transfer fields'})
            }

        conn = get_db_connection()
        cursor = conn.cursor()

        # INSECURE: no validation or authorization, no transaction atomicity
        debit_sql = f"UPDATE accounts SET balance = balance - {amount} WHERE id = '{from_account}'"
        cursor.execute(debit_sql)

        credit_sql = f"UPDATE accounts SET balance = balance + {amount} WHERE id = '{to_account}'"
        cursor.execute(credit_sql)

        transaction_sql = (
            "INSERT INTO transactions (from_account, to_account, amount, user_id, timestamp) "
            f"VALUES ('{from_account}', '{to_account}', {amount}, '{user_id}', NOW())"
        )
        cursor.execute(transaction_sql)

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"{request_id}: Transfer from {from_account} to {to_account} completed")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'status': 'success',
                'message': 'Transfer completed',
                'request_id': request_id
            }),
            'headers': {
                'Content-Type': 'application/json'
            }
        }

    except Exception as e:
        logger.error(f"{request_id}: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
