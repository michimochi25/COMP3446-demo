
import json
import mysql.connector
import os
import uuid


def handler(event, context):
    # VULNERABILITY: No authentication/authorization
    # VULNERABILITY: Direct SQL query without parameterization risk
    # VULNERABILITY: No input validation
    account_id = event.get('account_id')  # No validation!
    try:
        conn = mysql.connector.connect(
            host=os.environ['DB_HOST'],
            user=os.environ['DB_USER'],
            password=os.environ['DB_PASSWORD'],
            database=os.environ['DB_NAME']
        )
        cursor = conn.cursor()
        
        # VULNERABILITY: No parameterized queries
        query = f"SELECT * FROM transactions WHERE account_id = {account_id}"
        cursor.execute(query)
        result = cursor.fetchall()
        
        return {
            'statusCode': 200,
            'body': json.dumps(result)  # VULNERABILITY: Sensitive data exposed!
        }
    except Exception as e:
        # VULNERABILITY: Verbose error messages expose system details
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})  # Stack trace leakage!
        }



def handler(event, context):
    # VULNERABILITY: No authentication
    # VULNERABILITY: No authorization/permission checks
    # VULNERABILITY: No idempotency token (replay attacks possible)
    # VULNERABILITY: No rate limiting
    
    from_account = event.get('from_account')  # No validation!
    to_account = event.get('to_account')  # No validation!
    amount = event.get('amount')  # No validation!
    
    try:
        conn = mysql.connector.connect(
            host=os.environ['DB_HOST'],
            user=os.environ['DB_USER'],
            password=os.environ['DB_PASSWORD'],
            database=os.environ['DB_NAME']
        )
        cursor = conn.cursor()
        
        # VULNERABILITY: No transaction atomicity checks
        # VULNERABILITY: SQL injection possible
        debit_query = f"UPDATE accounts SET balance = balance - {amount} WHERE id = {from_account}"
        credit_query = f"UPDATE accounts SET balance = balance + {amount} WHERE id = {to_account}"
        
        cursor.execute(debit_query)
        cursor.execute(credit_query)
        conn.commit()  # VULNERABILITY: No rollback on partial failure!
        
        # VULNERABILITY: No audit log
        return {
            'statusCode': 200,
            'body': json.dumps({'status': 'transferred'})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
