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
