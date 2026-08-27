import boto3
from botocore.exceptions import ClientError

def check_public_s3_buckets():
    """Scans S3 buckets to identify if they are publicly accessible."""
    print("\n--- Scanning S3 Buckets for Public Access ---")
    s3_client = boto3.client('s3')
    
    try:
        buckets = s3_client.list_buckets()['Buckets']
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                # Check the Public Access Block configuration
                response = s3_client.get_public_access_block(Bucket=bucket_name)
                config = response['PublicAccessBlockConfiguration']
                
                if config.get('BlockPublicAcls') and config.get('BlockPublicPolicy'):
                    print(f"[SECURE] Bucket '{bucket_name}' blocks public access.")
                else:
                    print(f"[WARNING] Bucket '{bucket_name}' may have public access enabled!")
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    print(f"[CRITICAL] Bucket '{bucket_name}' has NO public access block configured. Highly vulnerable!")
                else:
                    print(f"[ERROR] Could not check bucket '{bucket_name}': {e}")
    except Exception as e:
        print(f"Error connecting to S3: {e}")

def check_over_permissioned_iam_users():
    """Scans IAM users for directly attached AdministratorAccess policies."""
    print("\n--- Scanning IAM Users for Excessive Permissions ---")
    iam_client = boto3.client('iam')
    
    try:
        users = iam_client.list_users()['Users']
        for user in users:
            user_name = user['UserName']
            # Get policies attached directly to the user
            policies = iam_client.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
            
            is_admin = False
            for policy in policies:
                if policy['PolicyName'] == 'AdministratorAccess':
                    is_admin = True
                    break
            
            if is_admin:
                print(f"[CRITICAL] User '{user_name}' has direct AdministratorAccess. Recommend moving to a restrictive group.")
            else:
                print(f"[SECURE] User '{user_name}' has no direct Admin policies attached.")
    except Exception as e:
        print(f"Error connecting to IAM: {e}")

if __name__ == "__main__":
    print("Starting Cloud & IAM Security Audit...")
    check_public_s3_buckets()
    check_over_permissioned_iam_users()
    print("\nAudit Complete. Please review critical findings and apply least privilege.")
