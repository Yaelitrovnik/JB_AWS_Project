import boto3
import time
import requests
import logging
import json
from botocore.exceptions import ClientError
from functools import wraps

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def retry_on_failure(max_retries=3, delay=5):
    """Retry decorator with exponential backoff."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except ClientError as e:
                    if attempt == max_retries - 1:
                        logger.error(f"Failed after {max_retries} attempts: {e}")
                        raise
                    logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay * (2 ** attempt)} seconds...")
                    time.sleep(delay * (2 ** attempt))
        return wrapper
    return decorator

@retry_on_failure()
def create_aws_key_pair(key_name, public_key, region):
    """Create AWS key pair."""
    logger.info(f"Creating AWS key pair '{key_name}'...")
    ec2 = boto3.client("ec2", region_name=region)
    try:
        ec2.describe_key_pairs(KeyNames=[key_name])
        logger.info(f"Key pair '{key_name}' already exists. Deleting it...")
        ec2.delete_key_pair(KeyName=key_name)
    except ClientError as e:
        if "InvalidKeyPair.NotFound" not in str(e):
            raise
    response = ec2.import_key_pair(
        KeyName=key_name,
        PublicKeyMaterial=public_key,
        TagSpecifications=[{
            'ResourceType': 'key-pair',
            'Tags': [
                {'Key': 'Name', 'Value': key_name},
                {'Key': 'Project', 'Value': 'BuilderYael'}
            ]
        }]
    )
    logger.info("AWS key pair created")
    return {'key_name': key_name, 'key_fingerprint': response.get('KeyFingerprint')}

def get_user_ip():
    """Get user's public IP address with fallback."""
    logger.info("Getting your public IP address...")
    try:
        ip = requests.get('https://ifconfig.me', timeout=5).text.strip()
        logger.info(f"Auto-detected IP: {ip}")
        confirm = input("Use this IP? (y/n) [y]: ").strip().lower()
        if confirm in ['', 'y', 'yes']:
            return ip + "/32"
    except Exception as e:
        logger.warning(f"Could not auto-detect IP: {e}")
    logger.info("Please enter your public IP address (find it at: https://ifconfig.me/)")
    while True:
        ip = input("Enter your public IP: ").strip()
        if ip:
            if not ip.endswith('/32'):
                ip = ip + "/32"
            return ip
        logger.error("Please enter a valid IP address")

@retry_on_failure()
def get_public_subnet_from_vpc(vpc_id, region):
    """Find public subnet in VPC."""
    logger.info(f"Finding public subnet in VPC {vpc_id}...")
    ec2 = boto3.client("ec2", region_name=region)
    response = ec2.describe_subnets(
        Filters=[
            {'Name': 'vpc-id', 'Values': [vpc_id]},
            {'Name': 'state', 'Values': ['available']}
        ]
    )
    subnets = response['Subnets']
    if not subnets:
        logger.error(f"No subnets found in VPC {vpc_id}")
        raise Exception("No subnets found")
    for subnet in subnets:
        if subnet.get('MapPublicIpOnLaunch', False):
            logger.info(f"Found public subnet: {subnet['SubnetId']}")
            return subnet['SubnetId']
    logger.info(f"No public subnet flag found, using first available: {subnets[0]['SubnetId']}")
    return subnets[0]['SubnetId']

@retry_on_failure()
def create_security_group(vpc_id, user_ip, region, security_group_name):
    """Create security group."""
    logger.info("Creating security group...")
    ec2 = boto3.client("ec2", region_name=region)
    try:
        sg_response = ec2.describe_security_groups(
            Filters=[
                {'Name': 'group-name', 'Values': [security_group_name]},
                {'Name': 'vpc-id', 'Values': [vpc_id]}
            ]
        )
        if sg_response['SecurityGroups']:
            sg_id = sg_response['SecurityGroups'][0]['GroupId']
            logger.info(f"Using existing security group: {sg_id}")
            return sg_id
        sg_create_response = ec2.create_security_group(
            GroupName=security_group_name,
            Description="Security group for builder-yael instance",
            VpcId=vpc_id,
            TagSpecifications=[{
                'ResourceType': 'security-group',
                'Tags': [
                    {'Key': 'Name', 'Value': security_group_name},
                    {'Key': 'Project', 'Value': 'BuilderYael'}
                ]
            }]
        )
        sg_id = sg_create_response['GroupId']
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': user_ip, 'Description': 'SSH access'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 5001,
                    'ToPort': 5001,
                    'IpRanges': [{'CidrIp': user_ip, 'Description': 'Web app access'}]
                }
            ]
        )
        logger.info(f"Security group created: {sg_id}")
        return sg_id
    except ClientError as e:
        logger.error(f"Error creating security group: {e}")
        raise

@retry_on_failure()
def create_iam_role(region):
    """Create IAM role for EC2 instance."""
    logger.info("Creating IAM role for EC2 instance...")
    iam = boto3.client('iam', region_name=region)
    role_name = 'BuilderYaelEC2Role'
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }
    try:
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Tags=[{'Key': 'Name', 'Value': 'BuilderYaelEC2Role'}, {'Key': 'Project', 'Value': 'BuilderYael'}]
        )
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn='arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess'
        )
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn='arn:aws:iam::aws:policy/ElasticLoadBalancingReadOnly'
        )
        profile_response = iam.create_instance_profile(InstanceProfileName=role_name)
        iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
        logger.info(f"IAM role and instance profile created: {role_name}")
        return role_name
    except ClientError as e:
        if "EntityAlreadyExists" in str(e):
            logger.info(f"IAM role {role_name} already exists")
            return role_name
        logger.error(f"Error creating IAM role: {e}")
        raise

@retry_on_failure()
def create_ec2_instance(key_name, vpc_id, subnet_id, sg_id, region, iam_role, instance_type, instance_name):
    """Create EC2 instance."""
    logger.info("Creating EC2 instance...")
    ec2 = boto3.client("ec2", region_name=region)
    logger.info("Getting latest Amazon Linux 2 AMI...")
    try:
        response = ec2.describe_images(
            Owners=['amazon'],
            Filters=[
                {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
                {'Name': 'state', 'Values': ['available']}
            ],
            MaxItems=50
        )
        images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
        latest_ami = images[0]['ImageId']
        logger.info(f"Using AMI: {latest_ami}")
    except Exception as e:
        logger.error(f"Error finding AMI: {e}")
        raise

    user_data = """#!/bin/bash
exec > >(tee /var/log/user-data.log)
exec 2>&1
echo "Starting user data execution at $(date)"
set -e
trap 'echo "Error occurred at line $LINENO" >> /var/log/user-data.log' ERR

yum update -y
amazon-linux-extras install docker -y
service docker start
usermod -a -G docker ec2-user
yum install -y python3-pip git
pip3 install flask boto3 requests
mkdir -p /home/ec2-user/webapp
chown ec2-user:ec2-user /home/ec2-user/webapp
cat > /etc/systemd/system/webapp.service << 'EOF'
[Unit]
Description=Flask Web Application
After=network.target
[Service]
Type=simple
User=ec2-user
WorkingDirectory=/home/ec2-user/webapp
Environment=PATH=/usr/local/bin:/usr/bin:/bin
ExecStart=/usr/bin/python3 /home/ec2-user/webapp/app.py
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable webapp.service
echo "Setup completed" > /tmp/user-data-done
"""

    try:
        response = ec2.run_instances(
            ImageId=latest_ami,
            MinCount=1,
            MaxCount=1,
            InstanceType=instance_type,
            KeyName=key_name,
            IamInstanceProfile={'Name': iam_role},
            NetworkInterfaces=[{
                "DeviceIndex": 0,
                "SubnetId": subnet_id,
                "AssociatePublicIpAddress": True,
                "Groups": [sg_id]
            }],
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': instance_name},
                    {'Key': 'Project', 'Value': 'BuilderYael'}
                ]
            }],
            UserData=user_data
        )
        instance_id = response['Instances'][0]['InstanceId']
        logger.info(f"Instance launched: {instance_id}")
        logger.info("Waiting for instance to be running (up to 10 minutes)...")
        waiter = ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id], WaiterConfig={'Delay': 15, 'MaxAttempts': 40})
        instance_info = ec2.describe_instances(InstanceIds=[instance_id])
        instance = instance_info['Reservations'][0]['Instances'][0]
        return {
            'instance_id': instance_id,
            'public_ip': instance.get('PublicIpAddress'),
            'public_dns': instance.get('PublicDnsName'),
            'ami_id': latest_ami,
            'instance_type': instance_type,
            'vpc_id': vpc_id,
            'subnet_id': subnet_id,
            'security_group_id': sg_id,
            'region': region
        }
    except Exception as e:
        logger.error(f"Error creating instance: {e}")
        raise