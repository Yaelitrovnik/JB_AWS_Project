#!/usr/bin/env python3
"""
SSH Key Generation and EC2 Instance Creation Script
Creates EC2 instance in specified VPC with a new security group.
"""

import boto3
import os
import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from botocore.exceptions import ClientError, NoCredentialsError

def generate_ssh_key():
    """Generate an RSA SSH key pair (4096 bits)."""
    print("Generating RSA SSH key pair (4096 bits)...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_openssh = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode("utf-8")
    return {'private_key_pem': private_key_pem, 'public_key_openssh': public_key_openssh}

def save_private_key_locally(private_key_pem, filename="builder_key.pem"):
    """Save the private key locally with 0600 permissions."""
    print(f"Saving private key to {filename}...")
    full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    try:
        with open(full_path, "wb") as f:
            f.write(private_key_pem)
        os.chmod(full_path, 0o600)
        print("Private key saved with 0600 permissions")
        return {'filename': full_path, 'content': private_key_pem}
    except Exception as e:
        print(f"Error saving private key: {e}")
        sys.exit(1)

def create_aws_key_pair(key_name, public_key, region="us-east-2"):
    """Create an AWS key pair using the public key."""
    print(f"Creating AWS key pair '{key_name}' in {region}...")
    try:
        ec2 = boto3.client("ec2", region_name=region)
        try:
            ec2.describe_key_pairs(KeyNames=[key_name])
            print(f"Key pair '{key_name}' already exists. Deleting it...")
            ec2.delete_key_pair(KeyName=key_name)
        except ClientError as e:
            if "InvalidKeyPair.NotFound" not in str(e):
                raise
        response = ec2.import_key_pair(KeyName=key_name, PublicKeyMaterial=public_key)
        print(f"AWS key pair '{key_name}' created successfully")
        return {
            'key_name': key_name,
            'key_fingerprint': response.get('KeyFingerprint'),
            'key_pair_id': response.get('KeyPairId')
        }
    except NoCredentialsError:
        print("AWS credentials not configured.")
        sys.exit(1)
    except ClientError as e:
        print(f"AWS Error: {e}")
        sys.exit(1)

def get_public_subnet_from_vpc(vpc_id, region="us-east-2"):
    """Get a public subnet from the specified VPC."""
    print(f"Finding public subnet in VPC {vpc_id}...")
    ec2 = boto3.client("ec2", region_name=region)
    response = ec2.describe_subnets(
        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}, {'Name': 'state', 'Values': ['available']}]
    )
    subnets = response['Subnets']
    if not subnets:
        raise Exception(f"No subnets found in VPC {vpc_id}")
    for subnet in subnets:
        if subnet.get('MapPublicIpOnLaunch', False):
            print(f"Found public subnet: {subnet['SubnetId']}")
            return subnet['SubnetId']
    print(f"No public subnet flag found, using first available: {subnets[0]['SubnetId']}")
    return subnets[0]['SubnetId']

def create_security_group(vpc_id, region="us-east-2"):
    """Create a new security group or reuse existing one."""
    print("Creating or using existing security group...")
    ec2 = boto3.client("ec2", region_name=region)
    sg_name = "builder-yael-sg"

    try:
        # Check if SG exists
        sg_response = ec2.describe_security_groups(
            Filters=[
                {'Name': 'group-name', 'Values': [sg_name]},
                {'Name': 'vpc-id', 'Values': [vpc_id]}
            ]
        )
        if sg_response['SecurityGroups']:
            sg_id = sg_response['SecurityGroups'][0]['GroupId']
            print(f"Using existing security group: {sg_id}")
            return sg_id

        # Otherwise create new SG
        sg_create_response = ec2.create_security_group(
            GroupName=sg_name,
            Description="Security group for builder-yael instance - SSH and port 5001",
            VpcId=vpc_id
        )
        sg_id = sg_create_response['GroupId']

        # Restrict inbound rules to student IP
        student_ip = "79.177.146.136"
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': student_ip, 'Description': 'SSH access from student IP'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 5001,
                    'ToPort': 5001,
                    'IpRanges': [{'CidrIp': student_ip, 'Description': 'Port 5001 access from student IP'}]
                }
            ]
        )

        print(f"Security group created: {sg_id}")
        return sg_id

    except ClientError as e:
        print(f"Error creating security group: {e}")
        sys.exit(1)

def create_ec2_instance(key_name, region="us-east-2"):
    """Create an EC2 instance with SSH key and security group."""
    print("Creating EC2 instance...")
    ec2 = boto3.client("ec2", region_name=region)
    vpc_id = "vpc-0c678d4904a68bd91"  
    subnet_id = get_public_subnet_from_vpc(vpc_id, region)
    sg_id = create_security_group(vpc_id, region)

    print("Getting latest Amazon Linux 2 AMI...")
    response = ec2.describe_images(
        Owners=['amazon'],
        Filters=[{'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']}, {'Name': 'state', 'Values': ['available']}]
    )
    images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
    latest_ami = images[0]['ImageId']
    print(f"Using AMI: {latest_ami}")

    response = ec2.run_instances(
        ImageId=latest_ami,
        MinCount=1,
        MaxCount=1,
        InstanceType='t3.medium',
        KeyName=key_name,
        NetworkInterfaces=[{
            "DeviceIndex": 0,
            "SubnetId": subnet_id,
            "AssociatePublicIpAddress": True,
            "Groups": [sg_id]
        }],
        TagSpecifications=[{
            'ResourceType': 'instance',
            'Tags': [{'Key': 'Name', 'Value': 'builder-yael'}]
        }]
    )

    instance_id = response['Instances'][0]['InstanceId']
    print(f"Instance launched: {instance_id}")
    waiter = ec2.get_waiter('instance_running')
    waiter.wait(InstanceIds=[instance_id])
    instance_info = ec2.describe_instances(InstanceIds=[instance_id])
    instance = instance_info['Reservations'][0]['Instances'][0]
    return {
        'instance_id': instance_id,
        'public_ip': instance.get('PublicIpAddress'),
        'public_dns': instance.get('PublicDnsName'),
        'ami_id': latest_ami,
        'instance_type': 't3.medium',
        'vpc_id': vpc_id,
        'subnet_id': subnet_id,
        'security_group_id': sg_id,
        'region': region
    }

def main():
    print("Starting SSH Key Generation and EC2 Instance Creation")
    print("="*65)
    print("\n1 SSH Key Generation")
    ssh_key = generate_ssh_key()
    print("\nSave Private Key Locally")
    private_key_file = save_private_key_locally(ssh_key['private_key_pem'], "builder_key.pem")
    print("\nCreate AWS Key Pair")
    aws_key_pair = create_aws_key_pair("builder-key", ssh_key['public_key_openssh'], "us-east-2")
    print("\nCreate EC2 Instance")
    ec2_instance = create_ec2_instance("builder-key", "us-east-2")
    
    print("\n" + "="*65)
    print("TERRAFORM-STYLE OUTPUTS")
    print("="*65)
    print(f"ssh_private_key_path = \"{private_key_file['filename']}\" (sensitive)")
    print(f"ssh_key_name = \"{aws_key_pair['key_name']}\"")
    print(f"instance_id = \"{ec2_instance['instance_id']}\"")
    print(f"instance_name = \"builder-yael\"")
    print(f"instance_type = \"{ec2_instance['instance_type']}\"")
    print(f"instance_public_ip = \"{ec2_instance['public_ip']}\"")
    print(f"instance_public_dns = \"{ec2_instance['public_dns']}\"")
    print(f"vpc_id = \"{ec2_instance['vpc_id']}\"")
    print(f"subnet_id = \"{ec2_instance['subnet_id']}\"")
    print(f"region = \"{ec2_instance['region']}\"")
    print(f"\nAdditional Information:")
    print(f"Key Fingerprint: {aws_key_pair['key_fingerprint']}")
    print(f"Key Pair ID: {aws_key_pair['key_pair_id']}")
    print(f"AMI ID: {ec2_instance['ami_id']} (Amazon Linux 2)")
    print(f"Security Group: {ec2_instance['security_group_id']}")
    print(f"\nSSH Command: ssh -i \"{private_key_file['filename']}\" ec2-user@{ec2_instance['public_ip']}")
    print(f"\nSUCCESS! Instance 'builder-yael' created in {ec2_instance['region']}")

if __name__ == "__main__":
    main()