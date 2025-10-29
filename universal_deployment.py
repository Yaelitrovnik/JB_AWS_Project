#!/usr/bin/env python3
"""
AWS Infrastructure + Web App Deployment Script
Creates AWS EC2 instance and deploys a Flask web dashboard (systemd service).
Works on Windows, Mac, and Linux - Ubuntu Version.
"""

import boto3
import os
import sys
import subprocess
import platform
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from botocore.exceptions import ClientError, NoCredentialsError

# ------------------------------
# Helper functions
# ------------------------------

def detect_platform():
    system = platform.system().lower()
    has_ssh = False
    try:
        subprocess.run(["ssh", "-V"], capture_output=True, timeout=5)
        has_ssh = True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        has_ssh = False
    return {'system': system, 'is_windows': system == 'windows', 'has_ssh': has_ssh}

def generate_ssh_key():
    print("🔑 Generating SSH key pair...")
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
    print(f"💾 Saving private key to {filename}...")
    full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    try:
        with open(full_path, "wb") as f:
            f.write(private_key_pem)
        if os.name != 'nt':
            os.chmod(full_path, 0o600)
        return {'filename': full_path}
    except Exception as e:
        print(f"❌ Error saving private key: {e}")
        sys.exit(1)

def create_aws_key_pair(key_name, public_key, region="us-east-2"):
    print(f"🔐 Creating AWS key pair '{key_name}'...")
    try:
        ec2 = boto3.client("ec2", region_name=region)
        try:
            ec2.describe_key_pairs(KeyNames=[key_name])
            print(f"🗑️ Deleting existing key pair...")
            ec2.delete_key_pair(KeyName=key_name)
        except ClientError as e:
            if "InvalidKeyPair.NotFound" not in str(e):
                raise
        ec2.import_key_pair(KeyName=key_name, PublicKeyMaterial=public_key)
        print(f"✅ AWS key pair created")
        return {'key_name': key_name}
    except NoCredentialsError:
        print("❌ AWS credentials not configured. Run 'aws configure'")
        sys.exit(1)
    except ClientError as e:
        print(f"❌ AWS Error: {e}")
        sys.exit(1)

def get_user_ip():
    print("🌍 Setting security access...")
    print("⚠️ Using 0.0.0.0/0 - accessible from anywhere for testing")
    return "0.0.0.0/0"

def get_default_vpc(region="us-east-2"):
    print(f"🔍 Finding VPC in region {region}...")
    ec2 = boto3.client("ec2", region_name=region)
    vpcs = ec2.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
    if vpcs['Vpcs']:
        vpc_id = vpcs['Vpcs'][0]['VpcId']
        print(f"✅ Using default VPC: {vpc_id}")
        return vpc_id
    vpcs = ec2.describe_vpcs()
    if vpcs['Vpcs']:
        vpc_id = vpcs['Vpcs'][0]['VpcId']
        print(f"✅ Using VPC: {vpc_id}")
        return vpc_id
    raise Exception("No VPC found")

def get_public_subnet_from_vpc(vpc_id, region="us-east-2"):
    print("🌐 Finding public subnet...")
    ec2 = boto3.client("ec2", region_name=region)
    response = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "state", "Values": ["available"]}])
    subnets = response["Subnets"]
    if not subnets:
        raise Exception("No subnets found in this VPC")
    for subnet in subnets:
        if subnet.get("MapPublicIpOnLaunch", False):
            print(f"✅ Found public subnet: {subnet['SubnetId']}")
            return subnet["SubnetId"]
    print(f"⚠️ No subnet with auto-assign public IPs found, using: {subnets[0]['SubnetId']}")
    return subnets[0]["SubnetId"]

def ensure_internet_gateway(vpc_id, region="us-east-2"):
    ec2 = boto3.client("ec2", region_name=region)
    igws = ec2.describe_internet_gateways(Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])["InternetGateways"]
    if igws:
        igw_id = igws[0]["InternetGatewayId"]
        print(f"✅ VPC already has IGW: {igw_id}")
    else:
        igw = ec2.create_internet_gateway()
        igw_id = igw["InternetGateway"]["InternetGatewayId"]
        ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        print(f"✅ Created and attached IGW: {igw_id}")
    return igw_id

def ensure_public_route(subnet_id, igw_id, region="us-east-2"):
    ec2 = boto3.client("ec2", region_name=region)
    rts = ec2.describe_route_tables(Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}])["RouteTables"]
    if not rts:
        subnet_info = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
        vpc_id = subnet_info["VpcId"]
        rts = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"]
        main_rt = next((rt for rt in rts if any(assoc.get("Main") for assoc in rt.get("Associations", []))), None)
        if not main_rt:
            raise Exception(f"No main route table found for VPC {vpc_id}")
        rt_id = main_rt["RouteTableId"]
    else:
        rt_id = rts[0]["RouteTableId"]
    rt_info = ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"][0]
    if not any(r.get("DestinationCidrBlock") == "0.0.0.0/0" for r in rt_info.get("Routes", [])):
        ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
        print(f"✅ Added 0.0.0.0/0 -> {igw_id} route to route table {rt_id}")
    else:
        print(f"✅ Default route already exists in route table {rt_id}")

def create_security_group(vpc_id, user_ip, region="us-east-2"):
    print("🛡️ Creating security group...")
    ec2 = boto3.client("ec2", region_name=region)
    sg_name = "builder-yael-sg"
    sg_response = ec2.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': [sg_name]}, {'Name': 'vpc-id', 'Values': [vpc_id]}])
    if sg_response['SecurityGroups']:
        sg_id = sg_response['SecurityGroups'][0]['GroupId']
        print(f"✅ Using existing security group: {sg_id}")
        return sg_id
    sg_create_response = ec2.create_security_group(GroupName=sg_name, Description="Security group for builder-yael instance", VpcId=vpc_id)
    sg_id = sg_create_response['GroupId']
    ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[
        {'IpProtocol': 'tcp','FromPort': 22,'ToPort': 22,'IpRanges': [{'CidrIp': user_ip,'Description': 'SSH access'}]},
        {'IpProtocol': 'tcp','FromPort': 5001,'ToPort': 5001,'IpRanges': [{'CidrIp': user_ip,'Description': 'Web app access'}]}
    ])
    print(f"✅ Security group created: {sg_id}")
    return sg_id

# ------------------------------
# EC2 + Flask Deployment
# ------------------------------

def create_ec2_instance(key_name, vpc_id, subnet_id, sg_id, region="us-east-2"):
    print("🚀 Creating EC2 instance...")
    ec2 = boto3.client("ec2", region_name=region)
    response = ec2.describe_images(Filters=[{'Name': 'name','Values': ['ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*']},{'Name': 'owner-id','Values': ['099720109477']},{'Name': 'state','Values': ['available']}], Owners=['099720109477'])
    images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
    latest_ami = images[0]['ImageId']
    print(f"✅ Using Ubuntu 22.04 LTS AMI: {latest_ami}")

    user_data = """#!/bin/bash
apt-get update -y
apt-get install -y python3-pip python3-venv git
mkdir -p /home/ubuntu/webapp
chown ubuntu:ubuntu /home/ubuntu/webapp

cat > /home/ubuntu/webapp/app.py << 'EOF'
import os
import requests
import boto3
from flask import Flask, render_template_string
app = Flask(__name__)

@app.route('/')
def home():
    try:
        token = requests.put('http://169.254.169.254/latest/api/token', headers={'X-aws-ec2-metadata-token-ttl-seconds':'21600'}, timeout=2).text
        headers = {'X-aws-ec2-metadata-token': token}
        instance_id = requests.get('http://169.254.169.254/latest/meta-data/instance-id', headers=headers, timeout=2).text
        public_ip = requests.get('http://169.254.169.254/latest/meta-data/public-ipv4', headers=headers, timeout=2).text
        instance_type = requests.get('http://169.254.169.254/latest/meta-data/instance-type', headers=headers, timeout=2).text

    except:
        instance_id = 'N/A'
        public_ip = 'N/A'
        instance_type = 'N/A'
    return f"<h2>EC2 is running!</h2><ul><li>ID: {instance_id}</li><li>Public IP: {public_ip}</li><li>Instance Type: {instance_type}</li></ul>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
EOF

chown ubuntu:ubuntu /home/ubuntu/webapp/app.py
pip3 install flask boto3 requests

cat > /etc/systemd/system/webapp.service << 'SERVICE'
[Unit]
Description=Flask Web Application
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/webapp
ExecStart=/usr/bin/python3 /home/ubuntu/webapp/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable webapp.service
systemctl start webapp.service
"""

    response = ec2.run_instances(
        ImageId=latest_ami,
        MinCount=1,
        MaxCount=1,
        InstanceType='t3.micro',
        KeyName=key_name,
        NetworkInterfaces=[{"DeviceIndex":0,"SubnetId":subnet_id,"AssociatePublicIpAddress":True,"Groups":[sg_id]}],
        TagSpecifications=[{'ResourceType':'instance','Tags':[{'Key':'Name','Value':'builder-yael'}]}],
        UserData=user_data
    )

    instance_id = response['Instances'][0]['InstanceId']
    print(f"⏳ Instance launched: {instance_id}")
    waiter = ec2.get_waiter('instance_running')
    waiter.wait(InstanceIds=[instance_id], WaiterConfig={'Delay':15,'MaxAttempts':40})
    instance_info = ec2.describe_instances(InstanceIds=[instance_id])
    instance = instance_info['Reservations'][0]['Instances'][0]
    return {'instance_id': instance_id, 'public_ip': instance.get('PublicIpAddress'), 'region': region}

# ------------------------------
# Main
# ------------------------------

def main():
    print("🚀 AWS Infrastructure + Web App Deployment (Ubuntu)")
    platform_info = detect_platform()
    print(f"🖥️ Platform: {platform_info['system'].title()}")
    print(f"🔧 SSH Available: {'✅' if platform_info['has_ssh'] else '❌'}")

    try:
        ssh_key = generate_ssh_key()
        private_key_file = save_private_key_locally(ssh_key['private_key_pem'])
        create_aws_key_pair("builder-key", ssh_key['public_key_openssh'])
        user_ip = get_user_ip()
        vpc_id = get_default_vpc()
        subnet_id = get_public_subnet_from_vpc(vpc_id)
        igw_id = ensure_internet_gateway(vpc_id)
        ensure_public_route(subnet_id, igw_id)
        sg_id = create_security_group(vpc_id, user_ip)
        ec2_instance = create_ec2_instance("builder-key", vpc_id, subnet_id, sg_id)
        print("\n🎉 DEPLOYMENT COMPLETED!")
        print(f"🏷️ Instance Name: builder-yael")
        print(f"🆔 Instance ID: {ec2_instance['instance_id']}")
        print(f"🌐 Public IP: {ec2_instance['public_ip']}")
        print(f"🔗 Access: ssh -i \"{private_key_file['filename']}\" ubuntu@{ec2_instance['public_ip']}")
        print(f"💻 Web Dashboard: http://{ec2_instance['public_ip']}:5001")

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
