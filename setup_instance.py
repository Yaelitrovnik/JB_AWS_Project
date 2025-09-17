import boto3
import os
import json
from botocore.exceptions import ClientError

# ==========================
# CONFIGURATION
# ==========================
VPC_ID = "vpc-044604d0bfb707142"  # Existing VPC
INSTANCE_NAME = "builder"
INSTANCE_TYPE = "t3.medium"
AMI_ID = "ami-0c02fb55956c7d316"  # Amazon Linux 2 (update if needed)
KEY_PAIR_NAME = "builder_key"
SECURITY_GROUP_NAME = "builder_sg"
FLASK_PORT = 5001

# Get your public IP to restrict access
import requests
MY_IP = requests.get("https://checkip.amazonaws.com").text.strip()
MY_CIDR = f"{MY_IP}/32"

# ==========================
# AWS SESSION
# ==========================
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
REGION = os.getenv("AWS_REGION", "us-east-1")

session = boto3.Session(
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=REGION
)

ec2 = session.resource("ec2")
ec2_client = session.client("ec2")

# ==========================
# 1. Create SSH Key Pair
# ==========================
try:
    key_pair = ec2_client.create_key_pair(KeyName=KEY_PAIR_NAME)
    private_key = key_pair["KeyMaterial"]

    # Save private key locally
    key_path = os.path.expanduser(f"~/{KEY_PAIR_NAME}.pem")
    with open(key_path, "w") as f:
        f.write(private_key)
    os.chmod(key_path, 0o400)  # Read-only for user
    print(f"✅ Private key saved to: {key_path}")

except ClientError as e:
    if "InvalidKeyPair.Duplicate" in str(e):
        print(f"⚠️ Key pair {KEY_PAIR_NAME} already exists. Using existing key.")
    else:
        raise e

# ==========================
# 2. Create Security Group
# ==========================
try:
    response = ec2_client.create_security_group(
        GroupName=SECURITY_GROUP_NAME,
        Description="Security group for builder instance",
        VpcId=VPC_ID
    )
    sg_id = response["GroupId"]
    print(f"✅ Security group created: {sg_id}")

    # Add inbound rules
    ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": MY_CIDR}]},
            {"IpProtocol": "tcp", "FromPort": FLASK_PORT, "ToPort": FLASK_PORT, "IpRanges": [{"CidrIp": MY_CIDR}]}
        ]
    )
    print("✅ Ingress rules added (SSH + Flask)")

except ClientError as e:
    if "InvalidGroup.Duplicate" in str(e):
        sg = ec2_client.describe_security_groups(GroupNames=[SECURITY_GROUP_NAME])
        sg_id = sg["SecurityGroups"][0]["GroupId"]
        print(f"⚠️ Security group {SECURITY_GROUP_NAME} already exists: {sg_id}")
    else:
        raise e

# ==========================
# 3. Find a Public Subnet
# ==========================
subnets = ec2_client.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [VPC_ID]}])["Subnets"]
public_subnet_id = None
for subnet in subnets:
    if subnet.get("MapPublicIpOnLaunch"):
        public_subnet_id = subnet["SubnetId"]
        break

if not public_subnet_id:
    raise Exception("No public subnet found in the VPC!")

print(f"✅ Using public subnet: {public_subnet_id}")

# ==========================
# 4. Launch EC2 Instance
# ==========================
instances = ec2.create_instances(
    ImageId=AMI_ID,
    InstanceType=INSTANCE_TYPE,
    KeyName=KEY_PAIR_NAME,
    MinCount=1,
    MaxCount=1,
    NetworkInterfaces=[{
        "SubnetId": public_subnet_id,
        "DeviceIndex": 0,
        "AssociatePublicIpAddress": True,
        "Groups": [sg_id]
    }],
    TagSpecifications=[{
        "ResourceType": "instance",
        "Tags": [{"Key": "Name", "Value": INSTANCE_NAME}]
    }]
)

instance = instances[0]
print("⏳ Launching instance...")
instance.wait_until_running()
instance.reload()
print(f"✅ Instance launched: {instance.id} (Public IP: {instance.public_ip_address})")
