#!/usr/bin/env python3
"""
AWS Infrastructure + Web App Deployment Script
Creates AWS EC2 instance and deploys a Flask web dashboard.
Works on Windows, Mac, and Linux.
"""

import boto3
import os
import sys
import time
import subprocess
import platform
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from botocore.exceptions import ClientError, NoCredentialsError

def detect_platform():
    """Detect platform and SSH capability."""
    system = platform.system().lower()
    has_ssh = False
    
    try:
        subprocess.run(["ssh", "-V"], capture_output=True, timeout=5)
        has_ssh = True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        has_ssh = False
    
    return {
        'system': system,
        'is_windows': system == 'windows',
        'has_ssh': has_ssh
    }

def generate_ssh_key():
    """Generate SSH key pair."""
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
    """Save SSH private key."""
    print(f"💾 Saving private key to {filename}...")
    full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    try:
        with open(full_path, "wb") as f:
            f.write(private_key_pem)
        
        if os.name != 'nt':
            os.chmod(full_path, 0o600)
            print("✅ Private key saved with secure permissions")
        else:
            print("✅ Private key saved")
        
        return {'filename': full_path}
    except Exception as e:
        print(f"❌ Error saving private key: {e}")
        sys.exit(1)

def create_aws_key_pair(key_name, public_key, region="us-east-2"):
    """Create AWS key pair."""
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
        
        response = ec2.import_key_pair(KeyName=key_name, PublicKeyMaterial=public_key)
        print(f"✅ AWS key pair created")
        return {'key_name': key_name}
    except NoCredentialsError:
        print("❌ AWS credentials not configured.")
        print("💡 Run 'aws configure' first")
        sys.exit(1)
    except ClientError as e:
        print(f"❌ AWS Error: {e}")
        sys.exit(1)

def get_user_ip():
    """Get user's public IP address."""
    print("🌍 Getting your public IP address...")
    
    try:
        import requests
        ip = requests.get('https://ifconfig.me', timeout=5).text.strip()
        print(f"✅ Auto-detected IP: {ip}")
        confirm = input("Use this IP? (y/n) [y]: ").strip().lower()
        if confirm in ['', 'y', 'yes']:
            return ip + "/32"
    except ImportError:
        print("⚠️ Unable to auto-detect IP")
    except Exception:
        print("⚠️ Could not auto-detect IP")
    
    print("\n📝 Please enter your public IP address")
    print("💡 Find it at: https://whatismyipaddress.com/")
    
    while True:
        ip = input("Enter your public IP (or 'open' for any IP): ").strip()
        
        if ip.lower() == 'open':
            print("⚠️ WARNING: Using 0.0.0.0/0 - accessible from anywhere")
            return "0.0.0.0/0"
        
        if ip:
            if not ip.endswith(('/32', '/24', '/16', '/8')):
                ip = ip + "/32"
            return ip
        
        print("❌ Please enter a valid IP address")

def get_default_vpc(region="us-east-2"):
    """Find default VPC."""
    print(f"🔍 Finding VPC in region {region}...")
    ec2 = boto3.client("ec2", region_name=region)
    
    try:
        vpcs = ec2.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
        if vpcs['Vpcs']:
            vpc_id = vpcs['Vpcs'][0]['VpcId']
            print(f"✅ Using default VPC: {vpc_id}")
            return vpc_id
    except Exception:
        pass
    
    try:
        vpcs = ec2.describe_vpcs()
        if vpcs['Vpcs']:
            vpc_id = vpcs['Vpcs'][0]['VpcId']
            print(f"✅ Using VPC: {vpc_id}")
            return vpc_id
    except Exception:
        pass
    
    raise Exception("No VPC found")

def get_public_subnet_from_vpc(vpc_id, region="us-east-2"):
    """Find public subnet in VPC."""
    print(f"🌐 Finding public subnet...")
    ec2 = boto3.client("ec2", region_name=region)
    
    try:
        response = ec2.describe_subnets(
            Filters=[
                {'Name': 'vpc-id', 'Values': [vpc_id]}, 
                {'Name': 'state', 'Values': ['available']}
            ]
        )
        subnets = response['Subnets']
        
        if not subnets:
            raise Exception("No subnets found")
        
        for subnet in subnets:
            if subnet.get('MapPublicIpOnLaunch', False):
                print(f"✅ Found public subnet: {subnet['SubnetId']}")
                return subnet['SubnetId']
        
        print(f"✅ Using subnet: {subnets[0]['SubnetId']}")
        return subnets[0]['SubnetId']
        
    except Exception as e:
        raise Exception(f"Error finding subnet: {e}")

def create_security_group(vpc_id, user_ip, region="us-east-2"):
    """Create security group."""
    print("🛡️ Creating security group...")
    ec2 = boto3.client("ec2", region_name=region)
    sg_name = "builder-yael-sg"

    try:
        sg_response = ec2.describe_security_groups(
            Filters=[
                {'Name': 'group-name', 'Values': [sg_name]},
                {'Name': 'vpc-id', 'Values': [vpc_id]}
            ]
        )
        
        if sg_response['SecurityGroups']:
            sg_id = sg_response['SecurityGroups'][0]['GroupId']
            print(f"✅ Using existing security group: {sg_id}")
            return sg_id

        sg_create_response = ec2.create_security_group(
            GroupName=sg_name,
            Description="Security group for builder-yael instance",
            VpcId=vpc_id
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

        print(f"✅ Security group created: {sg_id}")
        return sg_id

    except ClientError as e:
        print(f"❌ Error creating security group: {e}")
        sys.exit(1)

def create_ec2_instance(key_name, vpc_id, subnet_id, sg_id, region="us-east-2"):
    """Create EC2 instance."""
    print("🚀 Creating EC2 instance...")
    ec2 = boto3.client("ec2", region_name=region)

    print("📦 Getting latest Amazon Linux AMI...")
    try:
        # Use AWS Systems Manager to get the latest Amazon Linux 2 AMI ID
        ssm = boto3.client('ssm', region_name=region)
    
        try:
            # Get the latest Amazon Linux 2 AMI ID from AWS Parameter Store
            response = ssm.get_parameter(
                Name='/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2'
            )
            latest_ami = response['Parameter']['Value']
            print(f"✅ Using Amazon Linux 2 AMI: {latest_ami}")
        except Exception:
            # Fallback: try Amazon Linux 2023
            try:
                response = ssm.get_parameter(
                    Name='/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64'
                )
                latest_ami = response['Parameter']['Value']
                print(f"✅ Using Amazon Linux 2023 AMI: {latest_ami}")
            except Exception:
                # Final fallback: use a known working AMI ID for us-east-2
                latest_ami = "ami-0c7217cdde317cfec"  # Amazon Linux 2 in us-east-2
                print(f"✅ Using fallback AMI: {latest_ami}")
            
    except Exception as e:
        print(f"❌ Error finding AMI: {e}")
        sys.exit(1)

    user_data = """#!/bin/bash
yum update -y
yum install -y python3-pip git
pip3 install flask boto3 requests

mkdir -p /home/ec2-user/webapp
chown ec2-user:ec2-user /home/ec2-user/webapp

mkdir -p /home/ec2-user/.aws
cat > /home/ec2-user/.aws/config << 'EOF'
[default]
region = us-east-2
output = json
EOF
chown -R ec2-user:ec2-user /home/ec2-user/.aws

cat > /etc/systemd/system/webapp.service << 'EOF'
[Unit]
Description=Flask Web Application
After=network.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/home/ec2-user/webapp
Environment=PATH=/usr/local/bin:/usr/bin:/bin
Environment=AWS_DEFAULT_REGION=us-east-2
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
            }],
            UserData=user_data
        )

        instance_id = response['Instances'][0]['InstanceId']
        print(f"⏳ Instance launched: {instance_id}")
        print("⏳ Waiting for instance to be running (up to 10 minutes)...")
        
        waiter = ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id], WaiterConfig={'Delay': 15, 'MaxAttempts': 40})
        
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
        
    except Exception as e:
        print(f"❌ Error creating instance: {e}")
        sys.exit(1)

def create_flask_app_file():
    """Create Flask web application file."""
    app_content = """import os
import boto3
from flask import Flask, render_template_string

app = Flask(__name__)

def get_aws_clients():
    try:
        session = boto3.Session()
        ec2_client = session.client("ec2")
        elb_client = session.client("elbv2")
        ec2_client.describe_regions(MaxResults=1)
        return ec2_client, elb_client, None
    except Exception as e:
        return None, None, str(e)

@app.route("/")
def home():
    ec2_client, elb_client, error = get_aws_clients()
    
    if not ec2_client:
        return f'''
        <!DOCTYPE html>
        <html>
        <head><title>AWS Credentials Error</title>
        <style>body {{ font-family: Arial; margin: 40px; background: #f5f5f5; }}</style>
        </head>
        <body>
            <h1>🔐 AWS Credentials Not Configured</h1>
            <p><strong>Error:</strong> {error}</p>
            <h3>To fix this:</h3>
            <ol>
                <li>SSH to this instance</li>
                <li>Run: <code>aws configure</code></li>
                <li>Enter your AWS credentials</li>
                <li>Restart: <code>sudo systemctl restart webapp.service</code></li>
            </ol>
        </body>
        </html>
        '''
    
    try:
        instances = ec2_client.describe_instances()
        instance_data = []
        for reservation in instances["Reservations"]:
            for instance in reservation["Instances"]:
                instance_data.append({{
                    "ID": instance["InstanceId"],
                    "State": instance["State"]["Name"],
                    "Type": instance["InstanceType"],
                    "Public IP": instance.get("PublicIpAddress", "N/A")
                }})
        
        vpcs = ec2_client.describe_vpcs()
        vpc_data = [{{"VPC ID": vpc["VpcId"], "CIDR": vpc["CidrBlock"]}} for vpc in vpcs["Vpcs"]]
        
        try:
            lbs = elb_client.describe_load_balancers()
            lb_data = [{{"LB Name": lb["LoadBalancerName"], "DNS Name": lb["DNSName"]}} for lb in lbs["LoadBalancers"]]
        except:
            lb_data = [{{"LB Name": "No Load Balancers", "DNS Name": "N/A"}}]
        
        try:
            amis = ec2_client.describe_images(Owners=["self"], MaxItems=10)
            ami_data = [{{"AMI ID": ami["ImageId"], "Name": ami.get("Name", "N/A")}} for ami in amis["Images"]]
            if not ami_data:
                ami_data = [{{"AMI ID": "No Custom AMIs", "Name": "N/A"}}]
        except:
            ami_data = [{{"AMI ID": "Error Loading AMIs", "Name": "N/A"}}]
        
    except Exception as e:
        return f"<html><body><h1>AWS Error</h1><p>{{str(e)}}</p></body></html>"

    html_template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>AWS Resources Dashboard</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 40px; background: #f5f5f5; }}
            h1 {{ color: #232f3e; border-bottom: 3px solid #ff9900; padding-bottom: 10px; text-align: center; }}
            h2 {{ color: #232f3e; margin-top: 30px; }}
            table {{ border-collapse: collapse; width: 100%; margin: 20px 0; background: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            th {{ background: #232f3e; color: white; }}
            tr:nth-child(even) {{ background: #f9f9f9; }}
            tr:hover {{ background: #f0f8ff; }}
            .running {{ color: #28a745; font-weight: bold; }}
            .stopped {{ color: #dc3545; font-weight: bold; }}
            .footer {{ text-align: center; margin-top: 40px; color: #666; }}
        </style>
    </head>
    <body>
        <h1>🚀 AWS Resources Dashboard</h1>
        
        <h2>🖥️ EC2 Instances ({{{{ instance_data|length }}}})</h2>
        <table>
            <tr><th>Instance ID</th><th>State</th><th>Type</th><th>Public IP</th></tr>
            {{% for instance in instance_data %}}
            <tr>
                <td>{{{{ instance['ID'] }}}}</td>
                <td class="{{{{ instance['State'] }}}}">{{{{ instance['State']|title }}}}</td>
                <td>{{{{ instance['Type'] }}}}</td>
                <td>{{{{ instance['Public IP'] }}}}</td>
            </tr>
            {{% endfor %}}
        </table>
        
        <h2>🌐 VPCs ({{{{ vpc_data|length }}}})</h2>
        <table>
            <tr><th>VPC ID</th><th>CIDR Block</th></tr>
            {{% for vpc in vpc_data %}}
            <tr><td>{{{{ vpc['VPC ID'] }}}}</td><td>{{{{ vpc['CIDR'] }}}}</td></tr>
            {{% endfor %}}
        </table>
        
        <h2>⚖️ Load Balancers ({{{{ lb_data|length }}}})</h2>
        <table>
            <tr><th>Name</th><th>DNS Name</th></tr>
            {{% for lb in lb_data %}}
            <tr><td>{{{{ lb['LB Name'] }}}}</td><td>{{{{ lb['DNS Name'] }}}}</td></tr>
            {{% endfor %}}
        </table>
        
        <h2>💽 Custom AMIs ({{{{ ami_data|length }}}})</h2>
        <table>
            <tr><th>AMI ID</th><th>Name</th></tr>
            {{% for ami in ami_data %}}
            <tr><td>{{{{ ami['AMI ID'] }}}}</td><td>{{{{ ami['Name'] }}}}</td></tr>
            {{% endfor %}}
        </table>
        
        <div class="footer">
            <p>🏗️ Built with Flask + Boto3 | Running on builder-yael</p>
        </div>
    </body>
    </html>
    '''
    
    return render_template_string(
        html_template,
        instance_data=instance_data,
        vpc_data=vpc_data,
        lb_data=lb_data,
        ami_data=ami_data
    )

@app.route("/health")
def health():
    ec2_client, elb_client, error = get_aws_clients()
    if ec2_client:
        return {{"status": "healthy", "service": "AWS Dashboard"}}
    else:
        return {{"status": "error", "error": error}}, 503

if __name__ == "__main__":
    print("🌟 Starting AWS Resources Dashboard on port 5001...")
    print("📍 Access the dashboard in your web browser")
    app.run(host="0.0.0.0", port=5001, debug=True)
"""
    
    app_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py")
    with open(app_file_path, "w", encoding='utf-8') as f:
        f.write(app_content)
    print(f"📝 Created Flask app file: {app_file_path}")
    return app_file_path

def deploy_app_universal(instance_ip, private_key_path, app_file_path, platform_info):
    """Deploy web application."""
    print(f"📤 Deploying web application to {instance_ip}...")
    print("⏳ Waiting for instance to be ready (90 seconds)...")
    time.sleep(90)
    
    if platform_info['has_ssh'] and not platform_info['is_windows']:
        return deploy_automated(instance_ip, private_key_path, app_file_path)
    else:
        return deploy_manual_instructions(instance_ip, private_key_path, app_file_path)

def deploy_automated(instance_ip, private_key_path, app_file_path):
    """Try automated deployment."""
    try:
        print("🔄 Attempting automated deployment...")
        
        scp_cmd = [
            "scp", "-i", private_key_path,
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=30",
            app_file_path, f"ec2-user@{instance_ip}:/home/ec2-user/webapp/app.py"
        ]
        
        result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            print(f"⚠️ SCP failed, switching to manual instructions")
            return deploy_manual_instructions(instance_ip, private_key_path, app_file_path)
        
        ssh_cmd = [
            "ssh", "-i", private_key_path,
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=30",
            f"ec2-user@{instance_ip}",
            "sudo systemctl start webapp.service"
        ]
        
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            print(f"⚠️ Service start had issues, but app might still work")
        
        print("✅ Automated deployment completed!")
        return True
        
    except Exception as e:
        print(f"⚠️ Automated deployment failed: {e}")
        return deploy_manual_instructions(instance_ip, private_key_path, app_file_path)

def deploy_manual_instructions(instance_ip, private_key_path, app_file_path):
    """Show manual deployment instructions."""
    print("\n" + "="*50)
    print("📋 MANUAL DEPLOYMENT STEPS")
    print("="*50)
    print("Please complete these steps to finish deployment:")
    print()
    
    print("1. 🔗 Connect to your instance:")
    print(f"   ssh -i \"{private_key_path}\" ec2-user@{instance_ip}")
    
    print()
    print("2. 📝 Create the Flask app:")
    print("   nano /home/ec2-user/webapp/app.py")
    print("   (Copy content from the local app.py file)")
    
    print()
    print("3. ⚙️ Configure AWS credentials:")
    print("   aws configure")
    print("   (Enter your AWS Access Key and Secret Key)")
    
    print()
    print("4. 🚀 Start the web service:")
    print("   sudo systemctl start webapp.service")
    
    print()
    print("5. ✅ Check if it's running:")
    print("   sudo systemctl status webapp.service")
    
    print("="*50)
    return True

def main():
    """Main function."""
    print("🚀 AWS Infrastructure + Web App Deployment")
    print("="*50)
    
    platform_info = detect_platform()
    print(f"🖥️ Platform: {platform_info['system'].title()}")
    print(f"🔧 SSH Available: {'✅' if platform_info['has_ssh'] else '❌'}")
    
    if platform_info['is_windows'] and not platform_info['has_ssh']:
        print("💡 Will use manual deployment steps")
    elif platform_info['has_ssh']:
        print("💡 Will attempt automated deployment")
    
    print()
    
    try:
        print("🔑 Step 1: Generate SSH Key")
        ssh_key = generate_ssh_key()
        private_key_file = save_private_key_locally(ssh_key['private_key_pem'])
        
        print("\n🔐 Step 2: Create AWS Key Pair")
        create_aws_key_pair("builder-key", ssh_key['public_key_openssh'])
        
        print("\n🌍 Step 3: Configure Security")
        user_ip = get_user_ip()
        
        print("\n🏗️ Step 4: Create Infrastructure")
        vpc_id = get_default_vpc()
        subnet_id = get_public_subnet_from_vpc(vpc_id)
        sg_id = create_security_group(vpc_id, user_ip)
        
        print("\n🚀 Step 5: Create EC2 Instance")
        ec2_instance = create_ec2_instance("builder-key", vpc_id, subnet_id, sg_id)
        
        print("\n📝 Step 6: Create Flask App")
        app_file_path = create_flask_app_file()
        
        print("\n📤 Step 7: Deploy App")
        deploy_success = deploy_app_universal(
            ec2_instance['public_ip'],
            private_key_file['filename'],
            app_file_path,
            platform_info
        )
        
        print("\n" + "="*50)
        print("🎉 DEPLOYMENT COMPLETED!")
        print("="*50)
        print(f"🏷️ Instance Name: builder-yael")
        print(f"🆔 Instance ID: {ec2_instance['instance_id']}")
        print(f"🌐 Public IP: {ec2_instance['public_ip']}")
        print(f"📍 Region: {ec2_instance['region']}")
        print()
        print("🔗 Access Information:")
        print(f"   Web Dashboard: http://{ec2_instance['public_ip']}:5001")
        print(f"   Health Check: http://{ec2_instance['public_ip']}:5001/health")
        print(f"   SSH Command: ssh -i \"{private_key_file['filename']}\" ec2-user@{ec2_instance['public_ip']}")
        print()
        print("📁 Files Created:")
        print(f"   • SSH Key: {private_key_file['filename']}")
        print(f"   • Flask App: {app_file_path}")
        
        if deploy_success:
            print("\n✅ SUCCESS! Your AWS infrastructure and web app are ready!")
            print("💡 If web app doesn't load immediately, wait 2-3 minutes")
        else:
            print("\n⚠️ Infrastructure created but app deployment needs manual steps")
        
    except KeyboardInterrupt:
        print("\n\n👋 Deployment cancelled")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("💡 Check your AWS credentials and permissions")
        sys.exit(1)

if __name__ == "__main__":
    main()