import os
import subprocess
import time
import logging
from functools import lru_cache

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(_name_)

@lru_cache(maxsize=1)
def get_cached_aws_clients():
    """Cache AWS clients for Flask app."""
    try:
        import boto3
        session = boto3.Session()
        ec2_client = session.client("ec2")
        elb_client = session.client("elbv2")
        ec2_client.describe_regions(MaxResults=1)
        return ec2_client, elb_client, None
    except Exception as e:
        return None, None, str(e)

def create_flask_app_file():
    """Create Flask web application file."""
    app_content = """import os
import boto3
import logging
from flask import Flask, render_template_string
from functools import lru_cache

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(_name_)

app = Flask(_name_)

@lru_cache(maxsize=1)
def get_aws_clients():
    try:
        session = boto3.Session()
        ec2_client = session.client("ec2")
        elb_client = session.client("elbv2")
        ec2_client.describe_regions(MaxResults=1)
        return ec2_client, elb_client, None
    except Exception as e:
        logger.error(f"AWS client error: {e}")
        return None, None, str(e)

@app.route("/")
def home():
    ec2_client, elb_client, error = get_aws_clients()
    if not ec2_client:
        logger.error(f"AWS credentials error: {error}")
        return f'''
        <!DOCTYPE html>
        <html>
        <head><title>AWS Credentials Error</title>
        <style>body {{ font-family: Arial; margin: 40px; background: #f5f5f5; }}</style>
        </head>
        <body>
            <h1>🔐 AWS Credentials Not Configured</h1>
            <p><strong>Error:</strong> {error}</p>
            <h3>Note:</h3>
            <p>This instance uses an IAM role, so credentials may not be needed.</p>
            <p>Check logs or contact your administrator.</p>
        </body>
        </html>
        '''
    try:
        instances = ec2_client.describe_instances()
        instance_data = []
        for reservation in instances["Reservations"]:
            for instance in reservation["Instances"]:
                instance_data.append({
                    "ID": instance["InstanceId"],
                    "State": instance["State"]["Name"],
                    "Type": instance["InstanceType"],
                    "Public IP": instance.get("PublicIpAddress", "N/A")
                })
        vpcs = ec2_client.describe_vpcs()
        vpc_data = [{"VPC ID": vpc["VpcId"], "CIDR": vpc["CidrBlock"]} for vpc in vpcs["Vpcs"]]
        try:
            lbs = elb_client.describe_load_balancers()
            lb_data = [{"LB Name": lb["LoadBalancerName"], "DNS Name": lb["DNSName"]} for lb in lbs["LoadBalancers"]]
        except Exception as e:
            logger.error(f"Error fetching load balancers: {e}")
            lb_data = [{"LB Name": "No Load Balancers", "DNS Name": "N/A"}]
        try:
            amis = ec2_client.describe_images(Owners=["self"], MaxItems=10)
            ami_data = [{"AMI ID": ami["ImageId"], "Name": ami.get("Name", "N/A")} for ami in amis["Images"]]
            if not ami_data:
                ami_data = [{"AMI ID": "No Custom AMIs", "Name": "N/A"}]
        except Exception as e:
            logger.error(f"Error fetching AMIs: {e}")
            ami_data = [{"AMI ID": "Error Loading AMIs", "Name": "N/A"}]
    except Exception as e:
        logger.error(f"AWS error: {e}")
        return f"<html><body><h1>AWS Error</h1><p>{str(e)}</p></body></html>"

    html_template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>AWS Resources Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 40px; background: #f5f5f5; }
            h1 { color: #232f3e; border-bottom: 3px solid #ff9900; padding-bottom: 10px; text-align: center; }
            h2 { color: #232f3e; margin-top: 30px; }
            table { border-collapse: collapse; width: 100%; margin: 20px 0; background: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
            th { background: #232f3e; color: white; }
            tr:nth-child(even) { background: #f9f9f9; }
            tr:hover { background: #f0f8ff; }
            .running { color: #28a745; font-weight: bold; }
            .stopped { color: #dc3545; font-weight: bold; }
            .footer { text-align: center; margin-top: 40px; color: #666; }
        </style>
    </head>
    <body>
        <h1>🚀 AWS Resources Dashboard</h1>
        <h2>🖥 EC2 Instances ({{ instance_data|length }})</h2>
        <table>
            <tr><th>Instance ID</th><th>State</th><th>Type</th><th>Public IP</th></tr>
            {% for instance in instance_data %}
            <tr>
                <td>{{ instance['ID'] }}</td>
                <td class="{{ instance['State'] }}">{{ instance['State']|title }}</td>
                <td>{{ instance['Type'] }}</td>
                <td>{{ instance['Public IP'] }}</td>
            </tr>
            {% endfor %}
        </table>
        <h2>🌐 VPCs ({{ vpc_data|length }})</h2>
        <table>
            <tr><th>VPC ID</th><th>CIDR Block</th></tr>
            {% for vpc in vpc_data %}
            <tr><td>{{ vpc['VPC ID'] }}</td><td>{{ vpc['CIDR'] }}</td></tr>
            {% endfor %}
        </table>
        <h2>⚖ Load Balancers ({{ lb_data|length }})</h2>
        <table>
            <tr><th>Name</th><th>DNS Name</th></tr>
            {% for lb in lb_data %}
            <tr><td>{{ lb['LB Name'] }}</td><td>{{ lb['DNS Name'] }}</td></tr>
            {% endfor %}
        </table>
        <h2>💽 Custom AMIs ({{ ami_data|length }})</h2>
        <table>
            <tr><th>AMI ID</th><th>Name</th></tr>
            {% for ami in ami_data %}
            <tr><td>{{ ami['AMI ID'] }}</td><td>{{ ami['Name'] }}</td></tr>
            {% endfor %}
        </table>
        <div class="footer">
            <p>🏗 Built with Flask + Boto3 | Running on builder-yael</p>
        </div>
    </body>
    </html>
    '''
    logger.info("Rendering dashboard")
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
        logger.info("Health check: OK")
        return {"status": "healthy", "service": "AWS Dashboard"}
    else:
        logger.error(f"Health check failed: {error}")
        return {"status": "error", "error": error}, 503

if _name_ == "_main_":
    logger.info("Starting AWS Resources Dashboard on port 5001...")
    app.run(host="0.0.0.0", port=5001, debug=False)
"""
    app_file_path = os.path.join(os.path.dirname(os.path.abspath(_file_)), "app.py")
    with open(app_file_path, "w", encoding='utf-8') as f:
        f.write(app_content)
    logger.info(f"Created Flask app file: {app_file_path}")
    return app_file_path

def deploy_app_universal(instance_ip, private_key_path, app_file_path, platform_info):
    """Deploy web application."""
    logger.info(f"Deploying web application to {instance_ip}...")
    logger.info("Waiting for instance to be ready (90 seconds)...")
    time.sleep(90)
    if platform_info['has_ssh'] and not platform_info['is_windows']:
        return deploy_automated(instance_ip, private_key_path, app_file_path)
    else:
        return deploy_manual_instructions(instance_ip, private_key_path, app_file_path)

def deploy_automated(instance_ip, private_key_path, app_file_path):
    """Try automated deployment."""
    try:
        logger.info("Attempting automated deployment...")
        scp_cmd = [
            "scp", "-i", private_key_path,
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=30",
            app_file_path, f"ec2-user@{instance_ip}:/home/ec2-user/webapp/app.py"
        ]
        result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            logger.warning(f"SCP failed: {result.stderr}")
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
            logger.warning(f"Service start failed: {result.stderr}")
        logger.info("Automated deployment completed!")
        return True
    except Exception as e:
        logger.warning(f"Automated deployment failed: {e}")
        return deploy_manual_instructions(instance_ip, private_key_path, app_file_path)

def deploy_manual_instructions(instance_ip, private_key_path, app_file_path):
    """Show manual deployment instructions."""
    logger.info("Displaying manual deployment instructions")
    print("\n" + "="*50)
    print("📋 MANUAL DEPLOYMENT STEPS")
    print("="*50)
    print("Please complete these steps to finish deployment:")
    print(f"1. 🔗 Connect to your instance:\n   ssh -i \"{private_key_path}\" ec2-user@{instance_ip}")
    print("2. 📝 Create the Flask app:\n   nano /home/ec2-user/webapp/app.py\n   (Copy content from the local app.py file)")
    print("3. 🚀 Start the web service:\n   sudo systemctl start webapp.service")
    print("4. ✅ Check if it's running:\n   sudo systemctl status webapp.service")
    print("="*50)
    return True