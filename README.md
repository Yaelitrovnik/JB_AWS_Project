# 🚀 EC2 Builder Script

A Python-based AWS automation script that creates and configures an EC2 instance with SSH access, a security group, and the latest Amazon Linux 2 AMI.  
It also deploys a Flask web dashboard accessible via a custom port (5001).

---

## Features

- 🖥️ **EC2 Instance Creation**: Launch EC2 instances with a predefined instance type (`t3.medium`) and latest Amazon Linux 2 AMI.  
- 🔑 **SSH Key Management**: Automatically generates a 4096-bit RSA SSH key pair and imports it to AWS.  
- 🛡️ **Security Group Setup**: Creates or reuses a security group with inbound rules for SSH (port 22) and web access (port 5001).  
- 🌐 **Subnet Selection**: Automatically selects a public subnet in the VPC.  
- 📋 **Tagging & Metadata**: Names the instance (`builder-yael`) and enforces IMDSv2 for enhanced security.  
- 📊 **Web Dashboard**: Flask app shows EC2, VPC, AMI, and Load Balancer info in a browser.  

---

## Project Structure

```

JB_AWS_Project/
│── universal_deployment.py   # Main Python script
│── README.md
│── requirements.txt          # Python dependencies
│── .gitignore
└── images/
  │── instance_info.jpg
  └── instance.jpg

````

---

## Requirements

### Python Dependencies

- Python >= 3.9
- boto3==1.40.28
- cryptography==39.0.1
- flask==3.1.2

Install dependencies with:

```bash
pip install -r requirements.txt
````

> **Note:** `botocore` is automatically installed with `boto3`, no need to pin separately.

### AWS Requirements

* AWS account with configured credentials (`~/.aws/credentials` or environment variables)
* IAM permissions for EC2, VPC, and key pair operations:

  * `RunInstances`, `DescribeInstances`
  * `CreateSecurityGroup`, `AuthorizeSecurityGroupIngress`
  * `ImportKeyPair`

---

## Installation

1. **Clone the repository:**

```bash
git clone https://github.com/Yaelitrovnik/JB_AWS_Project.git
cd JB_AWS_Project
```

2. **Create and activate a virtual environment:**

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

3. **Install dependencies:**

```bash
pip install -r requirements.txt
```

---

## Configuration

### Public IP Restriction

Before running the script, ensure your public IP is set for the security group:

```python
student_ip = "YOUR_PUBLIC_IP/32"  # Replace with your actual public IP
```

Find your public IP:

```bash
# Command line
curl ifconfig.me

# Or visit: https://whatismyipaddress.com/
```

### Optional Script Variables

Edit these in `universal_deployment.py` if needed:

```python
vpc_id = "vpc-0c678d4904a68bd91"  # Your VPC ID (default provided)
region = "us-east-2"              # AWS region
key_name = "builder-key"          # Name of the SSH key pair
```

> By default, the script selects the first public subnet in the VPC and creates a security group if it doesn’t exist.

---

## Usage

Run the script:

```bash
python universal_deployment.py
```

### Example Output

```
ssh_private_key_path = "builder_key.pem" (sensitive)
ssh_key_name = "builder-key"
instance_id = "i-0abc1234def56789"
instance_name = "builder-yael"
instance_type = "t3.medium"
instance_public_ip = "3.123.45.67"
instance_public_dns = "ec2-3-123-45-67.compute-1.amazonaws.com"
vpc_id = "vpc-0c678d4904a68bd91"
subnet_id = "subnet-0abc1234def56789"
region = "us-east-2"
Security Group: sg-0abc1234def56789
🔐 SSH Command: ssh -i "builder_key.pem" ec2-user@3.123.45.67
Web Dashboard: http://3.123.45.67:5001
Health Check: http://3.123.45.67:5001/health
```

---

## Security Notes

* **IP Restriction**: Security group restricts SSH and port 5001 access to your specific IP only.
* **Key Management**: Overwrites existing AWS key pairs with the same name for consistency.
* **Private Key**: Saved locally with secure 0600 permissions.

---

## Troubleshooting

| Issue                     | Solution                                                     |
| ------------------------- | ------------------------------------------------------------ |
| AWS credentials not found | Configure AWS CLI or environment variables                   |
| Subnet or SG errors       | Ensure VPC ID exists and has available subnets               |
| Permission errors         | Check IAM user permissions                                   |
| SSH connection fails      | Verify security group rules and correct key file permissions |
| Web dashboard not loading | Wait 2-3 minutes after deployment                            |
| IP access denied          | Update `student_ip` with your current public IP              |


