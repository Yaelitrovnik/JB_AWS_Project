# 🚀 EC2 Builder Script

A Python-based AWS automation script that creates and configures an EC2 instance with SSH access, a security group, and the latest Amazon Linux 2 AMI.

---

## Features

- 🖥️ **EC2 Instance Creation**: Launch EC2 instances with a predefined instance type (`t3.medium`) and latest Amazon Linux 2 AMI.  
- 🔑 **SSH Key Management**: Automatically generates a 4096-bit RSA SSH key pair and imports it to AWS.  
- 🛡️ **Security Group Setup**: Creates or reuses a security group with inbound rules for SSH (port 22) and a custom port (5001).  
- 🌐 **Subnet Selection**: Finds a public subnet in a specified VPC automatically.  
- 📋 **Tagging & Metadata**: Names the instance (`builder-yael`) and enforces IMDSv2 for enhanced security.  
- 📊 **Terraform-style Output**: Provides structured instance info and a ready-to-use SSH command.  

---

## Project Structure

```

JB_AWS_Project/
│── SSH_Key_and_EC2.py          # Main script
│── README.md
└── requirements.txt            # Python dependencies

````

---

## Requirements

### Python Dependencies

- Python 3.13+
- boto3
- cryptography

Install with:

```bash
pip install -r requirements.txt
````

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
git clone https://github.com/Yaelitrovnik/JB_AWS_Project
cd JB_AWS_Project
```

2. **Create a virtual environment:**

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

Edit the script variables to match your environment:

```python
vpc_id = "vpc-xxxxxxxx"       # Your VPC ID
region = "us-east-2"          # AWS region
key_name = "builder-key"      # Name of the SSH key pair
```

> By default, the script selects the first public subnet in the VPC and creates a security group if it doesn't exist.

---

## Usage

Run the script:

```bash
python3 SSH_Key_and_EC2.py
```

### Example Terraform-style output:

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
```

---

## Security Notes

* Overwrites existing AWS key pairs with the same name.
* Security group allows SSH from any IP (`0.0.0.0/0`) – adjust for production use.

---

## Troubleshooting

| Issue                     | Solution                                                     |
| ------------------------- | ------------------------------------------------------------ |
| AWS credentials not found | Configure AWS CLI or environment variables                   |
| Subnet or SG errors       | Ensure VPC ID exists and has available subnets               |
| Permission errors         | Check IAM user permissions                                   |
| SSH connection fails      | Verify security group rules and correct key file permissions |

---

