Perfect! Here’s a **complete, professional README.md** for your repo, fully covering usage, setup, and details for your script:

````markdown
# EC2 Builder Script

This Python script automates the creation of an AWS EC2 instance, including SSH key generation, security group setup, and deployment in a specified VPC/subnet. It is designed to provide a quick, repeatable way to spin up an EC2 instance for development, testing, or learning purposes.

---

## Features

- Generates a **4096-bit RSA SSH key pair** locally.
- Creates or reuses an **AWS key pair** using the generated public key.
- Finds a **public subnet** in the specified VPC (or uses the first available subnet).
- Creates or reuses a **security group** with inbound rules for:
  - SSH (port 22)
  - Custom port 5001
- Launches an **EC2 instance** with the **latest Amazon Linux 2 AMI**.
- Outputs instance details in a **Terraform-style format** for easy reference.
- Provides a ready-to-use **SSH command** to connect to the instance.

---

## Prerequisites

- Python 3.13+
- AWS account with configured credentials (`~/.aws/credentials` or environment variables)
- IAM permissions for:
  - EC2: `RunInstances`, `DescribeInstances`, `CreateSecurityGroup`, `AuthorizeSecurityGroupIngress`, `ImportKeyPair`
  - VPC: `DescribeSubnets`
- Python packages:
  - [boto3](https://boto3.amazonaws.com/)
  - [cryptography](https://cryptography.io/)

---

## Installation

1. Clone the repository:

```bash
git clone <your-repo-url>
cd <repo-directory>
````

2. Install Python dependencies:

```bash
pip install boto3 cryptography
```

---

## Configuration

Before running the script, you can configure the following variables directly in the script:

```python
vpc_id = "vpc-xxxxxxxx"         # Your VPC ID
region = "us-east-2"            # AWS region
key_name = "builder-key"        # Name of the SSH key pair
```

> By default, the script finds a public subnet in the specified VPC.
> The security group allows SSH (22) and port 5001 from any IP (`0.0.0.0/0`). Adjust as needed.

---

## Usage

Run the script:

```bash
python3 SSH_Key_and_EC2.py
```

The script will:

1. Generate an RSA SSH key pair locally (`builder_key.pem`).
2. Save the private key securely with `0600` permissions.
3. Create or import an AWS key pair using the generated public key.
4. Find a public subnet in the specified VPC.
5. Create or reuse a security group with required inbound rules.
6. Launch an EC2 instance with the latest Amazon Linux 2 AMI.
7. Output instance details and the SSH command to connect.

Example output:

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

* The script **overwrites existing AWS key pairs** with the same name.
* Security group allows open SSH access (`0.0.0.0/0`). For production, restrict this to trusted IPs.
* Designed for **development/testing** environments.

---

## Advanced Usage

You can modify the script to:

* Launch in a **specific private subnet** by setting `AssociatePublicIpAddress=False`.
* Attach **additional EBS volumes** or modify instance types.
* Integrate with **DynamoDB** to store instance metadata.
* Automatically select the **latest AMI** in your preferred region (already included).

---

## Troubleshooting

* **AWS credentials not found**: Make sure you have configured AWS CLI or environment variables.
* **Subnet or security group errors**: Ensure the VPC ID exists and has available subnets.
* **Permission errors**: Check IAM user permissions for EC2, VPC, and Key Pair operations.
* **SSH connection issues**: Verify the security group allows inbound traffic from your IP.

---


