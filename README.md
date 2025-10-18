
# 🚀 EC2 Builder Script

A Python-based AWS automation script that creates and configures an EC2 instance with SSH access, a security group, and the latest Ubuntu 22.04 LTS AMI.  
It also deploys a Flask web dashboard accessible via a custom port (5001) that shows AWS resources: EC2 instances, VPCs, Load Balancers, and AMIs.

---

## Features

- 🖥️ **EC2 Instance Creation**: Launch EC2 instances with a predefined instance type (`t3.medium`) and Ubuntu 22.04 LTS AMI.  
- 🔑 **SSH Key Management**: Automatically generates a 4096-bit RSA SSH key pair and imports it to AWS.  
- 🛡️ **Security Group Setup**: Creates or reuses a security group with inbound rules for SSH (port 22) and web access (port 5001).  
- 🌐 **Subnet & IGW Management**: Automatically selects a public subnet in the VPC and attaches an Internet Gateway if missing.  
- 📋 **Tagging & Metadata**: Names the instance (`builder-yael`).  
- 📊 **Web Dashboard**: Flask app shows EC2 instances, VPCs, Load Balancers, and AMIs in a browser.

---

## Project Structure

```

JB_AWS_Project/
│── universal_deployment.py   # Main Python deployment script
│── README.md
│── requirements.txt          # Python dependencies
└── .gitignore


````

---

## Requirements

### Python Dependencies

- Python >= 3.9
- boto3
- cryptography
- flask

Install dependencies with:

```bash
pip install -r requirements.txt
````

> **Note:** `botocore` is installed automatically with `boto3`.

### AWS Requirements

* AWS account with configured credentials (`~/.aws/credentials` or environment variables)
* IAM permissions for EC2, VPC, Security Groups, Key Pair, and ELB operations:

  * `RunInstances`, `DescribeInstances`
  * `CreateSecurityGroup`, `AuthorizeSecurityGroupIngress`
  * `ImportKeyPair`
  * `DescribeVpcs`, `DescribeSubnets`
  * `DescribeImages`, `DescribeLoadBalancers`

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

By default, the security group allows access from anywhere (`0.0.0.0/0`) for testing.
For production, replace with your IP in the `get_user_ip()` function:

```python
student_ip = "YOUR_PUBLIC_IP/32"
```

Find your public IP:

```bash
curl ifconfig.me
```

### Optional Script Variables

Edit these in `universal_deployment.py` if needed:

```python
vpc_id = "vpc-xxxxxxxxxxxx"      # Optional VPC ID
region = "us-east-2"             # AWS region
key_name = "builder-key"         # SSH key pair name
```

> By default, the script selects the first public subnet in the VPC, creates a security group if it doesn’t exist, and attaches an Internet Gateway if the subnet cannot reach the internet.

---

## Usage

Run the script:

```bash
python universal_deployment.py
```

### Example Output

```
🎉 DEPLOYMENT COMPLETED!
🏷️ Instance Name: builder-yael
🆔 Instance ID: i-0abc1234def56789
🌐 Public IP: 3.123.45.67
📍 Region: us-east-2
🐧 OS: Ubuntu 22.04 LTS

🔗 Access Information:
   Web Dashboard: http://3.123.45.67:5001
   Health Check: http://3.123.45.67:5001/health
   SSH Command: ssh -i "builder_key.pem" ubuntu@3.123.45.67

📁 Files Created:
   • SSH Key: builder_key.pem
```

---

## Web Dashboard

Once the EC2 instance is running, visit:

```
http://<Public-IP>:5001
```

It shows:

* Running EC2 instances (ID, state, type, public IP)
* VPCs (ID, CIDR)
* Load Balancers (name, DNS)
* Available AMIs (ID, name)

Health endpoint:

```
http://<Public-IP>:5001/health
```

---

## SSH Access

Connect to your instance:

```bash
ssh -i "builder_key.pem" ubuntu@<Public-IP>
```

Disconnect:

```bash
exit
```

---

## Security Notes

* **IP Restriction**: Adjust your public IP for production use.
* **Key Management**: Existing AWS key pairs with the same name are overwritten.
* **Private Key**: Saved locally with secure 0600 permissions.

---

## Troubleshooting

| Issue                     | Solution                                             |
| ------------------------- | ---------------------------------------------------- |
| AWS credentials not found | Run `aws configure` or set environment variables     |
| Subnet or SG errors       | Ensure VPC exists and has available subnets          |
| Permission errors         | Check IAM user permissions                           |
| SSH connection fails      | Verify security group rules and key file permissions |
| Web dashboard not loading | Wait 2-3 minutes after deployment                    |
| IP access denied          | Update `student_ip` with your current public IP      |

---

## Cleanup

To remove all resources created by the script:

1. Terminate the EC2 instance.
2. Delete the security group `builder-yael-sg`.
3. Delete the key pair `builder-key` in AWS.
4. Optionally, remove `builder_key.pem` locally.

```



