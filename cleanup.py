import boto3
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(_name_)

def cleanup_resources(instance_id=None, key_name=None, sg_id=None, iam_role=None, region='us-east-2'):
    """Clean up created resources."""
    logger.info("Cleaning up resources...")
    ec2 = boto3.client('ec2', region_name=region)
    iam = boto3.client('iam', region_name=region)
    if instance_id:
        try:
            ec2.terminate_instances(InstanceIds=[instance_id])
            logger.info(f"Instance {instance_id} terminated")
        except Exception as e:
            logger.error(f"Failed to terminate instance: {e}")
    if key_name:
        try:
            ec2.delete_key_pair(KeyName=key_name)
            logger.info(f"Key pair {key_name} deleted")
        except Exception as e:
            logger.error(f"Failed to delete key pair: {e}")
    if sg_id:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            logger.info(f"Security group {sg_id} deleted")
        except Exception as e:
            logger.error(f"Failed to delete security group: {e}")
    if iam_role:
        try:
            iam.remove_role_from_instance_profile(InstanceProfileName=iam_role, RoleName=iam_role)
            iam.delete_instance_profile(InstanceProfileName=iam_role)
            iam.detach_role_policy(RoleName=iam_role, PolicyArn='arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess')
            iam.detach_role_policy(RoleName=iam_role, PolicyArn='arn:aws:iam::aws:policy/ElasticLoadBalancingReadOnly')
            iam.delete_role(RoleName=iam_role)
            logger.info(f"IAM role {iam_role} deleted")
        except Exception as e:
            logger.error(f"Failed to delete IAM role: {e}")