import os
import sys
import logging
from config_manager import load_config
from ssh_key_manager import detect_platform, generate_ssh_key, save_private_key_locally
from aws_resources import create_aws_key_pair, get_user_ip, get_public_subnet_from_vpc, create_security_group, create_iam_role, create_ec2_instance
from flask_app import create_flask_app_file, deploy_app_universal
from cleanup import cleanup_resources

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main(cleanup=False):
    """Main function to orchestrate AWS infrastructure and Flask app deployment."""
    logger.info("AWS Infrastructure + Web App Deployment")
    print("="*50)
    config = load_config()
    platform_info = detect_platform()
    logger.info(f"Platform: {platform_info['system'].title()}")
    logger.info(f"SSH Available: {'✅' if platform_info['has_ssh'] else '❌'}")
    if platform_info['is_windows'] and not platform_info['has_ssh']:
        logger.info("Will use manual deployment steps")
    else:
        logger.info("Will attempt automated deployment")

    if cleanup:
        logger.info("Running cleanup mode")
        cleanup_resources(
            instance_id=os.getenv('INSTANCE_ID'),
            key_name=os.getenv('KEY_PAIR_NAME', config['KEY_PAIR_NAME']),
            sg_id=os.getenv('SECURITY_GROUP_ID'),
            iam_role='BuilderYaelEC2Role',
            region=config['REGION']
        )
        return

    try:
        logger.info("Step 1: Generate SSH Key")
        ssh_key = generate_ssh_key()
        private_key_file = save_private_key_locally(ssh_key['private_key_pem'])
        logger.info("Step 2: Create AWS Key Pair")
        aws_key_pair = create_aws_key_pair(config['KEY_PAIR_NAME'], ssh_key['public_key_openssh'], config['REGION'])
        logger.info("Step 3: Create IAM Role")
        iam_role = create_iam_role(config['REGION'])
        logger.info("Step 4: Configure Security")
        user_ip = get_user_ip()
        logger.info("Step 5: Create Infrastructure")
        subnet_id = get_public_subnet_from_vpc(config['VPC_ID'], config['REGION'])
        sg_id = create_security_group(config['VPC_ID'], user_ip, config['REGION'], config['SECURITY_GROUP_NAME'])
        logger.info("Step 6: Create EC2 Instance")
        ec2_instance = create_ec2_instance(
            config['KEY_PAIR_NAME'], config['VPC_ID'], subnet_id, sg_id, config['REGION'], 
            iam_role, config['INSTANCE_TYPE'], config['INSTANCE_NAME']
        )
        logger.info("Step 7: Create Flask App")
        app_file_path = create_flask_app_file()
        logger.info("Step 8: Deploy App")
        deploy_success = deploy_app_universal(
            ec2_instance['public_ip'],
            private_key_file['filename'],
            app_file_path,
            platform_info
        )
        print("\n" + "="*50)
        print("🎉 DEPLOYMENT COMPLETED!")
        print("="*50)
        print(f"🏷 Instance Name: {config['INSTANCE_NAME']}")
        print(f"🆔 Instance ID: {ec2_instance['instance_id']}")
        print(f"🌐 Public IP: {ec2_instance['public_ip']}")
        print(f"📍 Region: {ec2_instance['region']}")
        print(f"🔗 Access Information:")
        print(f"   Web Dashboard: http://{ec2_instance['public_ip']}:{config['FLASK_PORT']}")
        print(f"   Health Check: http://{ec2_instance['public_ip']}:{config['FLASK_PORT']}/health")
        print(f"   SSH Command: ssh -i \"{private_key_file['filename']}\" ec2-user@{ec2_instance['public_ip']}")
        print(f"📁 Files Created:")
        print(f"   • SSH Key: {private_key_file['filename']}")
        print(f"   • Flask App: {app_file_path}")
        if deploy_success:
            print("\n✅ SUCCESS! Your AWS infrastructure and web app are ready!")
            print("💡 If web app doesn't load immediately, wait 2-3 minutes")
        else:
            print("\n⚠ Infrastructure created but app deployment needs manual steps")
    except KeyboardInterrupt:
        logger.info("Deployment cancelled")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error: {e}")
        logger.info("Attempting cleanup...")
        cleanup_resources(
            instance_id=locals().get('ec2_instance', {}).get('instance_id'),
            key_name=config['KEY_PAIR_NAME'],
            sg_id=locals().get('sg_id'),
            iam_role=locals().get('iam_role'),
            region=config['REGION']
        )
        logger.error("Check your AWS credentials, permissions, and VPC configuration")
        sys.exit(1)

if __name__ == "_main_":
    import argparse
    parser = argparse.ArgumentParser(description="AWS Infrastructure and Flask App Deployment")
    parser.add_argument('--cleanup', action='store_true', help='Clean up created resources')
    args = parser.parse_args()
    main(cleanup=args.cleanup)
    