import os
import configparser
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration defaults
DEFAULT_CONFIG = {
    'VPC_ID': 'vpc-0c678d4904a68bd91',
    'INSTANCE_NAME': 'builder-yael',
    'INSTANCE_TYPE': 't3.medium',
    'KEY_PAIR_NAME': 'builder-key',
    'SECURITY_GROUP_NAME': 'builder-yael-sg',
    'FLASK_PORT': '5001',
    'REGION': 'us-east-2'
}

def load_config():
    """Load configuration from environment variables or config file."""
    logger.info("Loading configuration...")
    config = configparser.ConfigParser()
    config_file = 'deployment_config.ini'
    if os.path.exists(config_file):
        config.read(config_file)
        config_section = config.get('aws', {}) if 'aws' in config else {}
    else:
        config_section = {}
    config = {
        'VPC_ID': os.getenv('VPC_ID', config_section.get('vpc_id', DEFAULT_CONFIG['VPC_ID'])),
        'INSTANCE_NAME': os.getenv('INSTANCE_NAME', config_section.get('instance_name', DEFAULT_CONFIG['INSTANCE_NAME'])),
        'INSTANCE_TYPE': os.getenv('INSTANCE_TYPE', config_section.get('instance_type', DEFAULT_CONFIG['INSTANCE_TYPE'])),
        'KEY_PAIR_NAME': os.getenv('KEY_PAIR_NAME', config_section.get('key_pair_name', DEFAULT_CONFIG['KEY_PAIR_NAME'])),
        'SECURITY_GROUP_NAME': os.getenv('SECURITY_GROUP_NAME', config_section.get('security_group_name', DEFAULT_CONFIG['SECURITY_GROUP_NAME'])),
        'FLASK_PORT': int(os.getenv('FLASK_PORT', config_section.get('flask_port', DEFAULT_CONFIG['FLASK_PORT']))),
        'REGION': os.getenv('AWS_REGION', config_section.get('region', DEFAULT_CONFIG['REGION']))
    }
    logger.info(f"Configuration loaded: {config}")
    return config