import os
import platform
import subprocess
import logging
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def detect_platform():
    """Detect platform and SSH capability."""
    logger.info("Detecting platform...")
    system = platform.system().lower()
    has_ssh = False
    try:
        subprocess.run(["ssh", "-V"], capture_output=True, timeout=5)
        has_ssh = True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        has_ssh = False
    platform_info = {
        'system': system,
        'is_windows': system == 'windows',
        'has_ssh': has_ssh
    }
    logger.info(f"Platform detected: {platform_info}")
    return platform_info

def generate_ssh_key():
    """Generate SSH key pair."""
    logger.info("Generating SSH key pair...")
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
    logger.info(f"Saving private key to {filename}...")
    full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    try:
        with open(full_path, "wb") as f:
            f.write(private_key_pem)
        if os.name != 'nt':
            os.chmod(full_path, 0o600)
            logger.info("Private key saved with secure permissions")
        else:
            logger.info("Private key saved")
        return {'filename': full_path}
    except Exception as e:
        logger.error(f"Error saving private key: {e}")
        raise