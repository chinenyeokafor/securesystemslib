
from DiVerify.trustverifier.utils.credential_store import load_credentials, save_credentials
from DiVerify.trustverifier.trust_verifier_loader import load_trust_verifier
from DiVerify.trustverifier import security_key

import requests
import logging
import configparser

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

#Here, we want to get the auth configuration from DiVerify deamon.
# TODO: The goal is to have the daemon started when called if it was running.
# For now, we assume the daemon is running at the DiVerify_Daemon_URL
config = configparser.ConfigParser()
config.read('stack_config.ini')
DiVerify_Daemon_URL = config['settings']['diverify-url']

def daemon_sign_artifact(payload, level, mode):
    response = requests.post(
        f"{DiVerify_Daemon_URL}/daemon/sign",
        json={"payload": payload, "level": level, "mode": mode}
    )
    if not response.ok:
        raise RuntimeError(f"Daemon failed to sign payload: {response.text}")
    
    return response.json()
    

def get_auth_requirements(level):
    """Fetch required authentication methods and nonces for a given level."""
    response = requests.get(f"{DiVerify_Daemon_URL}/auth/requirements", params={"level": level})
    if not response.ok:
        raise RuntimeError(f"Failed to fetch auth requirements: {response.text}")
    
    data = response.json()
    print(f"Required authentication for level {level}: {data['auth_requirements']}")
    return data["auth_requirements"], data["nonces"], data["request_state"]
    
def submit_auth_result(level, proofs, request_state):
    """Submit authentication proofs, payload, and retrieve the div proof."""
    response = requests.post(f"{DiVerify_Daemon_URL}/auth/submit", json={
        "level": level,
        "request_state": request_state,
        "scopes": proofs
    })
    if not response.ok:
        print(response.text)
        raise RuntimeError(f"Authentication submission failed: {response.text}")
    
    logger.debug(f"DiVerify Proof received")
    
    return response.json()


def verify_scope(auth):
    return load_trust_verifier(auth).verify()