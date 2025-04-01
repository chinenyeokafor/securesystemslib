
from DiVerify.trustverifier.utils.credential_store import load_credentials, save_credentials
from DiVerify.trustverifier.trust_verifier_loader import load_trust_verifier
from DiVerify.trustverifier import security_key

import requests
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

#Here, we want to get the auth configuration from DiVerify deamon.
# TODO: The goal is to have the daemon started when called if it was running.
# For now, we assume the daemon is running at the DiVerify_Daemon_URL
DiVerify_Daemon_URL = "http://localhost:8000"


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
        "auth_result": proofs
    })
    if not response.ok:
        raise RuntimeError(f"Authentication submission failed: {response.text}")
    
    logger.debug(f"DiVerify Proof received")
    
    return response.json()


def verify_security_key():
    # I envision that it is possible to provide register the device and have the credential available 
    # in perhaps tuf signer metadata. That way, the verification is essentially against the known trusted cred.
    trust_verifier = "security_key"
    origin = "https://sigstore.dev"
    rp_id, rp_name = "sigstore.dev", "sigstore"
    user_id = "acct_id"
    user_name = "u sername"

    key_verifier = security_key.SecurityKeyTrustVerifier
    credentials = load_credentials(user_id)
    verifier = load_trust_verifier(trust_verifier)

    if credentials:
        verifier.verify(rp_id=rp_id, rp_name=rp_name, origin=origin, credentials=credentials)
    else:
        # TODO: This should be provided from somewhere trusted. Perhaps Package Policy
        client, uv = key_verifier.setup_binding(origin)
        server, credentials = key_verifier.register(client, uv, rp_id, rp_name, user_id, user_name)
        key_verifier.authenticate(server, client, credentials, uv)
    
    return True

def verify_device_fingerprint(auth, state):
    # TODO: Modify device fingerprint to persist the state
    return load_trust_verifier(auth).verify()