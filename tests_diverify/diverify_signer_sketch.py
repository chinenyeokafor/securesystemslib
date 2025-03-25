from securesystemslib.signer import SigstoreKey
from securesystemslib.signer._signer import Signature
import json
import requests
from securesystemslib.signer import (
    SIGNER_FOR_URI_SCHEME,
    Signer,
    SigstoreSigner,
)

DIVERIFY_DAEMON_URL = "http://localhost:8000"

def get_auth_requirements(level):
    """Fetch required authentication methods for a given level."""
    response = requests.get(f"{DIVERIFY_DAEMON_URL}/auth/requirements", params={"level": level})
    if response.status_code == 200:
       return response.json()
    else:
        print(f"Error: {response.text}")

def parse_required_auth():
    pass

def submit_auth_result(level, proofs):
    """Send authentication proofs and get a div proof."""
    response = requests.post(
        f"{DIVERIFY_DAEMON_URL}/auth/submit",
        params={"level": level},
        json={"auth_result": proofs}
    )
    if response.status_code == 200:
        print(f"Div Proof: {response.json()}")
    else:
        print(f"Error: {response.text}")

def cert_request():
    pass


def send_cert():
    pass


def sign_request():
    pass


def log_bundle_request():
    pass


def artifact_signing(security_level):
    TEST_IDENTITY = "okaforchinenyelilian@gmail.com"
    TEST_ISSUER = "http://sigstore-dex:6000"
    SIGNER_FOR_URI_SCHEME[SigstoreSigner.SCHEME] = SigstoreSigner

    req_auth = get_auth_requirements(security_level) if security_level > 1 else {'identity': {'oidc': True}}
    print(f"req auth is: {req_auth}")

    uri, public_key=SigstoreSigner.import_(TEST_IDENTITY, TEST_ISSUER, ambient=False)
    signer=Signer.from_priv_key_uri(uri, public_key)

    # Project TODO: Add logic to perform DiVerify trust verification
    sig=signer.sign(b"data")

    # Project TODO: Fetch DiVerify Policy
    # Project TODO: Add logic to perform DiVerify specific verification against policy

    # Successful verification
    public_key.verify_signature(sig, b"data")




def verify_detached_signature():
    file_path="artifact.txt.sigstore.json"

    #signature bundle
    with open(file_path, "r") as file:
        bundle=json.load(file)

    #the signed file
    with open("artifact.txt", "rb") as artifact_file:
        data = artifact_file.read()
    keyid=bundle["verificationMaterial"]["tlogEntries"][0]["logId"]["keyId"]
    unrecognized_fields={"bundle": bundle}
    key=SigstoreKey(keyid=keyid, keytype='sigstore-oidc', scheme ='Fulcio', keyval={"identity": "okaforchinenyelilian@gmail.com", "issuer": "https://github.com/login/oauth"}, unrecognized_fields=unrecognized_fields)
    sig = bundle["messageSignature"]["signature"]
    signature=Signature(keyid=keyid,sig=sig, unrecognized_fields=unrecognized_fields)
    key.verify_signature(signature=signature, data=data)

if __name__ == "__main__":
    # signature_verifier()
    import argparse

    parser = argparse.ArgumentParser(description="Run the script with a security level")
    parser.add_argument('--security-level', type=int, default=1, choices=range(1, 4), help='Set the security level (default is 1)')
    args = parser.parse_args()

    security_level = args.security_level

    artifact_signing(security_level)