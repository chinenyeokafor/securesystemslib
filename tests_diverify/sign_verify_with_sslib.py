from securesystemslib.signer import SigstoreKey
from securesystemslib.signer._signer import Signature
import json
import time
import hashlib
import jwt
import sys
from securesystemslib.signer import (
    SIGNER_FOR_URI_SCHEME,
    Signer,
    # SigstoreSigner,
)
from securesystemslib.diverify._diverify_sigstore_signer import SigstoredKey, SigstoredSigner
from securesystemslib.diverify.rekor import submit_to_tlog
from securesystemslib.diverify.verifier import verify_signature, verify_quote_and_signature
from securesystemslib.diverify.daemon import (
    get_auth_requirements, submit_auth_result, verify_scope, daemon_sign_artifact)
import logging
import base64
from cryptography.x509 import load_pem_x509_certificate
from securesystemslib.diverify.util import perf_utils

logger = logging.getLogger(__name__)
# logging.basicConfig(level=logging.DEBUG)
logging.getLogger().setLevel(logging.CRITICAL)

TEST_IDENTITY = (
    "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/"
    "workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
)
TEST_ISSUER = "https://token.actions.githubusercontent.com"
PAYLOAD = b"data"

class Hashed:
    def __init__(self, algorithm: str, digest: bytes):
        self.algorithm = algorithm
        self.digest = digest
    
    @classmethod
    def from_dict(cls, data):
        algorithm = data["algorithm"]
        digest = base64.b64decode(data["digest"])
        return cls(algorithm, digest)


def vanilla_artifact_signing():
    SIGNER_FOR_URI_SCHEME[SigstoredSigner.SCHEME] = SigstoredSigner

    uri, public_key=SigstoredSigner.import_(TEST_IDENTITY, TEST_ISSUER, ambient=False)
    signer, _ =Signer.from_priv_key_uri(uri, public_key)
    sig=signer.sign(PAYLOAD)

    # Successful verification
    public_key.verify_signature(sig, PAYLOAD)

def run_mode_a(policy=None):
    SIGNER_FOR_URI_SCHEME[SigstoredSigner.SCHEME] = SigstoredSigner

    uri, public_key=SigstoredSigner.import_(TEST_IDENTITY, TEST_ISSUER, ambient=True)
    
    with open("config.json", 'r') as file:
        config = json.load(file)
    required_auth = config["levels"].get(str(LEVEL), {}).get("identity", {})
    signer, token =Signer.from_priv_key_uri(uri, public_key)

    @perf_utils.measure_latency
    def sign(required_auth):
        proofs = {}
        limit_scope_flag = False
        for auth in required_auth:
            if auth == "device_fingerprint":
                fingerprint = verify_scope(auth)
                proofs[auth] = fingerprint
                logger.debug(f"Device Fingerprint is: {fingerprint}")
            elif auth == "security_key":
                piv_attestation = verify_scope(auth)
                proofs[auth] = piv_attestation
                # for now, just assume its done
                # proofs[auth] = True
                # public_key.unrecognized_fields = {auth: ""}
            elif auth == "source_local_scope":
                limit_scope_flag = True
                proofs[auth] = True
            elif auth == "attestation":
                sign_in_enclave = True
                proofs[auth] = True

        claims = jwt.decode(token, options={"verify_signature": False})
        proofs["oidc"] = {
                "sub": "https://github.com/" + claims.get('job_workflow_ref'),
                "iss": claims.get('iss'),
                "token_hash": hashlib.sha256(token.encode()).hexdigest()
                }

        

        diverify_proof = {"level": LEVEL, "identity": proofs, "timestamp": int(time.time())}
        return signer, signer.sign(PAYLOAD, diverify_proof)
    signer, signature_material = sign(required_auth)
    sig = signer.submit_to_tlog(signature_material)
    
    # Successful verification

    @perf_utils.measure_latency
    def verify_sig(sig, policy):
        verify_signature(sig, PAYLOAD, TEST_IDENTITY, TEST_ISSUER, policy)

    verify_sig(sig, policy)


def run_mode_b(policy=None):
    payload = base64.b64encode(PAYLOAD).decode('utf-8')
    @perf_utils.measure_latency
    def sign(payload, mode):
        return daemon_sign_artifact(payload, LEVEL, mode)
    signature_material = sign(payload, mode="b")
    signature_material = json.loads(base64.b64decode(signature_material).decode('utf-8'))
    signature_material = {
        "hashed_input": Hashed.from_dict(signature_material["hashed_input"]),
        "artifact_signature": base64.b64decode(signature_material["artifact_signature"]),
        "signing_cert": load_pem_x509_certificate(signature_material["signing_cert"].encode('utf-8')),
    }
    sig = submit_to_tlog(signature_material)

    # Successful verification

    @perf_utils.measure_latency
    def verify_sig(sig, policy):
        verify_signature(sig, PAYLOAD, TEST_IDENTITY, TEST_ISSUER, policy)
    
    verify_sig(sig, policy)

def run_mode_c(policy=None):
    payload = base64.b64encode(PAYLOAD).decode('utf-8')
    @perf_utils.measure_latency
    def sign(payload, mode):
        return daemon_sign_artifact(payload, LEVEL, mode)
    signature_material = sign(payload, mode="c")
    signature_material = json.loads(base64.b64decode(signature_material).decode('utf-8'))
    signature_material = {
        "hashed_input": Hashed.from_dict(signature_material["hashed_input"]),
        "artifact_signature": base64.b64decode(signature_material["artifact_signature"]),
        "diverify_proof": signature_material["diverify_proof"],
    }

    # Successful verification

    @perf_utils.measure_latency
    def verify_sig(sig, policy):
        # breakpoint()
        verify_quote_and_signature(sig, PAYLOAD, TEST_IDENTITY, TEST_ISSUER, policy)

    verify_sig(signature_material, policy)

def verify_sigstore_signature():
    file_path="signature/artifact.sigstore.json"

    #signature bundle
    with open(file_path, "r") as file:
        bundle=json.load(file)

    #the signed file
    with open("artifact", "rb") as artifact_file:
        data = artifact_file.read()
    keyid=bundle["verificationMaterial"]["tlogEntries"][0]["logId"]["keyId"]
    unrecognized_fields={"bundle": bundle}
    key=SigstoredKey(keyid=keyid, keytype='sigstore-oidc', scheme ='Fulcio', keyval={"identity": "okaforchinenyelilian@gmail.com", "issuer": "https://github.com/login/oauth"}, unrecognized_fields=unrecognized_fields)
    sig = bundle["messageSignature"]["signature"]
    signature=Signature(keyid=keyid,sig=sig, unrecognized_fields=unrecognized_fields)
    key.verify_signature(signature=signature, data=data)
    print("verified")

# def verify_artifact_signature():
#     from pathlib import Path
#     import os
#     file_path = Path(os.path.dirname(__file__)) / "signature/artifact.sig.json"

#     if not file_path.exists():
#         raise FileNotFoundError(f"File not found: {file_path}")

#     #signature bundle
#     with open(file_path, "r") as file:
#         bundle=json.load(file)

#     #the signed file
#     with open("artifact", "rb") as artifact_file:
#         data = artifact_file.read()
#     with open(Path(os.path.dirname(__file__)) /"policy.json", "r") as policy:
#         policy=json.load(policy)
#     keyid=bundle["verificationMaterial"]["tlogEntries"][0]["logId"]["keyId"]
#     unrecognized_fields={"bundle": bundle, "diverify_policy": policy}
#     key=SigstoredKey(keyid=keyid, keytype='sigstore-oidc', scheme ='Fulcio', keyval={"identity": policy["identity"], "issuer": policy["provider"], "device_fingerprint": policy["device_fingerprint"]}, unrecognized_fields=unrecognized_fields)
#     sig = bundle["messageSignature"]["signature"]
#     signature=Signature(keyid=keyid,sig=sig, unrecognized_fields=unrecognized_fields)
#     key.verify_signature(signature=signature, data=data)
#     print("verified")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run the script in different modes: a, b, or c.")
    parser.add_argument("--mode", choices=["a", "b", "c"], required=True, help="Mode to run: a, b, or c")
    parser.add_argument("--level", type=int, default=1, help="Optional level parameter (default: 1)")
    args = parser.parse_args()

    LEVEL = args.level
    perf_utils.set_test_mode(args.mode, args.level)
    if args.mode == "a":
        policy = f"policy_a{args.level}.json"
        run_mode_a(policy)
    elif args.mode == "b":
        policy = f"policy_{args.level}.json"
        run_mode_b(policy)
    elif args.mode == "c":
        policy = f"policy_{args.level}.json"
        run_mode_c(policy)

    # signature_verifier()
    # vanilla_artifact_signing()
    # artifact_signing()
    # verify_artifact_signature()