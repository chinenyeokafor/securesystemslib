from securesystemslib.signer import SigstoreKey
from securesystemslib.signer._signer import Signature
import json
import hashlib
from securesystemslib.signer import (
    SIGNER_FOR_URI_SCHEME,
    Signer,
    SigstoreSigner,
)
from securesystemslib.diverify.daemon import get_auth_requirements, submit_auth_result, verify_security_key, verify_device_fingerprint
import logging
import base64
from cryptography.x509 import load_pem_x509_certificate

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
LEVEL = 3

def vanilla_artifact_signing():
    TEST_IDENTITY = "okaforchinenyelilian@gmail.com"
    TEST_ISSUER = "http://sigstore-dex:6000"
    SIGNER_FOR_URI_SCHEME[SigstoreSigner.SCHEME] = SigstoreSigner

    uri, public_key=SigstoreSigner.import_(TEST_IDENTITY, TEST_ISSUER, ambient=False)
    print(f"Before Signer.from_priv_key_ur")
    signer, _ =Signer.from_priv_key_uri(uri, public_key)

    # Project TODO: Add logic to perform DiVerify trust verification
    # sig=signer.sign(b"data")
    sig=signer.sign(b"data")

    # Project TODO: Fetch DiVerify Policy
    # Project TODO: Add logic to perform DiVerify specific verification against policy

    # Successful verification
    public_key.verify_signature(sig, b"data")



class Hashed:
    def __init__(self, algorithm: str, digest: bytes):
        self.algorithm = algorithm
        self.digest = digest
    
    @classmethod
    def from_dict(cls, data):
        algorithm = data["algorithm"]
        digest = base64.b64decode(data["digest"])
        return cls(algorithm, digest)

def artifact_signing():
    TEST_IDENTITY = "okaforchinenyelilian@gmail.com"
    TEST_ISSUER = "http://sigstore-dex:6000"
    DEVICE_FINGERPRINT = "54aa8265a2c74fdd477f55f00f06136d2d93c7a56fe3e346bdc0bbc9411e3110"
    RA = "xx"
    SIGNER_FOR_URI_SCHEME[SigstoreSigner.SCHEME] = SigstoreSigner

    uri, public_key=SigstoreSigner.import_(TEST_IDENTITY, TEST_ISSUER, ambient=False)
    

    required_auth, nonces, state = get_auth_requirements(LEVEL)

    limit_scope_flag = False
    sign_in_enclave = False
    proofs = {}

    # TODO: Fix state verification later
    for auth in required_auth:
        if auth == "device_fingerprint":
            proofs[auth] = verify_device_fingerprint(auth, state=nonces[auth])
            print(hashlib.sha256(proofs[auth].encode()).hexdigest())
        elif auth == "security_key":
            # Not sure what i should result to implement to be returned here or how to include nonce. Will revisit.
            # TODO: Liaise with ST.
            # if verify_security_key():
            #     proofs[auth] = True
            # for now, just assume its done
            proofs[auth] = True
        elif auth == "source_local_scope":
            limit_scope_flag = True
        elif auth == "attestation":
            sign_in_enclave = True

    # Temporay impl
    proofs = {auth: f"some_{auth}" for auth in required_auth}
    proofs.update({f"{auth}_nonce": nonces[auth] for auth in required_auth})

    # this is where the user token is retrieved. All level require oidc. We use the limit scope flag to 
    # tell the oidc verifier to request for authorization right enough to retrieve the user's permission on a repo
    signer, token =Signer.from_priv_key_uri(uri, public_key, secrets_handler=limit_scope_flag)
    proofs['oidc'] = token

    print(proofs)

    if sign_in_enclave:
        proofs["attestation"] = base64.b64encode(b"data").decode('utf-8')
        signature_material = submit_auth_result(LEVEL, proofs, state)
        if not signature_material:
            raise RuntimeError("Signing failed: daemon did not sign or return signing materials.")
        else:
            signature_material = json.loads(base64.b64decode(signature_material).decode('utf-8'))
            signature_material = {
                "hashed_input": Hashed.from_dict(signature_material["hashed_input"]),
                "artifact_signature": base64.b64decode(signature_material["artifact_signature"]),
                "signing_cert": load_pem_x509_certificate(signature_material["signing_cert"].encode('utf-8')),
            }
            sig=signer.submit_to_tlog(signature_material)
    else:
        diverify_proof = submit_auth_result(LEVEL, proofs, state)
        # TODO: Pass the diverify proof to be included in fulcio cert
        sig=signer.sign(b"data")

    # Project TODO: Fetch DiVerify Policy
    # Project TODO: Add logic to perform DiVerify specific verification against policy

    # Successful verification
    public_key.verify_signature(sig, b"data")



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
    key=SigstoreKey(keyid=keyid, keytype='sigstore-oidc', scheme ='Fulcio', keyval={"identity": "okaforchinenyelilian@gmail.com", "issuer": "https://github.com/login/oauth"}, unrecognized_fields=unrecognized_fields)
    sig = bundle["messageSignature"]["signature"]
    signature=Signature(keyid=keyid,sig=sig, unrecognized_fields=unrecognized_fields)
    key.verify_signature(signature=signature, data=data)
    print("verified")

def verify_signature():
    from pathlib import Path
    import os
    file_path = Path(os.path.dirname(__file__)) / "signature/artifact.sig.json"

    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    #signature bundle
    with open(file_path, "r") as file:
        bundle=json.load(file)

    #the signed file
    with open("artifact", "rb") as artifact_file:
        data = artifact_file.read()
    with open(Path(os.path.dirname(__file__)) /"policy.json", "r") as policy:
        policy=json.load(policy)
    keyid=bundle["verificationMaterial"]["tlogEntries"][0]["logId"]["keyId"]
    unrecognized_fields={"bundle": bundle, "diverify_policy": policy}
    key=SigstoreKey(keyid=keyid, keytype='sigstore-oidc', scheme ='Fulcio', keyval={"identity": policy["identity"], "issuer": policy["provider"], "device_fingerprint": policy["device_fingerprint"]}, unrecognized_fields=unrecognized_fields)
    sig = bundle["messageSignature"]["signature"]
    signature=Signature(keyid=keyid,sig=sig, unrecognized_fields=unrecognized_fields)
    key.verify_signature(signature=signature, data=data)
    print("verified")

if __name__ == "__main__":
    # signature_verifier()
    # vanilla_artifact_signing()
    # artifact_signing()
    verify_signature()