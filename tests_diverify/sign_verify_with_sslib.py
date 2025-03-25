from securesystemslib.signer import SigstoreKey
from securesystemslib.signer._signer import Signature
import json
from securesystemslib.signer import (
    SIGNER_FOR_URI_SCHEME,
    Signer,
    SigstoreSigner,
)
import logging

logging.basicConfig(level=logging.DEBUG)

def artifact_signing():
    TEST_IDENTITY = "okaforchinenyelilian@gmail.com"
    TEST_ISSUER = "http://sigstore-dex:6000"
    SIGNER_FOR_URI_SCHEME[SigstoreSigner.SCHEME] = SigstoreSigner

    uri, public_key=SigstoreSigner.import_(TEST_IDENTITY, TEST_ISSUER, ambient=False)
    print(f"Before Signer.from_priv_key_ur")
    signer=Signer.from_priv_key_uri(uri, public_key)

    # Project TODO: Add logic to perform DiVerify trust verification
    # sig=signer.sign(b"data")
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
    artifact_signing()