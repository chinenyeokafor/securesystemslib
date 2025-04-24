from securesystemslib.signer._signer import Signature
from securesystemslib.diverify.policy import PolicyEvaluator
from securesystemslib.exceptions import VerificationError, UnverifiedSignatureError
import logging
from pathlib import Path
import os
import json
from typing import cast
import base64
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from securesystemslib.diverify.util import perf_utils
from DiVerify.daemon.quote import verify_quote, validate_user_data

logger = logging.getLogger(__name__)

from securesystemslib.diverify._diverify_sigstore_signer import DEFAULT_REKOR_URL
IMPORT_ERROR = "Required dependencies for signature verification are not installed."

def verify_signature(signature: Signature, data: bytes, identity: str, issuer: str, policy: str) -> None:
    keyid = signature.keyid
    try:
        from sigstore.errors import VerificationError as SigstoreVerifyError
        from sigstore.models import Bundle
        from sigstore.verify import Verifier
        from sigstore.verify.policy import Identity
        from sigstore._internal.trust import TrustedRoot
        from sigstore._internal.rekor.client import RekorClient
        from sigstore_protobuf_specs.dev.sigstore.trustroot.v1 import (
            TrustedRoot as _TrustedRoot,
        )
    except ImportError as e:
        raise VerificationError(IMPORT_ERROR) from e

    try:
        from securesystemslib.signer import Signature
        path = Path(os.path.join(os.path.dirname(__file__), "trusted_root.json"))
        verifier = Verifier(rekor=RekorClient(DEFAULT_REKOR_URL), trusted_root=TrustedRoot(_TrustedRoot().from_json(path.read_bytes())))

        bundle_data = signature.unrecognized_fields["bundle"]
        bundle = Bundle.from_json(json.dumps(bundle_data))
        

        policy_evaluator = PolicyEvaluator(policy)
        result = policy_evaluator.evaluate({"cert": bundle.signing_certificate})
        if not result:
            raise VerificationError("The signature does not meet the policy constraints.")
        logger.info("Policy evaluation passed")

        identity = Identity(
            identity=identity, issuer=issuer
        )

        verifier.verify_artifact(data, bundle, identity)

    except SigstoreVerifyError as e:
        logger.info(
            "Key %s failed to verify sig: %s",
            keyid,
            e,
        )
        raise UnverifiedSignatureError(
            f"Failed to verify signature by {keyid}"
        ) from e
    except Exception as e:
        logger.info("Key %s failed to verify sig: %s", keyid, str(e))
        raise VerificationError(
            f"Unknown failure to verify signature by {keyid}"
        ) from e
    
def verify_quote_and_signature(signature_material, payload, identity, issuer, policy):
    """
    Perform a Trusted Verification of the quote and signature
    1. Verify the quote
    2. Validate the report data in the quote is consistent with the diverify_proof
    3. Verify diverify_proof against the policy
    4. Verify the artifact signature
    """    
    diverify_proof = signature_material['diverify_proof']
    hashed_input = signature_material["hashed_input"]
    artifact_signature = signature_material["artifact_signature"]
    # quote = base64.b64decode(diverify_proof.get("quote"))
    proof_without_quote = diverify_proof.copy()
    quote = base64.b64decode(proof_without_quote.pop("quote"))
    dvp_hash = hashlib.sha256(
                            json.dumps(proof_without_quote).encode()
                        ).digest()
    public_key = diverify_proof["public_key"]
    public_key = serialization.load_pem_public_key(
                        public_key.encode('utf-8'),
                        backend=default_backend()
                    )
    # step 1
    validate_user_data(quote, dvp_hash, public_key) 

    # step 2 & 3
    policy_evaluator = PolicyEvaluator(policy) 

    result = policy_evaluator.evaluate({"diverify_proof": diverify_proof})
    if not result:
        raise VerificationError("The signature does not meet the policy constraints.")
    logger.info("Policy evaluation passed")

    # step 3: Verify the quote in quote verification enclave

    _verif_quote(quote)

    # step 4: verify that the signature was signed by the public key in the diverify proof.
    try:
        signing_key = cast(ec.EllipticCurvePublicKey, public_key)
        signing_key.verify(
            artifact_signature,
            hashed_input.digest,
            ec.ECDSA(Prehashed(hashes.SHA256())),
        )
    except InvalidSignature:
        raise VerificationError("Signature is invalid for input")

    logger.debug("Successfully verified signature...")


@perf_utils.measure_latency
def _verif_quote(quote):
    if not verify_quote(quote):
        raise VerificationError("Quote failed to verify.")
    return True

def check_size(cert):
    cert_bytes = cert.public_bytes(serialization.Encoding.DER)
    print(f"Size in bytes: {len(cert_bytes)}")

# def verify(quote_path):
#     try:
#         logger.debug("Starting SGX quote verification process")
        
#         base_dir = "/home/SGXDataCenterAttestationPrimitives/SampleCode/QuoteVerificationSample"
#         verification_app = os.path.join(base_dir, "app")
#         if not os.path.exists(verification_app):
#             logging.error(f"Verification tool not found at {verification_app}.")
#             return False
            
#         if not os.path.exists(quote_path):
#             logging.error(f"Quote file not found at {quote_path}")
#             return False
#         result = subprocess.run([verification_app, "-quote", quote_path],cwd=base_dir,capture_output=True,text=True,check=False)
        
#         if "Verification completed successfully" in result.stdout:
#             logging.info("Quote verification succeeded")
#             logging.debug(f"Verification output:\n{result.stdout}")
#             return True
#         elif "Warning: App: Verification completed, but collateral is out of date based " in result.stdout:
#             return True
#         else:
#             logging.error("Quote verification failed")
#             if result.stderr:
#                 logging.error(f"Error output:\n{result.stderr}")
#             else:
#                 logging.error(f"Tool output:\n{result.stdout}")
#             return False
            
#     except subprocess.CalledProcessError as e:
#         logging.error(f"Verification process failed with exit code {e.returncode}")
#         logging.debug(f"Process output:\n{e.stderr if e.stderr else e.stdout}")
#         return False
#     except Exception as e:
#         logging.error(f"Unexpected error during verification: {str(e)}", exc_info=True)
#         return False
    
# def verify_quote(quote_data):
#     """Verify a quote received as byte data."""
#     try:
#         with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as temp_file:
#             temp_file.write(quote_data)
#             temp_path = temp_file.name
#         return verify(temp_path)
#     except Exception as e:
#         print(f"Verification failed: {e}")
#         return False
#     finally:
#         os.unlink(temp_path) if 'temp_path' in locals() and os.path.exists(temp_path) else None

  
