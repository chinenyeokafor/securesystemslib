import json
from typing import cast
from cryptography.exceptions import InvalidSignature
from securesystemslib.exceptions import (
    VerificationError,
)
import logging
import hashlib, base64, json
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from securesystemslib.diverify.quote import validate_user_data
from securesystemslib.diverify.util import perf_utils
import argparse
import logging
import os
import tempfile, subprocess
import traceback
from hashlib import sha256
from pathlib import Path

import urllib3
import requests
logger = logging.getLogger(__name__)
from tuf.api.exceptions import DownloadError, RepositoryError
from tuf.ngclient import Updater, UpdaterConfig
from securesystemslib.signer import KEY_FOR_TYPE_AND_SCHEME, SigstoreKey
KEY_FOR_TYPE_AND_SCHEME.update({("sigstore-oidc", "Fulcio"): SigstoreKey,})

class PolicyEvaluator:
    def __init__(self, policy_file: str = None):
        """Initialize with a policy file."""
        try:
            self.policy = self.get_policy_from_tuf(policy_file)
        except:
            policy_path = self.get_policy_path(policy_file)
            self.policy = self.load_policy(policy_path)
        
    
    @perf_utils.measure_latency
    def get_policy_from_tuf(self, target = "policy_a1.json"):

        base_url = "http://diverify_web:8083"
        DOWNLOAD_DIR = "/home"

        metadata_dir = self.build_metadata_dir(base_url)

        if not os.path.isfile(f"{metadata_dir}/root.json"):
            print(
                "Trusted local root not found. Use 'tofu' command to "
                "Trust-On-First-Use or copy trusted root metadata to "
                f"{metadata_dir}/root.json"
            )
            return False

        logger.debug(f"Using trusted root in {metadata_dir}")

        if not os.path.isdir(DOWNLOAD_DIR):
            os.mkdir(DOWNLOAD_DIR)

        updater_config = UpdaterConfig(
            prefix_targets_with_hash=False
        )
        try:

            metadata_base_url='http://tuf-metadata:8082'
            updater = Updater(
                metadata_dir=metadata_dir,
                metadata_base_url=metadata_base_url,
                target_base_url=base_url,
                target_dir=DOWNLOAD_DIR,
                config=updater_config,

            )
            updater.refresh()
            
            info = updater.get_targetinfo(target)

            if info is None:
                print(f"Target {target} not found")
                return self.load_policy(path)

            path = updater.find_cached_target(info)
            if path:
                logger.debug(f"Target is available in {path}")
                return self.load_policy(path)

            path = updater.download_target(info)
            # print(f"Target downloaded and available in {path}")

        except (OSError, RepositoryError, DownloadError) as e:
            print(f"Failed to download target {target}: {e}")
            if logging.root.level < logging.ERROR:
                traceback.print_exc()
            return ""
        return self.load_policy(path)
        

    def build_metadata_dir(self, base_url: str) -> str:
        """build a unique and reproducible directory name for the repository url"""
        name = sha256(base_url.encode()).hexdigest()[:8]
        # TODO: Make this not windows hostile?
        return "./tuf-metadata"

    def get_policy_path(self, policy_file) -> str:
        policy_path = Path(os.path.join(os.path.dirname(__file__), policy_file))
        if not policy_path.exists():
            raise FileNotFoundError(f"Policy file not found: {policy_path}")
        return policy_path

    def load_policy(self, file_path: str) -> dict:
        with open(file_path, "r") as f:
            return json.load(f)

    def build_context(self, diverify_proof) -> dict:
        slot9a_public_key = self.policy.get("security_key").get("slot9a_public_key")
        slot9a_attestation_cert = self.policy.get("security_key").get("slot9a_attestation_cert")
        piv_attestation = diverify_proof.get('identity').get("security_key")
        
        slot9a_public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyPANdivOD+syGUwVmOoN\nyo+rxUE8uOTusyhqKux/Yh+/2f/SSuLT38Q5mCo/PPBpIN5bn2RKou2ttMlCO0Dk\nCwA3ZencDqdGcDdjJ6++pD1X7gJV0Pe7UlWGZGoqtlQFU/3kYS+dukuRsYWjk0Nk\nxHwNbHXTUnphOkpvptLd+MMl85UxdAqUtKUhrVuUl1hGIllEOplz2iGK4Ot79xsV\nSoITzYLwM2RbsdU4exRgrpQqy0PHlStGOXx6xk8Oa6+JxjuE0qzOtDWCdMcnLDV+\nuf7gvSjywag7AyE0RxtU5j3J0+sYlTxYSoJUHuId9vk0YW5SZI7j4ZK6TDIPmkzf\nKQIDAQAB\n-----END PUBLIC KEY-----"
        slot9a_attestation_cert = "-----BEGIN CERTIFICATE-----\nMIIC+jCCAeKgAwIBAgIJAJF9cmxN2+oAMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNV\nBAMMIFl1YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAw\nMDAwMFoYDzIwNTIwNDE3MDAwMDAwWjAhMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0\ndGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4GVnOpu\nnNI/CYsL/DwNkT2N7gLp3Bd/thHWSWNVcZ6UuvgFnwO8WtAZ6kPwayII09rJnAgi\nED9qeW/WxRQymn+P624jLkfVKmBbGNjX81q9/6bUGZIm6iQPQPp17BSicY0tQpM2\nz2kV98e3XFNkACI5QiE9vbXdsPq3PhDmgD9ZYRpcbM8G/WLZ1DO0jsGhHhfJxepY\ntOfUsPzUQ/E9aDmZ21+/TSZm+OuLOs4sZIVBBy3hHdEhB+DLMbJ4eq9jYv1WeyAK\nfYYolkeWbUt0zHQmx3MOUdX1pJdqh7K/1oQKBTwR5s77mprbzWBfKgxoJDl+1kN0\nsA2S1hXDQn/4WQIDAQABoykwJzARBgorBgEEAYLECgMDBAMFAgcwEgYDVR0TAQH/\nBAgwBgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAQEASNb5w/pmYp/Qeq7qjSY3UdUi\nfVR6kXtmaMOZ2HRmZr/wQa+PWHnQWwnL8tRJeomEb0zC5qQvOpEqJvdiTO+TWukC\nALAlXnSM2Dn7+fJl45AKtD7l0aXYSnlGF1rYi3lSdmPG8Ptxoc+WChCaNB1X7pM/\nlnP3uWncij1dr/G48cDLC8OPeBsojFzqBX9E1HfiBnjwOokvR8/sUSFOVB+NyDhv\nt42i2Iz/2BB3KeD/8w/C+PmEqse2kC/D6coLs1n8eqQJUwasuPd6SN37WOmf/AoI\n+i2DR7MtBGuQ+AiiL5OBvkCZpvm54MpA4jrFfj31Q6Yv8rXbWUrEfBNbWBWpJA==\n-----END CERTIFICATE-----"
        piv_attestation = "-----BEGIN CERTIFICATE-----\nMIIDIDCCAgigAwIBAgIQAcbB8zx5+995nXk5DGDr4TANBgkqhkiG9w0BAQsFADAh\nMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0dGVzdGF0aW9uMCAXDTE2MDMxNDAwMDAw\nMFoYDzIwNTIwNDE3MDAwMDAwWjAlMSMwIQYDVQQDDBpZdWJpS2V5IFBJViBBdHRl\nc3RhdGlvbiA5YTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMjwDXYr\nzg/rMhlMFZjqDcqPq8VBPLjk7rMoairsf2Ifv9n/0kri09/EOZgqPzzwaSDeW59k\nSqLtrbTJQjtA5AsAN2Xp3A6nRnA3YyevvqQ9V+4CVdD3u1JVhmRqKrZUBVP95GEv\nnbpLkbGFo5NDZMR8DWx101J6YTpKb6bS3fjDJfOVMXQKlLSlIa1blJdYRiJZRDqZ\nc9ohiuDre/cbFUqCE82C8DNkW7HVOHsUYK6UKstDx5UrRjl8esZPDmuvicY7hNKs\nzrQ1gnTHJyw1frn+4L0o8sGoOwMhNEcbVOY9ydPrGJU8WEqCVB7iHfb5NGFuUmSO\n4+GSukwyD5pM3ykCAwEAAaNOMEwwEQYKKwYBBAGCxAoDAwQDBQIHMBQGCisGAQQB\ngsQKAwcEBgIEAPM1RjAQBgorBgEEAYLECgMIBAICATAPBgorBgEEAYLECgMJBAED\nMA0GCSqGSIb3DQEBCwUAA4IBAQAU94+7V3HNkapLPJ6HW/H8VO8dSqk693O3WB1w\ngfFg1tbddgb1n1gIcjAgUhB8E72NpAllKXwAfk8bpQjO530TNHM8rVFvRkITZacl\nUbUPmiK4L+ykQje+J4qPIsdyzw2PGbPCtFfH0J/uCsVOxhkhqkmVXWpBg4Hkdl38\nAbVdU2bnvt4QliOOH1pafaWETCOxf3PLFvtxvnVrrLbAj51U3ogovyWHvqYb+efS\noQf+f5GCrORzS+mKnOlL8+dG8DdDiFWi/iB2RwvTg/EBeHmPktmMUQ21b3EWrScP\nFhWtFzNedwrG+dMDvBljjpd85KChkm4O1lFfKwQbiX8pVKZw\n-----END CERTIFICATE-----"
        
        return {
            "identity": diverify_proof.get('identity').get("oidc").get("sub") == self.policy.get("identity"),
            "provider": diverify_proof.get('identity').get("oidc").get("iss") == self.policy.get("provider"),
            "device_fingerprint": diverify_proof.get('identity').get("device_fingerprint") == self.policy.get("device_fingerprint"),
            "security_key": diverify_proof.get('identity').get("security_key") == self.policy.get("security_key"),
            "security_key": self.verify_piv_attestation(slot9a_attestation_cert, slot9a_public_key, piv_attestation),
            "signer_measurement": diverify_proof.get('identity').get("signer_measurement") == self.policy.get("signer_measurement"),
            "ra_required": diverify_proof.get('identity').get("ra_required"), # this should be false by default
        }
    @perf_utils.measure_latency
    def evaluate(self, trust_material) -> bool:
        cert = trust_material.get("cert")
        diverify_proof = trust_material.get("diverify_proof")
        if cert:
            quote, diverify_proof = self.retrieve_quote(cert)
            key = cert.public_key()
            # self.show_cert(cert)
        elif diverify_proof:   
            quote = base64.b64decode(diverify_proof.pop("quote"))
            key = diverify_proof.get("public_key")
            key = serialization.load_pem_public_key(
                        key.encode('utf-8'),
                        backend=default_backend()
                    )
        try:
            if self.policy.get("ra_required"):
                proof_hash = hashlib.sha256(json.dumps(diverify_proof).encode()).digest()
                if quote and not validate_user_data(quote, key, proof_hash):
                    raise InvalidSignature
            context = self.build_context(diverify_proof)
            rule = self.policy["rule"].replace("AND", "and").replace("OR", "or")
            return eval(rule, {}, context)
        except InvalidSignature as e:
            raise VerificationError(f"Invalid quote user data signature: {str(e)}")
        except ValueError as e:
            raise VerificationError(f"Error retrieving quote frm cert: {str(e)}")
        
    def retrieve_quote(self, cert):
        diverify_OID = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.23")
        try:
            ext = cert.extensions.get_extension_for_oid(diverify_OID)
            data = ext.value.value
            json_start = data.find(b"{")
            if json_start == -1:
                raise ValueError("Invalid diverify_OID content")
            proof_without_quote = json.loads(data[json_start:].decode())
            try:
                quote = base64.b64decode(proof_without_quote.pop("quote"))
            except KeyError:
                # Mode A is used
                quote = ""
            return quote, proof_without_quote
        except x509.ExtensionNotFound:
            raise ValueError(f"Extension with OID {diverify_OID} not found.")
    

    def verify_piv_attestation(self, slot9a_attestation_cert, slot9a_public_key, piv_attestation):
        def run(cmd):
            return subprocess.run(cmd, check=True, stdout=subprocess.PIPE).stdout

        try:
            CA_URL = "https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem"

            if not slot9a_attestation_cert or not slot9a_public_key:
                print("Missing attestation certificate or slot9a public_key in policy.")
                return False
            if not piv_attestation:
                print("Missing PIV attestation in DiVerify proof")
                return False

            with tempfile.NamedTemporaryFile("w+", delete=True) as f9_cert, \
                tempfile.NamedTemporaryFile("w+", delete=True) as pubkey, \
                tempfile.NamedTemporaryFile("w+", delete=True) as attest_cert, \
                tempfile.NamedTemporaryFile("wb+", delete=True) as ca_cert:

                f9_cert.write(slot9a_attestation_cert); f9_cert.flush()
                pubkey.write(slot9a_public_key); pubkey.flush()
                attest_cert.write(piv_attestation); attest_cert.flush()

                ca_cert.write(requests.get(CA_URL).content); ca_cert.flush()

                run([
                    "openssl", "verify",
                    "-CAfile", ca_cert.name,
                    "-untrusted", f9_cert.name,
                    attest_cert.name
                ])

                attested_pub = run(["openssl", "x509", "-in", attest_cert.name, "-pubkey", "-noout"])
                saved_pub = Path(pubkey.name).read_bytes()

                if attested_pub.strip() != saved_pub.strip():
                    raise ValueError("Public key mismatch — attestation invalid.")

            return True
        except Exception as e:
            print(f"PIV Attestation verification failed: {e}")
            return False

    def show_cert(self, signing_certificate):
        """Display the signing certificate in text format."""
        from OpenSSL import crypto
        from cryptography.hazmat.primitives.serialization import Encoding

        cert = crypto.load_certificate(
            crypto.FILETYPE_ASN1,
            signing_certificate.public_bytes(Encoding.DER)
        )

        text_output = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert)
        logging.info(f"Signing Certificate: {text_output.decode('utf-8')}")

if __name__ == "__main__":
    policy_evaluator = PolicyEvaluator("policy.json")

    keyval = {
        "identity": "alice@issuer.com",
        "issuer": "issuer.com",
        "device_fingerprint": "fingerprint123",
    }

    result = policy_evaluator.evaluate(keyval)
    assert result, "Policy evaluation failed"
