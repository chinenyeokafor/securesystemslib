import json
import requests
from securesystemslib.signer._utils import compute_default_keyid

RSTUF_API = "https://your-rstuf-instance/api"

def create_delegation(project: str, pubkey: dict[str, dict | str]) -> dict:
    payload = {
        "delegations": {
            "keys": {
                pubkey["keyid"]: {
                    "keytype": pubkey["keytype"],
                    "keyval1": {
                        "diverify-policy": {
                            "identity": "user@domain",
                            "provider": "identity provider",
                            "device_fingerprint": "<fingerprint>",
                            "security_key": "<key_cred>",
                            "RA": True,
                            "pubkey": pubkey["keyval"]["public"],
                            "rule": "identity" and "provider" and ("device_fingerprint" or "security_key") and "pubkey"
                        }
                    },
                    "keyval2": {
                        "diverify-policy": {
                            "path": "path-to-diverify-policy",
                            "pubkey": pubkey["keyval"]["public"]
                        }
                    },
                    "scheme": pubkey["scheme"],
                    "x-rstuf-key-name": project
                }
            },
            "roles": [
                {
                    "keyids": [pubkey["keyid"]],
                    "name": f"{project}-policy",
                    "paths": [f"pypi/{project}/*"],
                    "terminating": True,
                    "threshold": 1,
                    "x-rstuf-expire-policy": 365
                }
            ]
        }
    }
    
    response = requests.post(f"{RSTUF_API}/delegations", json=payload)
    return response.json()

# Example public key (normally extracted from PyPI metadata)
example_pubkey = {
    "keyid": "abcd1234",
    "keytype": "ed25519",
    "public": "4f66dabebcf30628963786001984c0b75c175cdcf3bc4855933a2628f0cd0a0f",
    "scheme": "ed25519"
}

# Delegate project
result = create_delegation("example_project", example_pubkey)
print(result)
