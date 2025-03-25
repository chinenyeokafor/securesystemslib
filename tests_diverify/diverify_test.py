from DiVerify.trustverifier import security_key
from DiVerify.trustverifier.utils.credential_store import load_credentials, save_credentials
from DiVerify.trustverifier.trust_verifier_loader import load_trust_verifier
import requests


# Device Fingerprinter
trust_verifier = "device_fingerprinter"
verifier = load_trust_verifier(trust_verifier)
verification_result = verifier.verify()
print(f"Device Fingerprint is: {verification_result}\n")

# Security Key
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
    save_credentials(user_id, credentials)

# Local Scope to limit Signing

# trust_verifier = "local_scope"
# identity_token = "signer identity_token"
# repo_full_name = "repo_full_name where package to be signed lives"
# username = "signer username from id token"

# verifier = load_trust_verifier(trust_verifier)

# try:
#     scope = verifier.verify(identity_token=identity_token, repo_full_name=repo_full_name, username=username)
#     print(f"User {username} has the following scope in {repo_full_name}: {scope}")
# except ValueError as ve:
#     print(f"Missing parameters: {ve}")
# except requests.exceptions.RequestException as e:
#     print(f"An error occurred: {e}")