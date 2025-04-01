import json
from typing import cast

class PolicyEvaluator:
    def __init__(self, policy_file: str):
        """Initialize with a policy file."""
        self.policy = self.load_policy(policy_file)

    def load_policy(self, file_path: str) -> dict:
        with open(file_path, "r") as f:
            return json.load(f)

    def build_context(self, keyval: dict) -> dict:
        return {
            "identity": keyval.get("identity") == self.policy.get("identity"),
            "provider": keyval.get("issuer") == self.policy.get("provider"),
            "device_fingerprint": keyval.get("device_fingerprint") == self.policy.get("device_fingerprint"),
            "security_key": keyval.get("security_key") == self.policy.get("security_key"),
            "signer_measurement": keyval.get("signer_measurement") == self.policy.get("signer_measurement"),
        }

    def evaluate(self, keyval: dict, cert) -> bool:
        if self.policy.get("ra_required", False):
            # verify signing key with 
            # try:
            #     import hashlib
            #     signing_key = cert.public_key()
            #     signing_key = cast(ec.EllipticCurvePublicKey, signing_key)
            #     input = cert.dvp - {cert.dvp.quote}
            #     signing_key.verify(
            #         cert.dvp.quote.user_data,
            #         input,
            #         ec.ECDSA(hashlib.sha256(input)._as_prehashed()),
            #     )
            # except InvalidSignature:
            #     return VerificationError("Invalid signature")
            pass
        context = self.build_context(keyval)
        rule = self.policy["rule"].replace("AND", "and").replace("OR", "or")

        try:
            return eval(rule, {}, context)
        except Exception as e:
            print(f"Error evaluating policy rule: {e}")
            return False

if __name__ == "__main__":
    policy_evaluator = PolicyEvaluator("policy.json")

    keyval = {
        "identity": "alice@issuer.com",
        "issuer": "issuer.com",
        "device_fingerprint": "fingerprint123",
    }

    result = policy_evaluator.evaluate(keyval)
    assert result, "Policy evaluation failed"
