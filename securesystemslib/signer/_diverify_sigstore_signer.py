"""Signer implementation for project sigstore."""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib import parse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import CertificateSigningRequestBuilder, Name, NameAttribute, BasicConstraints
from cryptography.x509.oid import NameOID
from typing import Tuple, Optional
import base64

from securesystemslib.exceptions import (
    UnsupportedLibraryError,
    UnverifiedSignatureError,
    VerificationError,
)

from sigstore.models import Bundle
from sigstore import hashes as sigstore_hashes

from securesystemslib.signer._signer import (
    Key,
    SecretsHandler,
    Signature,
    Signer,
)
from securesystemslib.signer._utils import compute_default_keyid

IMPORT_ERROR = "sigstore library required to use 'sigstore-oidc' keys"

logger = logging.getLogger(__name__)



class SigstoreKey(Key):
    """Sigstore verifier.

    NOTE: The Sigstore key and signature serialization formats are not yet
    considered stable in securesystemslib. They may change in future releases
    and may not be supported by other implementations.
    """

    DEFAULT_KEY_TYPE = "sigstore-oidc"
    DEFAULT_SCHEME = "Fulcio"

    def __init__(
        self,
        keyid: str,
        keytype: str,
        scheme: str,
        keyval: dict[str, Any],
        unrecognized_fields: dict[str, Any] | None = None,
    ):
        for content in ["identity", "issuer"]:
            if content not in keyval or not isinstance(keyval[content], str):
                raise ValueError(f"{content} string required for scheme {scheme}")
        super().__init__(keyid, keytype, scheme, keyval, unrecognized_fields)

    @classmethod
    def from_dict(cls, keyid: str, key_dict: dict[str, Any]) -> SigstoreKey:
        keytype, scheme, keyval = cls._from_dict(key_dict)
        return cls(keyid, keytype, scheme, keyval, key_dict)

    def to_dict(self) -> dict:
        return self._to_dict()

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        try:
            from sigstore.errors import VerificationError as SigstoreVerifyError
            from sigstore.models import Bundle
            from sigstore.verify import Verifier
            from sigstore.verify.policy import Identity
        except ImportError as e:
            raise VerificationError(IMPORT_ERROR) from e

        try:
            verifier = Verifier.production()
            identity = Identity(
                identity=self.keyval["identity"], issuer=self.keyval["issuer"]
            )
            bundle_data = signature.unrecognized_fields["bundle"]
            bundle = Bundle.from_json(json.dumps(bundle_data))

            verifier.verify_artifact(data, bundle, identity)

        except SigstoreVerifyError as e:
            logger.info(
                "Key %s failed to verify sig: %s",
                self.keyid,
                e,
            )
            raise UnverifiedSignatureError(
                f"Failed to verify signature by {self.keyid}"
            ) from e
        except Exception as e:
            logger.info("Key %s failed to verify sig: %s", self.keyid, str(e))
            raise VerificationError(
                f"Unknown failure to verify signature by {self.keyid}"
            ) from e


class SigstoreSigner(Signer):
    """Sigstore signer.

    NOTE: The Sigstore key and signature serialization formats are not yet
    considered stable in securesystemslib. They may change in future releases
    and may not be supported by other implementations.

    All signers should be instantiated with ``Signer.from_priv_key_uri()``.
    Unstable ``SigstoreSigner`` currently requires opt-in via
    ``securesystemslib.signer.SIGNER_FOR_URI_SCHEME``.

    Usage::

        identity = "luk.puehringer@gmail.com"  # change, unless you know pw
        issuer = "https://github.com/login/oauth"

        # Create signer URI and public key for identity and issuer
        uri, public_key = SigstoreSigner.import_(identity, issuer, ambient=False)

        # Load signer from URI -- requires browser login with GitHub
        signer = SigstoreSigner.from_priv_key_uri(uri, public_key)

        # Sign with signer and verify public key
        signature = signer.sign(b"data")
        public_key.verify_signature(signature, b"data")

    The private key URI scheme is "sigstore:?<PARAMS>", where PARAMS is
    optional and toggles ambient credential usage. Example URIs:

    * "sigstore:":
        Sign with ambient credentials.
    * "sigstore:?ambient=false":
        Sign with OAuth2 + OpenID via browser login.

    Arguments:
        token: The OIDC identity token used for signing.
        public_key: The related public key instance.

    Raises:
        UnsupportedLibraryError: sigstore library not found.
    """

    SCHEME = "sigstore"

    def __init__(self, token: Any, decoded_token:Any, public_key: Key):
        self._public_key = public_key
        # token is of type sigstore.oidc.IdentityToken but the module should be usable
        # without sigstore so it's not annotated
        self._token = token
        self._decoded_token = decoded_token

    @property
    def public_key(self) -> Key:
        return self._public_key

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: SecretsHandler | None = None,
    ) -> SigstoreSigner:
        try:
            from sigstore.oidc import detect_credential
        except ImportError as e:
            raise UnsupportedLibraryError(IMPORT_ERROR) from e

        if not isinstance(public_key, SigstoreKey):
            raise ValueError(f"expected SigstoreKey for {priv_key_uri}")

        uri = parse.urlparse(priv_key_uri)

        if uri.scheme != cls.SCHEME:
            raise ValueError(f"SigstoreSigner does not support {priv_key_uri}")

        params = dict(parse.parse_qsl(uri.query))
        ambient = params.get("ambient", "true") == "true"

        if not ambient:
            token, decoded_token = cls._get_identity_token()
        else:
            import jwt
            credential = detect_credential()
            if not credential:
                raise RuntimeError("Failed to detect Sigstore credentials")
            # token = IdentityToken(credential)
            token, decoded_token = credential, jwt.decode(credential, options={"verify_signature": False})

        key_identity = public_key.keyval["identity"]
        key_issuer = public_key.keyval["issuer"]
        if key_issuer != decoded_token["iss"]:
            raise ValueError(
                f"Signer identity issuer {decoded_token["iss"]} "
                f"did not match key: {key_issuer}"
            )
        # TODO: should check ambient identity too: unfortunately IdentityToken does
        # not provide access to the expected identity value (cert SAN) in ambient case
        try:
            identry_from_token = decoded_token['email']
        except:
            identry_from_token = decoded_token['sub']
        if not ambient and key_identity != identry_from_token:
            raise ValueError(
                f"Signer identity {identry_from_token} did not match key: {key_identity}"
            )

        return cls(token, decoded_token, public_key)

    @classmethod
    def _get_uri(cls, ambient: bool) -> str:
        return f"{cls.SCHEME}:{'' if ambient else '?ambient=false'}"

    @classmethod
    def import_(
        cls, identity: str, issuer: str, ambient: bool = True
    ) -> tuple[str, SigstoreKey]:
        """Create public key and signer URI.

        Returns a private key URI (for Signer.from_priv_key_uri()) and a public
        key. import_() should be called once and the returned URI and public
        key should be stored for later use.

        Arguments:
            identity: The OIDC identity to use when verifying a signature.
            issuer: The OIDC issuer to use when verifying a signature.
            ambient: Toggle usage of ambient credentials in returned URI.
        """
        keytype = SigstoreKey.DEFAULT_KEY_TYPE
        scheme = SigstoreKey.DEFAULT_SCHEME
        keyval = {"identity": identity, "issuer": issuer}
        keyid = compute_default_keyid(keytype, scheme, keyval)
        key = SigstoreKey(keyid, keytype, scheme, keyval)
        uri = cls._get_uri(ambient)

        return uri, key 
    
    @staticmethod
    def _get_identity_token():
        """Retrieve an identity token using OAuth2 with Dex."""
        from jwt import decode
        import requests

        client_id = "sigstore"
        client_secret = ""

        auth_code, redirect_uri, code_verifier = SigstoreSigner.get_authorization_code(client_id, client_secret)

        response = requests.post(
            "http://sigstore-dex:6000/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            }
        )

        response.raise_for_status() 
        response_json = response.json()
        
        raw_token = response_json.get("id_token")
        if not raw_token:
            raise KeyError("Response does not contain 'id_token'")

        return raw_token, decode(raw_token, options={"verify_signature": False})

    @staticmethod
    def get_authorization_code(client_id, client_secret):
        """Starts a temporary web server on an available port to capture the authorization code."""
        import webbrowser
        import http.server
        import socketserver
        import urllib.parse
        from threading import Thread, Event
        import uuid

        class AuthHandler(http.server.BaseHTTPRequestHandler):
            """Handles the OAuth2 redirect and extracts the auth code."""
            def do_GET(self):
                parsed_path = urllib.parse.urlparse(self.path)
                query_params = urllib.parse.parse_qs(parsed_path.query)
                if "code" in query_params:
                    self.server.auth_code = query_params["code"][0]
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"Authentication successful. You can close this window.")
                    self.server.auth_event.set()  # Signal that auth is complete
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Authentication failed.")

        # Start a local web server to receive the authorization response
        server = socketserver.TCPServer(("localhost", 0), AuthHandler, bind_and_activate=False)
        server.allow_reuse_address = True
        server.server_bind()
        server.server_activate()
        port = server.server_address[1]
        redirect_uri = f"http://localhost:{port}/callback"
        
        # Generate PKCE parameters
        code_verifier, code_challenge = SigstoreSigner._generate_pkce_challenge()
        state, nonce = str(uuid.uuid4()), str(uuid.uuid4())

        # Prepare authentication URL
        auth_url = (
            f"http://sigstore-dex:6000/auth?"
            f"response_type=code&client_id={client_id}&client_secret={client_secret}&"
            f"scope=openid+email&redirect_uri={redirect_uri}&"
            f"code_challenge={code_challenge}&code_challenge_method=S256&"
            f"state={state}&nonce={nonce}"
        )

        print(f"Opening browser for login: {auth_url}")
        webbrowser.open(auth_url)

        # Use event to wait for auth completion
        server.auth_event = Event()
        server_thread = Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        print("Waiting for authentication...")
        server.auth_event.wait()  

        auth_code = server.auth_code
        server.shutdown()
        return auth_code, redirect_uri, code_verifier

    @classmethod
    def _generate_pkce_challenge(cls):
        import hashlib
        import os
        """Generates a PKCE challenge (S256)"""
        code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
        return code_verifier, code_challenge
    
    def generate_key_pair(self) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """Generate an EC key pair."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key

    def create_csr(self, private_key: ec.EllipticCurvePrivateKey, email_address: str) -> str:
        csr_builder = CertificateSigningRequestBuilder().subject_name(
            Name([
                NameAttribute(NameOID.EMAIL_ADDRESS, email_address),
            ])
        ).add_extension(
            BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        
        csr = csr_builder.sign(private_key, hashes.SHA256())
        # return csr.public_bytes(serialization.Encoding.PEM).decode()
        return csr
    

    def sign(self, payload: bytes) -> Signature:
        """Signs payload using the OIDC token on the signer instance.

        Arguments:
            payload: bytes to be signed.

        Raises:
            Various errors from sigstore-python.

        Returns:
            Signature.

            NOTE: The relevant data is in `unrecognized_fields["bundle"]`.

        """
        try:
            from sigstore.sign import SigningContext
        except ImportError as e:
            raise UnsupportedLibraryError(IMPORT_ERROR) from e

        context = SigningContext.production()

        # Step 1: Generate keys
        private_key, public_key = self.generate_key_pair()

        # Step 2: Create CSR using your email address
        try:
            email_address = self._decoded_token['email']
        except:
            email_address = self._decoded_token['sub']

        csr = self.create_csr(private_key, email_address)

        # Step 3: We assume identity token is valid and send CSR to Fulcio
        certificate_response = context._fulcio.signing_cert.post(
                csr, self._token
            )
        
        self.signing_cert = certificate_response.cert
        

        # Step 4: Sign the payload
        proposed_entry, content = self.sign_artifact(private_key, payload)

        # Submit the proposed entry to the transparency log
        entry = context._rekor.log.entries.post(proposed_entry)

        bundle = Bundle._from_parts(self.signing_cert, content, entry,)

        # We want to access the actual signature, see
        # https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto
        bundle_json = json.loads(bundle.to_json())
        import pdb;pdb.set_trace()
        return Signature(
            self.public_key.keyid,
            bundle_json["messageSignature"]["signature"],
            {"bundle": bundle_json},
        )

    def sign_artifact(
        self,
        private_key,
        input_: bytes | sigstore_hashes.Hashed,
    ) -> Bundle:
        
        """
        Sign an artifact, and return a `Bundle` corresponding to the signed result.

        The input can be one of two forms:

        1. A `bytes` buffer;
        2. A `Hashed` object, containing a pre-hashed input (e.g., for inputs
           that are too large to buffer into memory).

        Regardless of the input format, the signing operation will produce a
        `hashedrekord` entry within the bundle. No other entry types
        are supported by this API.
        """
        try:
            import rekor_types
            from sigstore._utils import sha256_digest
            from sigstore_protobuf_specs.dev.sigstore.common.v1 import (
                HashOutput,
                MessageSignature,
            )
        except ImportError as e:
            raise UnsupportedLibraryError(IMPORT_ERROR) from e

        cert = self.signing_cert

        # Prepare inputs
        b64_cert = base64.b64encode(
            cert.public_bytes(encoding=serialization.Encoding.PEM)
        )

        # Sign artifact
        hashed_input = sha256_digest(input_)

        artifact_signature = private_key.sign(
            hashed_input.digest, ec.ECDSA(hashed_input._as_prehashed())
        )

        content = MessageSignature(
            message_digest=HashOutput(
                algorithm=hashed_input.algorithm,
                digest=hashed_input.digest,
            ),
            signature=artifact_signature,
        )

        # Create the proposed hashedrekord entry
        proposed_entry = rekor_types.Hashedrekord(
            spec=rekor_types.hashedrekord.HashedrekordV001Schema(
                signature=rekor_types.hashedrekord.Signature(
                    content=base64.b64encode(artifact_signature).decode(),
                    public_key=rekor_types.hashedrekord.PublicKey(
                        content=b64_cert.decode()
                    ),
                ),
                data=rekor_types.hashedrekord.Data(
                    hash=rekor_types.hashedrekord.Hash(
                        algorithm=hashed_input._as_hashedrekord_algorithm(),
                        value=hashed_input.digest.hex(),
                    )
                ),
            ),
        )

        return proposed_entry, content


    @classmethod
    def import_github_actions(
        cls, project: str, workflow_path: str, ref: str | None = "refs/heads/main"
    ) -> tuple[str, SigstoreKey]:
        """Convenience method to build identity and issuer string for import_() from
        GitHub project and workflow path.

        Args:
            project: GitHub project name (example:
               "secure-systems-lab/securesystemslib")
            workflow_path: GitHub workflow path (example:
               ".github/workflows/online-sign.yml")
            ref: optional GitHub ref, defaults to refs/heads/main

        Returns:
            uri: string
            key: SigstoreKey

        """
        identity = f"https://github.com/{project}/{workflow_path}@{ref}"
        issuer = "https://token.actions.githubusercontent.com"
        uri, key = cls.import_(identity, issuer)

        return uri, key
