import argparse
import logging
import os
import sys
import traceback
from hashlib import sha256
from pathlib import Path

import urllib3
import requests

from tuf.api.exceptions import DownloadError, RepositoryError
from tuf.ngclient import Updater, UpdaterConfig
from securesystemslib.signer import KEY_FOR_TYPE_AND_SCHEME, SigstoreKey
KEY_FOR_TYPE_AND_SCHEME.update({("sigstore-oidc", "Fulcio"): SigstoreKey,})

def get_policy_from_tuf(target = "policy_a1.json"):

    base_url = "http://diverify_web:8083"
    DOWNLOAD_DIR = "/home"

    metadata_dir = build_metadata_dir(base_url)

    if not os.path.isfile(f"{metadata_dir}/root.json"):
        print(
            "Trusted local root not found. Use 'tofu' command to "
            "Trust-On-First-Use or copy trusted root metadata to "
            f"{metadata_dir}/root.json"
        )
        return False

    print(f"Using trusted root in {metadata_dir}")

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
            return True

        path = updater.find_cached_target(info)
        if path:
            print(f"Target is available in {path}")
            return True

        path = updater.download_target(info)
        print(f"Target downloaded and available in {path}")

    except (OSError, RepositoryError, DownloadError) as e:
        print(f"Failed to download target {target}: {e}")
        if logging.root.level < logging.ERROR:
            traceback.print_exc()
        return False
    return True
    

def build_metadata_dir(base_url: str) -> str:
    """build a unique and reproducible directory name for the repository url"""
    name = sha256(base_url.encode()).hexdigest()[:8]
    # TODO: Make this not windows hostile?
    return "./tuf-metadata"

if __name__ == "__main__":
    get_policy_from_tuf()
