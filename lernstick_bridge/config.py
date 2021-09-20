'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
import json

from lernstick_bridge.keylime import ek
from lernstick_bridge.schema.config import Config

config = Config()
cert_store = ek.create_ca_store(config.tpm_cert_store)

REGISTRAR_URL = f"{config.keylime_registrar}/{config.keylime_api_entrypoint}"
VERIFIER_URL = f"{config.keylime_verifier}/{config.keylime_api_entrypoint}"

MB_POLICY = {}
if config.measured_boot_policy is not None:
    with open(config.measured_boot_policy, encoding="utf-8") as mb_file:
        MB_POLICY = json.load(mb_file)

IMA_POLICY = None
if config.ima_policy is not None:
    with open(config.ima_policy, encoding="utf-8") as ima_file:
        IMA_POLICY = json.load(ima_file)
