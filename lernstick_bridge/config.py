"""
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
"""
from lernstick_bridge.keylime import ek
from lernstick_bridge.schema.config import Config

config = Config()
cert_store = ek.create_ca_store(config.tpm_cert_store)

REGISTRAR_URL = f"{config.keylime_registrar}/{config.keylime_api_entrypoint}"
VERIFIER_URL = f"{config.keylime_verifier}/{config.keylime_api_entrypoint}"
