'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''

#  Objects needed to interact with the Keylime API

import json
from pydantic import BaseModel
from typing import Dict, List, Optional
from ipaddress import IPv4Address

from lernstick_bridge.bridge.config import config


class AgentRegistrar(BaseModel):
    """
    Agent response object from the registrar.
    """
    aik_tpm: str
    ek_tpm: str
    ekcert: str
    ip: IPv4Address
    port: int

    def get_url(self):
        return f"http://{self.ip}:{self.port}/{config.keylime_api_entrypoint}"


class DeviceVerifierRequest(BaseModel):
    """
    Request for the verifier with defaults set from the configuration.
    """
    v: str
    cloudagent_ip: IPv4Address
    cloudagent_port: int
    tpm_policy: str
    vtpm_policy: str
    metadata: str = json.dumps({})
    allowlist: str = json.dumps({})
    mb_refstate: str = None
    ima_sign_verification_keys: str = json.dumps([])
    revocation_key: str = ""
    accept_tpm_hash_algs: str = json.dumps(config.tenant.accept_tpm_hash_algs)
    accept_tpm_encryption_algs: str = json.dumps(config.tenant.accept_tpm_encryption_algs)
    accept_tpm_signing_algs: str = json.dumps(config.tenant.accept_tpm_signing_algs)


class Payload(BaseModel):
    k: bytes
    u: bytes
    v: bytes
    encrypted_data: str
    plain_data: str

