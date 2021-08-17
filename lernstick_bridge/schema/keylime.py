'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''

#  Objects needed to interact with the Keylime API

import json
from pydantic import BaseModel, Json
from typing import Union
from ipaddress import IPv4Address

from lernstick_bridge.config import config


class AgentRegistrar(BaseModel):
    """
    Agent response object from the registrar.
    """
    aik_tpm: str
    ek_tpm: str
    ekcert: str
    ip: IPv4Address
    port: int


class DeviceVerifierRequest(BaseModel):
    """
    Request for the verifier with defaults set from the configuration.
    """
    v: str
    cloudagent_ip: IPv4Address
    cloudagent_port: int
    tpm_policy: str
    vtpm_policy: str = "{\"mask\": \"0x408000\"}"  # We don't use vtpms so just always add an empty mask
    metadata: str = json.dumps({})
    allowlist: str = json.dumps({})
    mb_refstate: str = None
    ima_sign_verification_keys: str = json.dumps([])
    revocation_key: str = ""  # We don't use the revocation feature, so we specify always an empty string
    accept_tpm_hash_algs: str = json.dumps(config.tenant.accept_tpm_hash_algs)
    accept_tpm_encryption_algs: str = json.dumps(config.tenant.accept_tpm_encryption_algs)
    accept_tpm_signing_algs: str = json.dumps(config.tenant.accept_tpm_signing_algs)


class RevocationMsg(BaseModel):
    type: str
    ip: IPv4Address
    agent_id: str
    port: int
    tpm_policy: str
    meta_data: str
    event_time: str


class RevocationResp(BaseModel):
    msg: Union[Json[RevocationMsg], RevocationMsg]


class Payload(BaseModel):
    """
    Abstraction of the Payload that can be deployed to the agent.
    """
    k: bytes
    u: bytes
    v: bytes
    encrypted_data: str
    plain_data: str

