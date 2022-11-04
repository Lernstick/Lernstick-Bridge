'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
# pylint: disable=too-few-public-methods
#  Objects needed to interact with the Keylime API

import json
from ipaddress import IPv4Address
from typing import Optional, Union

from pydantic import BaseModel, Json

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
    mtls_cert: str


class AgentVerifierRequest(BaseModel):
    """
    Request for the verifier with defaults set from the configuration.
    """
    v: str
    cloudagent_ip: IPv4Address
    cloudagent_port: int
    tpm_policy: str
    metadata: str = json.dumps({})
    allowlist: str = json.dumps({})
    ima_policy_bundle: str = json.dumps({})
    mb_refstate: Optional[str] = None
    ima_sign_verification_keys: str = json.dumps([])
    revocation_key: str = ""  # We don't use the revocation feature, so we specify always an empty string
    accept_tpm_hash_algs: str = json.dumps(config.tenant.accept_tpm_hash_algs)
    accept_tpm_encryption_algs: str = json.dumps(config.tenant.accept_tpm_encryption_algs)
    accept_tpm_signing_algs: str = json.dumps(config.tenant.accept_tpm_signing_algs)
    # We only support agents with the same API version as the server components
    supported_version: str = config.keylime_api_entrypoint[1:]
    ak_tpm: str
    mtls_cert: str


class RevocationMsg(BaseModel):
    """
    Revocation message data send by Keylime on agent failure.
    """
    type: str
    ip: IPv4Address
    agent_id: str
    port: str
    tpm_policy: str
    meta_data: str
    event_time: str
    event_id: Optional[str]
    severity_label: Optional[str]
    context: Optional[Json]


class RevocationResp(BaseModel):
    """
    Revocation message send by Keylime on agent failure with an optional signature.
    We do not use the signature feature because we can trust the Keylime Verifier directly.
    """
    msg: Union[Json[RevocationMsg], RevocationMsg]  # type: ignore # pylint: disable=E1136
    signature: Optional[str]


class Payload(BaseModel):
    """
    Abstraction of the Payload that can be deployed to the agent.
    """
    k: bytes
    u: bytes
    v: bytes
    encrypted_data: str
    plain_data: str
