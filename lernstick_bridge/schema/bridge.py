'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
import base64
import json

from pydantic import BaseModel, PrivateAttr
from typing import Optional
from lernstick_bridge.schema.keylime import AgentRegistrar, Payload, DeviceVerifierRequest
from lernstick_bridge.keylime import keylime_crypto, registrar, ek, agent, verifier
from lernstick_bridge.bridge import config
from lernstick_bridge.db import crud

class Device(BaseModel):
    """Device model that is stored in the database"""
    id: str  # Normally the hash of the ek_cert
    ek_cert: str  # The hardware vendor cert for the TPM
    # BIOS & UEFI related PCRs should be in general stable
    # Bootloader and Mok entries are getting validated via Keylime policies
    pcr_0: str
    pcr_1: str
    pcr_2: str
    pcr_3: str
    pcr_4: str
    pcr_5: str
    pcr_6: str
    pcr_7: str
    event_log_reference: str  # Reference of the boot event log. Used for improving the measured boot policies

    class Config:
        orm_mode = True


class Token(BaseModel):
    """Verification token"""
    device_id: str
    token: str

    _payload: Optional[Payload] = PrivateAttr(None)

    def __init__(self, device_id: str):
        token = keylime_crypto.get_random_nonce(128)
        super().__init__(device_id=device_id, token=token)

    def to_payload(self):
        if not self._payload:
            self._payload = keylime_crypto.generate_payload(self.token)
        return self._payload

    class Config:
        orm_mode = True


class Agent(BaseModel):
    """
    Agent object to interact with.
    device might be None if Agent is not in strict mode
    """
    strict: bool
    id: str
    device: Optional[Device]
    registrar_data: AgentRegistrar

    _token: Optional[Token] = PrivateAttr(None)

    def __init__(self, device_id: str, strict=True):
        registrar_data = registrar.get_device(device_id)
        device = None
        if registrar_data is None:
            raise ValueError("Didn't found device in registrar")

        if strict:
            device = crud.get_device(config.get_db(), device_id)
            if device is None:
                raise ValueError("Didn't found device in database")

        super().__init__(id=device_id, strict=strict, device=device, registrar_data=registrar_data)

    def valid_ek(self):
        """
        Validates the EK against the database in strict mode and otherwise against the certificate store.
        For validating the AIK call do_quote
        """
        if self.strict:
            return self.device.ek_cert == self.registrar_data.ekcert

        return ek.validate_ek(self.registrar_data.ekcert.encode(), config.cert_store)

    def do_qoute(self):
        return agent.do_quote(self.get_url(), self.registrar_data.aik_tpm)

    def get_url(self):
        return f"http://{self.registrar_data.ip}:{self.registrar_data.port}"

    def deploy_token(self):
        if not self._token:
            token = Token(self.id)
            payload = token.to_payload()
            if agent.post_payload_u(self.id, self.get_url(), payload):
                self._token = token
        return self._token

    def add_to_verifier(self):
        if not self._token:
            ValueError("Token must be deployed before adding device to the verifier")

        request = DeviceVerifierRequest(
            v=base64.b64encode(self._token.to_payload().v).decode("utf-8"),
            cloudagent_ip=self.registrar_data.ip,
            cloudagent_port=self.registrar_data.port,
            tpm_policy="{\"22\": [\"0000000000000000000000000000000000000001\", \"0000000000000000000000000000000000000000000000000000000000000001\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001\", \"ffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"], \"15\": [\"0000000000000000000000000000000000000000\", \"0000000000000000000000000000000000000000000000000000000000000000\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"], \"mask\": \"0x408000\"}",
            vtpm_policy="{\"23\": [\"ffffffffffffffffffffffffffffffffffffffff\", \"0000000000000000000000000000000000000000\"], \"15\": [\"0000000000000000000000000000000000000000\"], \"mask\": \"0x808000\"}",
            allowlist=json.dumps({})
        )
        verifier.add_device(self.id, request)
