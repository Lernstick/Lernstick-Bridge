'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''

import base64
import json
from typing import Optional

from pydantic import BaseModel, PrivateAttr

from lernstick_bridge import config
from lernstick_bridge.db import crud
from lernstick_bridge.keylime import registrar, ek, agent, verifier, util
from lernstick_bridge.schema.bridge import Device, Token
from lernstick_bridge.schema.keylime import AgentRegistrar, DeviceVerifierRequest


class Agent(BaseModel):
    """
    Agent class for doing common interactions with the agent during activation.
    In relaxed mode device might be None.
    """
    strict: bool
    id: str
    device: Optional[Device]
    registrar_data: AgentRegistrar

    _token: Optional[Token] = PrivateAttr(None)
    _pubkey: Optional[str] = PrivateAttr(None)  # TODO cache the public key instead of requesting it again

    def __init__(self, device_id: str, strict=True):
        registrar_data = registrar.get_device(device_id)
        device = None
        if registrar_data is None:
            raise ValueError("Didn't found device in registrar")

        if strict:
            device = crud.get_device(device_id)
            if device is None:
                raise ValueError("Didn't found device in database")

        super().__init__(id=device_id, strict=strict, device=device, registrar_data=registrar_data)

    def valid_ek(self):
        """
        Validates the EK against the database in strict mode and otherwise against the certificate store.
        For validating the AIK call do_quote.
        """
        if self.strict:
            return self.device.ek_cert == self.registrar_data.ekcert

        return ek.validate_ek(self.registrar_data.ekcert.encode(), config.cert_store)

    def do_qoute(self):
        valid, pubkey = agent.do_quote(self.get_url(), self.registrar_data.aik_tpm)
        if valid:
            self._pubkey = pubkey
        return valid

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
            tpm_policy=json.dumps(self._get_tpm_policy()),
            allowlist=json.dumps(self._get_ima_policy())
        )
        return verifier.add_device(self.id, request)

    def remove_from_verifier(self):
        return verifier.delete_device(self.id)

    def _get_tpm_policy(self):
        output = {}
        # if self.strict:
            # TODO add all always static pcrs
            # output["0"] = self.device.pcr_0  # Firmware PCR
        output["mask"] = util.generate_mask(output, measured_boot=True, ima=False)

        return output

    def _get_ima_policy(self):
        """
        :return: IMA include and exclude lists
        """
        allowlist = {}
        excludelist = {}
        return {'allowlist': allowlist, 'excludelist': excludelist}