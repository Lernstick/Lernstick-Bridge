'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''

import base64
import copy
import datetime
import json
from typing import Any, Dict, Optional, Tuple

from pydantic import BaseModel, PrivateAttr, root_validator

from lernstick_bridge import config
from lernstick_bridge.bridge_logger import logger
from lernstick_bridge.db import crud
from lernstick_bridge.keylime import agent, ek, registrar, util, verifier
from lernstick_bridge.schema.bridge import Agent, Token
from lernstick_bridge.schema.keylime import AgentRegistrar, AgentVerifierRequest


class AgentBridge(BaseModel):
    """
    Agent class for doing common interactions with the agent during activation.
    In relaxed mode agent might be None.
    """
    strict: bool
    agent_id: str
    agent: Optional[Agent]
    registrar_data: Optional[AgentRegistrar]

    _token: Optional[Token] = PrivateAttr(None)
    _pubkey: Optional[str] = PrivateAttr(None)  # Caching the pubkey to reduce requests to the agent

    @root_validator(pre=True)
    def get_agent(cls, values: Any) -> Any:  # pylint: disable=no-self-argument
        """
        Initializes registrar_data and bridge_agent automatically using pydandic validators.
        This is done for better type checking.
        """
        is_strict = values.get("strict")
        agent_id = values.get("agent_id")
        assert agent_id and (is_strict is not None),  "Agent id and mode need to be added"

        registrar_data = registrar.get_agent(agent_id)
        assert registrar_data, "Didn't found agent in registrar"

        bridge_agent = None
        if is_strict:
            bridge_agent = crud.get_agent(agent_id)
            assert bridge_agent, "Didn't found agent in database"
        values["registrar_data"] = registrar_data
        values["agent"] = bridge_agent
        return values

    def valid_ek(self) -> bool:
        """
        Validates the EK against the database in strict mode and otherwise against the certificate store.
        For validating the AK call do_quote.

        :return: True if the EK is valid
        """
        assert self.registrar_data is not None
        if self.strict:
            if self.agent is None:
                return False
            return self.agent.ek_cert == self.registrar_data.ekcert

        return ek.validate_ek(base64.b64decode(self.registrar_data.ekcert), config.cert_store)

    def do_quote(self) -> bool:
        """
        Does an identity quote and validates it against the AK.
        As a side effect it also caches the transport key.

        :return: True if quote is valid
        """
        assert self.registrar_data
        valid, pubkey = agent.do_quote(self.get_url(), self.registrar_data.aik_tpm, self.registrar_data.mtls_cert)
        if valid:
            self._pubkey = util.str_to_rsapubkey(pubkey)
        return valid

    def get_url(self) -> str:
        """
        Construct agent contact url from IP and port.

        :return: string that is the agent contact url
        """
        assert self.registrar_data
        return f"https://{self.registrar_data.ip}:{self.registrar_data.port}/{config.config.keylime_api_entrypoint}"

    def deploy_token(self) -> Optional[Token]:
        """
        Deploys the verification token onto the agent

        :return: The deployed token or None
        """
        if not self._token:
            token = Token(agent_id=self.agent_id)
            payload = token.to_payload()
            assert self.registrar_data
            if agent.post_payload_u(self.agent_id, self.get_url(), payload, self.registrar_data.mtls_cert, self._pubkey):
                self._token = token
        return self._token

    def add_to_verifier(self) -> bool:
        """
        Adds the agent to the verifier.

        :return: True if successful
        """
        if not self._token:
            raise ValueError("Token must be deployed before adding agent to the verifier")

        assert self.registrar_data
        # Make sure that the verifier.conf includes the correct module to parse the mb_refstate
        mb_refstate, runtime_policy = self._get_keylime_policy()
        request = AgentVerifierRequest(
            v=base64.b64encode(self._token.to_payload().v).decode("utf-8"),
            cloudagent_ip=self.registrar_data.ip,
            cloudagent_port=self.registrar_data.port,
            tpm_policy=json.dumps(self._get_tpm_policy()),
            runtime_policy=json.dumps(runtime_policy),
            mb_refstate=json.dumps(mb_refstate),
            ak_tpm=self.registrar_data.aik_tpm,
            mtls_cert=self.registrar_data.mtls_cert,
        )
        return verifier.add_agent(self.agent_id, request)

    def remove_from_verifier(self) -> bool:
        """
        Removes agent from the verifier.

        :return: True if successful
        """
        return verifier.delete_agent(self.agent_id)

    def activate(self, timeout: datetime.datetime = None) -> bool:
        """
        Mark the agent as active in the bridge.

        :param timeout: (Optional) If set the agent gets removed in relaxed mode if the timeout is exceeded.
        :return: True if activation was successful
        """
        if self._token is None:
            return False

        crud.add_active_agent(self.agent_id, self._token.token, timeout)
        return True

    def _get_tpm_policy(self) -> Dict[str, Any]:
        """
        Construct tpm policy with the correct mask.

        :return: tpm_policy dict for the verifier
        """
        output: Dict[str, Any] = {}
        used_pcrs = None
        keylime_policy = crud.get_active_keylime_policy()
        use_ima_pcr = keylime_policy is not None and keylime_policy.runtime_policy is not None
        if self.strict:
            assert self.agent
            # Note: Keylime only uses the static policy if no measured boot policy is specified for those PCRs
            output["0"] = self.agent.pcr_0  # Firmware PCR
            used_pcrs = [0]

        output["mask"] = util.generate_mask(used_pcrs, measured_boot=True, ima=use_ima_pcr)
        return output

    def _get_keylime_policy(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Generates IMA and reference boot state for the agent based on the policy currently configured.
        Defaults to an empty policy if no policy is active.

        :return: Keylime configuration
        """
        keylime_policy = crud.get_active_keylime_policy()

        if keylime_policy is None:
            logger.warning("No keylime policy is specified. Using empty policy!")
            return {}, {}

        mb_refstate: Dict[str, Any] = copy.deepcopy(keylime_policy.mb_refstate)
        if mb_refstate and self.agent:
            assert self.strict
            mb_refstate["crtm"] = self.agent.pcr_0

        return mb_refstate, keylime_policy.runtime_policy
