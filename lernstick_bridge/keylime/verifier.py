'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
import requests

from typing import Any, Dict, Optional

from lernstick_bridge.schema.keylime import AgentVerifierRequest
from lernstick_bridge.config import config, VERIFIER_URL
from lernstick_bridge.bridge_logger import logger
from lernstick_bridge.utils import RetrySession

session = RetrySession()
session.cert = (config.verifier.tls_cert, config.verifier.tls_priv_key)
session.verify = False


def add_agent(agent_id: str, verifier_request: AgentVerifierRequest) -> bool:
    try:
        res = session.post(f"{VERIFIER_URL}/agents/{agent_id}", data=verifier_request.json())
        return res.status_code == 200
    except requests.exceptions.RequestException as e:
        logger.error(f"Couldn't add agent from verifier: {e}")
        return False


def get_agent(agent_id: str) -> Optional[Dict[Any,Any]]:
    try:
        res = session.get(f"{VERIFIER_URL}/agents/{agent_id}")
        data = res.json()
        if "results" not in data:
            logger.error("Couldn't get agent form verifier. results are missing.")
            return None
        return data["results"]
    except requests.exceptions.RequestException as e:
        logger.error(f"Couldn't get agent form verifier: {e}")
        return None


def get_agent_state(agent_id: str) -> Any:
    # TODO this will change when the tagging proposal is implemented
    agent_data = get_agent(agent_id)
    assert agent_data is not None
    return agent_data["operational_state"]


def delete_agent(agent_id: str) -> bool:
    try:
        res = session.delete(f"{VERIFIER_URL}/agents/{agent_id}")
        if res.status_code == 202:
            logger.info(f"Agent {agent_id} will not be immediately deleted from verifier.")
        return res.status_code in [200, 202, 201]
    except requests.exceptions.RequestException as e:
        logger.error(f"Couldn't delete agent {agent_id} from verifier: {e}")
        return False
