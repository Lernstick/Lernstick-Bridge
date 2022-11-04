'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
from typing import Any, Dict, Optional

import requests

from lernstick_bridge.bridge_logger import logger
from lernstick_bridge.config import VERIFIER_URL, config
from lernstick_bridge.schema.keylime import AgentVerifierRequest
from lernstick_bridge.utils import RetrySession

session = RetrySession(cert=(config.verifier.tls_cert, config.verifier.tls_priv_key),
                       verify=config.verifier.ca_cert,
                       ignore_hostname=True)


def add_agent(agent_id: str, verifier_request: AgentVerifierRequest) -> bool:
    """
    Add an agent to the Keylime Verifier.

    :param agent_id: the agent UUID
    :param verifier_request: the necessary agent data.
    :return: True if successful
    """
    try:
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        res = session.post(f"{VERIFIER_URL}/agents/{agent_id}", data=verifier_request.json(), headers=headers)
        return res.status_code == 200
    except requests.exceptions.RequestException as e:
        logger.error(f"Couldn't add agent from verifier: {e}")
        return False


def get_agent(agent_id: str) -> Optional[Dict[Any, Any]]:
    """
    Get agent data from the verifier.

    :param agent_id: the agent UUID
    :return: a dict of the the agent data or None with something went wrong.
    """
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
    """
    Get the state of the agent from the Keylime Verifier.

    :param agent_id: the agent UUID
    :return: the state
    """
    # TODO this will change when the tagging proposal is implemented
    agent_data = get_agent(agent_id)
    assert agent_data is not None
    return agent_data["operational_state"]


def delete_agent(agent_id: str) -> bool:
    """
    Remove an agent from the Keylime Verifier.
    Note that it might take a while before the agent is actually removed from the Verifier.

    :param agent_id: the agent UUID
    :return: True if successful
    """
    try:
        res = session.delete(f"{VERIFIER_URL}/agents/{agent_id}")
        if res.status_code == 202:
            logger.info(f"Agent {agent_id} will not be immediately deleted from verifier.")
        return res.status_code in [200, 202, 201]
    except requests.exceptions.RequestException as e:
        logger.error(f"Couldn't delete agent {agent_id} from verifier: {e}")
        return False
