"""
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
"""

from typing import List, Optional

import requests

from lernstick_bridge.bridge_logger import logger
from lernstick_bridge.config import REGISTRAR_URL, config
from lernstick_bridge.schema.keylime import AgentRegistrar
from lernstick_bridge.utils import RetrySession

session = RetrySession(
    cert=(config.registrar.tls_cert, config.registrar.tls_priv_key),
    verify=config.registrar.ca_cert,
    ignore_hostname=True,
)


def get_agent(agent_id: str) -> Optional[AgentRegistrar]:
    """
    Gets an agent from the Keylime Registrar.

    :param agent_id: the agent UUID
    :return: the Agent or None if not found.
    """
    try:
        res = session.get(f"{REGISTRAR_URL}/agents/{agent_id}")
        data = res.json()
        if "results" not in data:
            logger.error("Couldn't get agent from registrar: results are missing in the response")
            return None
        return AgentRegistrar(**data["results"])
    except requests.exceptions.RequestException as e:
        logger.error(f"Couldn't get agent from registrar: {e}")
        return None


def get_agents() -> List[str]:
    """
    Get all agent UUIDs currently found in the Keylime Registrar.

    :return: list of agent UUIDs
    """
    try:
        res = session.get(f"{REGISTRAR_URL}/agents")
        data = res.json()
        if "results" not in data or "uuids" not in data["results"]:
            logger.error("Couldn't get agents from registrar returning empty list!")
            return []
        return data["results"]["uuids"]
    except requests.exceptions.RequestException as e:
        logger.error(f"Couldn't get agents from registrar returning empty list: {e}")
        return []


def delete_agent(agent_id: str) -> bool:
    """
    Removes an agent from the Keylime Registrar.

    :param agent_id: the agent UUID
    :return: True if successful
    """
    try:
        res = session.delete(f"{REGISTRAR_URL}/agents/{agent_id}")
        return res.status_code == 200
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to delete agent {agent_id} from registrar: {e}")
        return False
