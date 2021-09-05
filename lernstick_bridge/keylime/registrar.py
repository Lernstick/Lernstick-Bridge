'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''

from typing import List, Optional

import requests
import urllib3

from lernstick_bridge.bridge_logger import logger
from lernstick_bridge.config import REGISTRAR_URL, config
from lernstick_bridge.schema.keylime import AgentRegistrar
from lernstick_bridge.utils import RetrySession

# TODO don't disable SSL Cert validation
session = RetrySession()
session.cert = (config.registrar.tls_cert, config.registrar.tls_priv_key)
session.verify = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_agent(agent_id: str) -> Optional[AgentRegistrar]:
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
    try:
        res = session.delete(f"{REGISTRAR_URL}/agents/{agent_id}")
        return res.status_code == 200
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to delete agent {agent_id} from registrar: {e}")
        return False
