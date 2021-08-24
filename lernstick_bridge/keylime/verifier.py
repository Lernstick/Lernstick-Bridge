'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
import time

import requests
from lernstick_bridge.schema.keylime import AgentVerifierRequest
from lernstick_bridge.config import config, VERIFIER_URL
from lernstick_bridge.bridge_logger import logger

session = requests.Session()
session.cert = (config.verifier.tls_cert, config.verifier.tls_priv_key)
session.verify = False


def add_agent(agent_id: str, verifier_request: AgentVerifierRequest):
    res = session.post(f"{VERIFIER_URL}/agents/{agent_id}", data=verifier_request.json())
    return res.status_code == 200


def get_agent(agent_id: str):
    res = session.get(f"{VERIFIER_URL}/agents/{agent_id}")
    if res.status_code != 200:
        return None
    return res.json()["results"]


def get_agent_state(agent_id: str):
    # TODO this will change when the tagging proposal is implemented
    agent_data = get_agent(agent_id)
    return agent_data["operational_state"]


def delete_agent(agent_id: str):
    res = session.delete(f"{VERIFIER_URL}/agents/{agent_id}")
    if res.status_code == 202:
        logger.info("agent will not be immediately deleted")
    return res.status_code in [200, 202, 201]


def add_allowlist():
    pass


