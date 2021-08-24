'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''

import requests
import urllib3

from lernstick_bridge.schema.keylime import AgentRegistrar
from lernstick_bridge.config import config, REGISTRAR_URL

# TODO don't disable SSL Cert validation
session = requests.Session()
session.cert = (config.registrar.tls_cert, config.registrar.tls_priv_key)
session.verify = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_agent(agent_id: str):
    res = session.get(f"{REGISTRAR_URL}/agents/{agent_id}")
    if res.status_code != 200:
        return None
    data = res.json()
    if "results" not in data:
        return None
    return AgentRegistrar(**data["results"])


def get_agents():
    res = session.get(f"{REGISTRAR_URL}/agents")
    if res.status_code != 200:
        return None
    return res.json()["results"]["uuids"]


def delete_agent(agent_id: str):
    res = session.delete(f"{REGISTRAR_URL}/agents/{agent_id}")
    return res.status_code == 200
