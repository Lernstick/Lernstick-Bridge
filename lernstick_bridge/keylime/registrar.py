'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''

import requests
from lernstick_bridge.schema.keylime import AgentRegistrar
from lernstick_bridge.bridge.config import config, REGISTRAR_URL

# TODO don't disable SSL Cert validation
session = requests.Session()
session.cert = (config.registrar.tls_cert, config.registrar.tls_priv_key)
session.verify = False


def get_device(device_id: str):
    res = session.get(f"{REGISTRAR_URL}/agents/{device_id}")
    if res.status_code != 200:
        return None
    data = res.json()
    if "results" not in data:
        return None
    return AgentRegistrar(**data["results"])


def delete_device(device_id: str):
    res = session.delete(f"{REGISTRAR_URL}/agents/{device_id}")
    return res.status_code == 200
