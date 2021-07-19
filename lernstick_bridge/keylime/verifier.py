'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''

import requests
from lernstick_bridge.schema.keylime import DeviceVerifierRequest
from lernstick_bridge.config import config, VERIFIER_URL

session = requests.Session()
session.cert = (config.verifier.tls_cert, config.verifier.tls_priv_key)
session.verify = False


def add_device(device_id: str, verifier_request: DeviceVerifierRequest):
    res = session.post(f"{VERIFIER_URL}/agents/{device_id}", data=verifier_request.json())
    return res.status_code == 200


def get_device(device_id: str):
    res = session.get(f"{VERIFIER_URL}/agents/{device_id}")
    return res.json()["results"]


def get_device_state(device_id: str):
    # TODO this will change when the tagging proposal is implemented
    device_data = get_device(device_id)
    return device_data["operational_state"]


def delete_device(device_id: str):
    res = session.delete(f"{VERIFIER_URL}/agents/{device_id}")
    # TODO block if 202 and wait for the device to actually disappear
    return res.status_code in [200, 202, 201]


def add_allowlist():
    pass


