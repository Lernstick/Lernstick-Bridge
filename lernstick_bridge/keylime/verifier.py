'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''

import requests
from lernstick_bridge.schema.keylime import Payload, DeviceVerifierRequest
from lernstick_bridge.keylime import registrar
from lernstick_bridge.bridge.config import config, VERIFIER_URL

session = requests.Session()
session.cert = (config.verifier.tls_cert, config.verifier.tls_priv_key)
session.verify = False


def add_device(device_id: str, verifier_request: DeviceVerifierRequest):
    res = session.request("POST", f"{VERIFIER_URL}/agents/{device_id}", data=verifier_request.json())

def get_device(device_id: str):
    res = session.request("GET", f"{VERIFIER_URL}/agents/{device_id}")
    return res.json()


def delete_device(device_id: str):
    pass


def get_devices():
    pass


def stop_device(device_id: str):
    pass


def reactivate_device(device_id: str):
    pass


def add_allowlist():
    pass


