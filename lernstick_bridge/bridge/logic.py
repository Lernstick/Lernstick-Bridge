'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''

import lernstick_bridge.bridge.agent
from lernstick_bridge.config import config
from lernstick_bridge.db import crud
from lernstick_bridge.keylime import verifier


def activate_device(device_id: str):
    if config.mode == "strict":
        return _strict_activate_device(device_id)
    elif config.mode == "relaxed":
        return _relaxed_activate_device(device_id)
    return False


def deactivate_device(device_id: str):
    if config.mode == "strict":
        return _strict_deactivate_device(device_id)
    return False


def _strict_activate_device(device_id: str):
    """
    Try to add a device for remote attestation
    :param device_id:
    :return:

    Steps
        - Get data from DB and registrar
        - Check if its actually there
        - validate if the EK is actually the expected one
        - Do a identity quote on the agent to retrieve public key
        - Validate that quote to see if it matches the aik in the registrar
        - Deploy U key and token (payload) to the agent
        - Add token to database
        - Add agent to the verifier
        - (Optional check if the agent has got the V also key)
        - Mark the device as active in the database
    """
    try:
        agent = lernstick_bridge.bridge.agent.Agent(device_id, strict=True)
    except ValueError:
        return None

    if not agent.valid_ek():
        return None

    if not agent.do_qoute():
        return None

    token = agent.deploy_token()
    if token is None:
        return None

    if not agent.add_to_verifier():
        agent.remove_from_verifier()
        return None

    crud.add_active_device(agent.id, token.token)

    return True

def _relaxed_activate_device(device_id: str):
    """
    Activates device in relaxed mode.
    :param device_id:
    :return:

    Steps:
        - Check if device is there
        - If not re add it to attestation
        - Remove timeout from attestation
    """
    pass


def _strict_deactivate_device(device_id: str):
    if not crud.get_active_device(device_id):
        return False  # TODO should be a not found

    verifier.delete_device(device_id)
    crud.delete_active_device(device_id)
    return True

