'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''

from lernstick_bridge.schema import bridge


def strict_activate_device(device_id: str):
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
        agent = bridge.Agent(device_id, strict=True)
    except ValueError:
        return None

    if not agent.valid_ek():
        return None

    if not agent.do_qoute():
        return None

    return True
