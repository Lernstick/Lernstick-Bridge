'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
import datetime
import time
from asyncio import ensure_future

from starlette.concurrency import run_in_threadpool

from lernstick_bridge.bridge.agent import Agent
from lernstick_bridge.config import config
from lernstick_bridge.db import crud
from lernstick_bridge.keylime import verifier, registrar


def activate_device(device_id: str):
    if config.mode == "strict":
        return _strict_activate_device(device_id)
    elif config.mode == "relaxed":
        return _relaxed_activate_device(device_id)
    return False


def deactivate_device(device_id: str):
    if config.mode == "strict":
        return _strict_deactivate_device(device_id)
    elif config.mode == "relaxed":
        return _relaxed_deactivate_device(device_id)
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
        agent = Agent(device_id, strict=True)
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

    agent.activate()

    return True

def _relaxed_activate_device(device_id: str):
    """
    Activates device in relaxed mode.
    :param device_id:
    :return:

    Steps:
        - Check if device is there
        - Remove timeout from attestation
    """
    return crud.set_timeout_active_device(device_id, None)


def _strict_deactivate_device(device_id: str):
    if not crud.get_active_device(device_id):
        return False  # TODO should be a not found

    verifier.delete_device(device_id)
    crud.delete_active_device(device_id)
    return True


def _relaxed_deactivate_device(device_id: str):
    if not crud.get_active_device(device_id):
        return False  # TODO should be a not found

    verifier.delete_device(device_id)
    crud.delete_active_device(device_id)
    return True


def _relaxed_handle_devices():
    active_devices = crud.get_active_devices()
    active_ids = set()
    for device in active_devices:
        active_ids.add(device.device_id)
    registrar_devices = registrar.get_devices()
    for device_id in registrar_devices:
        if device_id in active_ids:
            continue
        try:
            agent = Agent(device_id, strict=False)
        except ValueError:
            continue

        agent.valid_ek()
        agent.do_qoute()
        agent.deploy_token()
        agent.add_to_verifier()
        timeout = datetime.datetime.now() + config.tenant.relaxed_timeout
        agent.activate(timeout=timeout)

    for device in active_devices:
        if device.timeout is None:
            continue
        if datetime.datetime.now() < device.timeout:
            continue
        _relaxed_deactivate_device(device.device_id)
        # We will delete also the device from the registrar. It has to be restarted in order to be added again.
        registrar.delete_device(device.device_id)

    time.sleep(10)


async def relaxed_loop():
    """Initial PoC for an loop that automatically adds and removes devices"""
    async def loop():
        while True:
            await run_in_threadpool(_relaxed_handle_devices)

    ensure_future(loop())
