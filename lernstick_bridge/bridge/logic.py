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


def activate_device(device_id: str) -> bool:
    if config.mode == "strict":
        return _strict_activate_device(device_id)
    elif config.mode == "relaxed":
        return _relaxed_activate_device(device_id)
    return False


def deactivate_device(device_id: str) -> bool:
    if config.mode == "strict":
        return _strict_deactivate_device(device_id)
    elif config.mode == "relaxed":
        return _relaxed_deactivate_device(device_id)
    return False


def _strict_activate_device(device_id: str) -> bool :
    """
    Try to add a device for remote attestation
    :param device_id:
    :return:

    """
    try:
        agent = Agent(device_id, strict=True)
    except ValueError:
        return False

    if not agent.valid_ek():
        return False

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


def _relaxed_handle_agents():
    """
     - Get's the agents from the registrar and tries to activate them.
     - Checks if an active agent has reached its timeout and removes it.
     Note: It also removes it from the registrar currently. The agent must register itself again if it should be activated.
    :return: None
    """
    active_devices = crud.get_active_devices()
    active_ids = set()
    for device in active_devices:
        active_ids.add(device.device_id)
    registrar_devices = registrar.get_devices()
    # TODO This should be done in parallel and sequential so that a single device can block this loop
    for device_id in registrar_devices:
        if device_id in active_ids:
            continue
        try:
            agent = Agent(device_id, strict=False)
        except ValueError:
            continue

        if not agent.valid_ek():
            continue

        if not agent.do_qoute():
            continue

        if not agent.deploy_token():
            continue
        if not agent.add_to_verifier():
            continue

        timeout = datetime.datetime.now() + config.tenant.relaxed_timeout
        if not agent.activate(timeout=timeout):
            continue

    for device in active_devices:
        if device.timeout is None:
            continue
        if datetime.datetime.now() < device.timeout:
            continue
        _relaxed_deactivate_device(device.device_id)
        # We will delete also the device from the registrar. It has to be restarted in order to be added again.
        registrar.delete_device(device.device_id)

    time.sleep(10) # TODO make this configurable


async def relaxed_loop():
    """Initial PoC for an loop that automatically adds and removes agents"""
    async def loop():
        while True:
            await run_in_threadpool(_relaxed_handle_agents)

    ensure_future(loop())
