'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
import datetime
import time
from asyncio import ensure_future

import requests
from starlette.concurrency import run_in_threadpool

from lernstick_bridge.bridge.agent import Agent
from lernstick_bridge.config import config
from lernstick_bridge.db import crud
from lernstick_bridge.keylime import verifier, registrar
from lernstick_bridge.bridge_logger import logger
from lernstick_bridge.schema.keylime import RevocationMsg
from lernstick_bridge.schema.bridge import RevocationMessage


def activate_device(device_id: str) -> bool:
    if config.mode == "strict":
        return _strict_activate_device(device_id)
    elif config.mode == "relaxed":
        return _relaxed_activate_device(device_id)
    logger.error(f"Unknown mode {config.mode}. Cannot activate device {device_id}!")
    return False


def deactivate_device(device_id: str) -> bool:
    if config.mode == "strict":
        return _strict_deactivate_device(device_id)
    elif config.mode == "relaxed":
        return _relaxed_deactivate_device(device_id)
    logger.error(f"Unknown mode {config.mode}. Cannot deactivate device {device_id}!")
    return False


def _strict_activate_device(device_id: str) -> bool :
    """
    Try to add a device for remote attestation
    :param device_id:
    :return:

    """
    try:
        agent = Agent(device_id, strict=True)
    except ValueError as e:
        logger.error(f"Was not able to collect agent data for id: {device_id}! {e}")
        return False

    if not agent.valid_ek():
        logger.error(f"EK for agent {device_id} was invalid!")
        return False

    if not agent.do_qoute():
        logger.error(f"Quote form agent {device_id} was invalid!")
        return False

    token = agent.deploy_token()
    if token is None:
        logger.error(f"Token could not be deployed on agent {device_id}")
        return False
    logger.debug(f"Deployed token: {token}")

    if not agent.add_to_verifier():
        logger.error(f"Agent {device_id} could not be added to verifier")
        agent.remove_from_verifier()
        return False

    if not agent.activate():
        logger.error(f"Couldn't activate agent {device_id}")
        agent.remove_from_verifier()
        return False

    logger.info(f"Successfully activated agent: {device_id}")
    return True


def _relaxed_activate_device(device_id: str) -> bool:
    """
    Activates device in relaxed mode.
    :param device_id: Device ID of agent to activate
    :return: True if successful

    """
    if crud.set_timeout_active_device(device_id, None):
        logger.info(f"Removed timeout from device {device_id}")
        return True

    return False


def _strict_deactivate_device(device_id: str):
    """

    :param device_id:
    :return:
    """
    if not crud.get_active_device(device_id):
        logger.error(f"Device {device_id} is not active so it cannot be deactivated!")
        return False  # TODO should be a not found

    verifier.delete_device(device_id)
    crud.delete_active_device(device_id)
    logger.error(f"Device {device_id} was deactivated.")
    return True


def _relaxed_deactivate_device(device_id: str):
    if not crud.get_active_device(device_id):
        return False  # TODO should be a not found

    verifier.delete_device(device_id)
    crud.delete_active_device(device_id)
    # We will delete also the device from the registrar. It has to be restarted in order to be added again.
    registrar.delete_device(device_id)
    logger.info(f"Deactivated device: {device_id}")
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
            logger.error(f"Was not able to collect agent data for id: {device_id}! {e}")
            continue

        if not agent.valid_ek() and config.validate_ek_registration:
            logger.error(f"EK for {device_id} couldn't be validated!")
            continue

        if not agent.do_qoute():
            logger.error(f"Quote of {device_id} was invalid!")
            continue

        if not agent.deploy_token():
            logger.error(f"Token couldn't be deployed on {device_id}!")
            continue
        if not agent.add_to_verifier():
            logger.error(f"Couldn't add agent for device {device_id} to verifier!")
            continue

        timeout = datetime.datetime.now() + config.tenant.relaxed_timeout
        if not agent.activate(timeout=timeout):
            continue
        logger.info(f"Successfully activated device: {device_id}")

    for device in active_devices:
        if device.timeout is None:
            continue
        if datetime.datetime.now() < device.timeout:
            continue
        logger.info(f"Deactivating device {device.device_id} due to automatic timeout.")
        _relaxed_deactivate_device(device.device_id)

    time.sleep(10)  # TODO make this configurable


async def relaxed_loop():
    """Initial PoC for an loop that automatically adds and removes agents"""
    async def loop():
        while True:
            await run_in_threadpool(_relaxed_handle_agents)

    ensure_future(loop())


def send_revocation(message: RevocationMsg):
    url = config.revocation_webhook
    # Check if a webhook is specified
    if not url:
        return
    session = requests.Session()
    # Dummy values will be replaced with real ones once the tagging part in Keylime is merged.
    new_msg = RevocationMessage(device_id=message.agent_id,
                                event_id="default",
                                severity_level="1",
                                context="DEFAULT")
    logger.info(f"Sending revocation message: {message}")
    try:
        session.post(url, data=new_msg)
    except requests.exceptions.RequestException as e:
        logger.error(f"Couldn't send revocation message \"{new_msg}\" via webhook: {e}")
