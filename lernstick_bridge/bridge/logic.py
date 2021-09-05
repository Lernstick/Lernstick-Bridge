'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
import datetime
import time
from asyncio import ensure_future

import requests
from starlette.concurrency import run_in_threadpool

from lernstick_bridge.bridge.agent import AgentBridge
from lernstick_bridge.config import config
from lernstick_bridge.db import crud
from lernstick_bridge.keylime import verifier, registrar
from lernstick_bridge.bridge_logger import logger
from lernstick_bridge.schema.keylime import RevocationMsg
from lernstick_bridge.schema.bridge import RevocationMessage
from lernstick_bridge.utils import RetrySession

def activate_agent(agent_id: str) -> bool:
    if config.mode == "strict":
        return _strict_activate_agent(agent_id)
    elif config.mode == "relaxed":
        return _relaxed_activate_agent(agent_id)
    logger.error(f"Unknown mode {config.mode}. Cannot activate agent {agent_id}!")
    return False


def deactivate_agent(agent_id: str) -> bool:
    if config.mode == "strict":
        return _strict_deactivate_agent(agent_id)
    elif config.mode == "relaxed":
        return _relaxed_deactivate_agent(agent_id)
    logger.error(f"Unknown mode {config.mode}. Cannot deactivate agent {agent_id}!")
    return False


def _strict_activate_agent(agent_id: str) -> bool :
    """
    Try to add a agent for remote attestation
    :param agent_id:
    :return:

    """
    try:
        agent = AgentBridge(agent_id=agent_id, strict=True)
    except ValueError as e:
        logger.error(f"Was not able to collect agent data for id: {agent_id}! {e}")
        return False

    if not agent.valid_ek():
        logger.error(f"EK for agent {agent_id} was invalid!")
        return False

    if not agent.do_qoute():
        logger.error(f"Quote form agent {agent_id} was invalid!")
        return False

    token = agent.deploy_token()
    if token is None:
        logger.error(f"Token could not be deployed on agent {agent_id}")
        return False
    logger.debug(f"Deployed token: {token}")

    if not agent.add_to_verifier():
        logger.error(f"Agent {agent_id} could not be added to verifier")
        agent.remove_from_verifier()
        return False

    if not agent.activate():
        logger.error(f"Couldn't activate agent {agent_id}")
        agent.remove_from_verifier()
        return False

    logger.info(f"Successfully activated agent: {agent_id}")
    return True


def _relaxed_activate_agent(agent_id: str) -> bool:
    """
    Activates agent in relaxed mode.
    :param agent_id: agent ID of agent to activate
    :return: True if successful

    """
    if crud.set_timeout_active_agent(agent_id, None):
        logger.info(f"Removed timeout from agent {agent_id}")
        return True

    return False


def _strict_deactivate_agent(agent_id: str):
    """

    :param agent_id:
    :return:
    """
    if not crud.get_active_agent(agent_id):
        logger.error(f"Agent {agent_id} is not active so it cannot be deactivated!")
        return False  # TODO should be a not found

    verifier.delete_agent(agent_id)
    crud.delete_active_agent(agent_id)
    logger.error(f"Agent {agent_id} was deactivated.")
    return True


def _relaxed_deactivate_agent(agent_id: str):
    if not crud.get_active_agent(agent_id):
        return False  # TODO should be a not found

    verifier.delete_agent(agent_id)
    crud.delete_active_agent(agent_id)
    # We will delete also the agent from the registrar. It has to be restarted in order to be added again.
    registrar.delete_agent(agent_id)
    logger.info(f"Deactivated agent: {agent_id}")
    return True


def _relaxed_handle_agents():
    """
     - Get's the agents from the registrar and tries to activate them.
     - Checks if an active agent has reached its timeout and removes it.
     Note: It also removes it from the registrar currently. The agent must register itself again if it should be activated.
    :return: None
    """
    active_agents = crud.get_active_agents()
    active_ids = set()
    for agent in active_agents:
        active_ids.add(agent.agent_id)
    registrar_agents = registrar.get_agents()
    # TODO This should be done in parallel and sequential so that a single agent can block this loop
    for agent_id in registrar_agents:
        if agent_id in active_ids:
            continue
        try:
            agent = AgentBridge(agent_id=agent_id, strict=False)
        except ValueError as e:
            logger.error(f"Was not able to collect agent data for id: {agent_id}! {e}")
            continue

        if not agent.valid_ek() and config.validate_ek_registration:
            logger.error(f"EK for {agent_id} couldn't be validated!")
            continue

        if not agent.do_qoute():
            logger.error(f"Quote of {agent_id} was invalid!")
            continue

        if not agent.deploy_token():
            logger.error(f"Token couldn't be deployed on {agent_id}!")
            continue
        if not agent.add_to_verifier():
            logger.error(f"Couldn't add agent for agent {agent_id} to verifier!")
            continue

        timeout = datetime.datetime.now() + config.tenant.relaxed_timeout
        if not agent.activate(timeout=timeout):
            continue
        logger.info(f"Successfully activated agent: {agent_id}")

    for agent in active_agents:
        if agent.timeout is None:
            continue
        if datetime.datetime.now() < agent.timeout:
            continue
        logger.info(f"Deactivating agent {agent.agent_id} due to automatic timeout.")
        _relaxed_deactivate_agent(agent.agent_id)

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
    session = RetrySession()
    # Dummy values will be replaced with real ones once the tagging part in Keylime is merged.
    new_msg = RevocationMessage(agent_id=message.agent_id,
                                event_id="default",
                                severity_level="1",
                                context="DEFAULT")
    logger.info(f"Sending revocation message: {message}")
    try:
        session.post(url, data=new_msg)
    except requests.exceptions.RequestException as e:
        logger.error(f"Couldn't send revocation message \"{new_msg}\" via webhook: {e}")
