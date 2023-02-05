'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
from typing import Any, Dict, List

import anyio
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from starlette.background import BackgroundTasks

from lernstick_bridge.bridge import logic
from lernstick_bridge.bridge_logger import logger
from lernstick_bridge.config import config
from lernstick_bridge.db import crud
from lernstick_bridge.schema import bridge, keylime
from lernstick_bridge.utils import WebsocketConnectionManager

router = APIRouter(tags=["keylime"])


callback_router = APIRouter()  # This router is only used for documentation purposes


@callback_router.post("{$revocation_webhook}", description="Sends revocation message to exam system")
def send_revocation_message(_: bridge.RevocationMessage) -> None:  # pylint: disable=missing-function-docstring
    pass


_manager = WebsocketConnectionManager()


def _get_manager() -> WebsocketConnectionManager:
    return _manager


if config.revocation_websocket:
    @router.websocket("/ws")
    async def websocket_endpoint(
            websocket: WebSocket,
            manager: WebsocketConnectionManager = Depends(_get_manager)
            ) -> None:
        """
        Websocket entrypoint for revocation messaged.
        WARNING: This only works if the bridge runs single threaded. Use for test purposes only!

        :param websocket: the websocket that tries to connect.
        :param manager: websocket connection manager.
        """
        await manager.connect(websocket)
        try:
            while True:
                await anyio.sleep(10)
        except WebSocketDisconnect:
            manager.disconnect(websocket)


@router.post("/revocation", callbacks=callback_router.routes)
async def revocation(
        message: keylime.RevocationResp,
        background_task: BackgroundTasks,
        manager: WebsocketConnectionManager = Depends(_get_manager)
) -> bool:
    """
    Webhook entry point for Keylime to call for revocation messages.

    :param message: revocation message from Keylime
    :param background_task: Background task that is used to send the message to the exam system.
    :param manager: websocket connection manager.
    :return: True if we sent the message.
    """
    assert isinstance(message.msg, keylime.RevocationMsg)  # Make mypy happy because Json type defaults to str

    if not crud.get_active_agent(message.msg.agent_id):
        logger.info(f"Received for agent {message.msg.agent_id}, but this agent is not active. Ignoring...")
        return False
    logger.info(f"Received revocation message from Keylime: {message.json()}")

    if config.revocation_websocket:
        await manager.broadcast(message.json())
    background_task.add_task(logic.send_revocation, message.msg)
    return True


# Routes for Keylime policy management
@router.get("/policy", response_model=List[bridge.KeylimePolicy], tags=["keylime"])
def list_keylime_policies() -> List[bridge.KeylimePolicy]:
    """
    Lists all currently available policies.

    :return: List of Keylime policies
    """
    return crud.get_keylime_policies()


@router.get("/policy/{policy_id}", response_model=bridge.KeylimePolicy, tags=["keylime"],
            responses={404: {"model": bridge.HTTPError, "description": "If the Keylime policy cannot be found"}})
def get_keylime_policy(policy_id: str) -> bridge.KeylimePolicy:
    """
    Gets the Keylime policy by id.

    :param policy_id: ID of the Keylime policy
    :return: KeylimePolicy
    """
    keylime_policy = crud.get_keylime_policy(policy_id)
    if keylime_policy is None:
        raise HTTPException(404, detail="Keylime policy found in the database")
    return keylime_policy


@router.post("/policy", tags=["keylime"],
             response_model=bridge.KeylimePolicyAdd,
             responses={409: {"model": bridge.HTTPError, "description": "Keylime policy is already in the database"}})
def add_keylime_policy(keylime_policy: bridge.KeylimePolicyAdd) -> bridge.KeylimePolicy:
    """
    Add Keylime policy to the bridge.

    :param keylime_policy: the policy to add.
    :return: The created policy
    """
    added_keylime_policy = crud.add_keylime_policy(keylime_policy)
    if added_keylime_policy is None:
        raise HTTPException(409, "Keylime policy is already in the database")

    return added_keylime_policy


@router.delete("/policy/{policy_id}", tags=["keylime"],
             response_model=Dict[Any, Any],
             responses={404: {"model": bridge.HTTPError, "description": "If policy is not in the database"}})
def delete_keylime_policy(policy_id: str) -> Dict[Any, Any]:
    """
    Delete a keylime policy.

    :param policy_id: ID of the Keylime policy
    :return: Empty dict if successful
    """
    res = crud.delete_keylime_policy(policy_id)
    if res is None:
        raise HTTPException(404, "Policy is not in database")
    return {}


@router.get("/policy/{policy_id}/activate", tags=["keylime"],
            response_model=Dict[Any, Any],
            responses={404: {"model": bridge.HTTPError, "description": "If policy is not in the database"}})
def activate_keylime_policy(policy_id: str) -> Dict[Any, Any]:
    """
    Activate Keylime policy. The old active policy gets deactivated.

    :param policy_id: ID of the Keylime policy
    :return: Empty dict if successful
    """
    if not crud.get_keylime_policy(policy_id):
        raise HTTPException(404, "Policy is not in database")

    if not crud.activate_keylime_policy(policy_id):
        raise HTTPException(500, "Policy could not be activated")

    return {}


@router.get("/policy/{policy_id}/deactivate",
            response_model=Dict[Any, Any],
            responses={404: {"model": bridge.HTTPError, "description": "If policy is not in the database"}})
def deactivate_keylime_policy(policy_id: str) -> Dict[Any, Any]:
    """
    Deactivate Keylime policy.

    :param policy_id: ID of the Keylime policy
    :return: Empty dict if successful
    """
    if not crud.get_keylime_policy(policy_id):
        raise HTTPException(404, "Policy is not in database")

    if not crud.deactivate_keylime_policy(policy_id):
        raise HTTPException(500, "Policy could not be deactivated")

    return {}
