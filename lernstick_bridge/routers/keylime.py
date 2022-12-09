'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
import anyio
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
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
