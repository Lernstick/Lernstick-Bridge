'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
from fastapi import APIRouter
from starlette.background import BackgroundTasks

from lernstick_bridge.bridge import logic
from lernstick_bridge.bridge_logger import logger
from lernstick_bridge.db import crud
from lernstick_bridge.schema import keylime

router = APIRouter(tags=["keylime"])


@router.post("/revocation")
def revocation(message: keylime.RevocationResp, background_task: BackgroundTasks):
    if not crud.get_active_agent(message.msg.agent_id):
        logger.info(f"Received for agent {message.msg.agent_id}, but this agent is not active. Ignoring...")
        return False
    logger.info(f"Received revocation message from Keylime: {message.json()}")
    background_task.add_task(logic.send_revocation, message.msg)
    return True
