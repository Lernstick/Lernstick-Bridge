'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
from fastapi import APIRouter
from starlette.background import BackgroundTasks

from lernstick_bridge.bridge import logic
from lernstick_bridge.schema import keylime

router = APIRouter()

@router.post("/revocation")
def revocation(message: keylime.RevocationResp, background_task: BackgroundTasks):
    background_task.add_task(logic.send_revocation, message.msg)
    return "OK"