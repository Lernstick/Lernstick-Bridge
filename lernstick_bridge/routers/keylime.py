'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
import json
from typing import Annotated, Any, AsyncGenerator, AsyncIterator, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sse_starlette.sse import EventSourceResponse

from lernstick_bridge.bridge_logger import logger
from lernstick_bridge.config import config
from lernstick_bridge.db import crud
from lernstick_bridge.db.database import get_db
from lernstick_bridge.schema import bridge, keylime
from lernstick_bridge.utils import RedisStream, create_redis_pool

router = APIRouter(tags=["keylime"])
callback_router = APIRouter()  # This router is only used for documentation purposes


_redis_pool = create_redis_pool(config.redis_host, config.redis_port)


async def _get_stream() -> AsyncGenerator[RedisStream, None]:
    stream = RedisStream("keylime", connection_pool=_redis_pool, max_messages=config.redis_max_revocation_messages)
    try:
        yield stream
    finally:
        await stream.close()


@router.post("/revocation", callbacks=callback_router.routes)
async def post_revocation(
        message: keylime.RevocationResp,
        stream: Annotated[RedisStream, Depends(_get_stream)],
        db: Session = Depends(get_db)
) -> bool:
    """
    Webhook entry point for Keylime to call for revocation messages.

    :param message: revocation message from Keylime
    :param stream: stream for SSE handling of revocation messages
    :param db: Session to DB
    :return: True if we sent the message.
    """
    assert isinstance(message.msg, keylime.RevocationMsg)  # Make mypy happy because Json type defaults to str

    if not crud.get_active_agent(db, message.msg.agent_id):
        logger.info(f"Received for agent {message.msg.agent_id}, but this agent is not active. Ignoring...")
        return False
    logger.info(f"Received revocation message from Keylime: {message.json()}")

    bridge_message = bridge.RevocationMessage.from_revocation_msg(message.msg)
    await stream.add(json.dumps(bridge_message.json()))
    return True


async def get_revocations(request: Request, stream: RedisStream) -> AsyncIterator[Dict[Any, Any]]:
    """
    Iterator that get the revocation messages from the stream until the request is closed.

    :param request: The SSE request that is used.
    :param stream: The stream to get the messages from
    """
    while True:
        data = await stream.get(block=1000)
        if await request.is_disconnected():
            break
        for item in data:
            yield json.loads(item)


@router.get("/revocation", tags=["keylime"])
async def get_revocation(request: Request, stream: Annotated[RedisStream, Depends(_get_stream)]) -> EventSourceResponse:
    """
    SSE endpoint for revocation messages

    :param request: the HTTP request. Used by the iterator to check if the session was disconnected
    :param stream: stream for the revocation data
    """
    generator = get_revocations(request, stream)
    return EventSourceResponse(generator)


# Routes for Keylime policy management
@router.get("/policy", response_model=List[bridge.KeylimePolicy], tags=["keylime"])
def list_keylime_policies(db: Session = Depends(get_db)) -> List[bridge.KeylimePolicy]:
    """
    Lists all currently available policies.

    :param db: Session to DB
    :return: List of Keylime policies
    """
    return crud.get_keylime_policies(db)


@router.get("/policy/{policy_id}", response_model=bridge.KeylimePolicy, tags=["keylime"],
            responses={404: {"model": bridge.HTTPError, "description": "If the Keylime policy cannot be found"}})
def get_keylime_policy(policy_id: str, db: Session = Depends(get_db)) -> bridge.KeylimePolicy:
    """
    Gets the Keylime policy by id.

    :param policy_id: ID of the Keylime policy
    :param db: Session to DB
    :return: KeylimePolicy
    """
    keylime_policy = crud.get_keylime_policy(db, policy_id)
    if keylime_policy is None:
        raise HTTPException(404, detail="Keylime policy found in the database")
    return keylime_policy


@router.post("/policy", tags=["keylime"],
             response_model=bridge.KeylimePolicy,
             responses={409: {"model": bridge.HTTPError, "description": "Keylime policy is already in the database"}})
def add_keylime_policy(keylime_policy: bridge.KeylimePolicyAdd, db: Session = Depends(get_db)) -> bridge.KeylimePolicy:
    """
    Add Keylime policy to the bridge.

    :param keylime_policy: the policy to add.
    :param db: Session to DB
    :return: The created policy
    """
    added_keylime_policy = crud.add_keylime_policy(db, keylime_policy)
    if added_keylime_policy is None:
        raise HTTPException(409, "Keylime policy is already in the database")

    return added_keylime_policy


@router.delete("/policy/{policy_id}", tags=["keylime"],
             response_model=Dict[Any, Any],
             responses={404: {"model": bridge.HTTPError, "description": "If policy is not in the database"}})
def delete_keylime_policy(policy_id: str, db: Session = Depends(get_db)) -> Dict[Any, Any]:
    """
    Delete a keylime policy.

    :param policy_id: ID of the Keylime policy
    :param db: Session to DB
    :return: Empty dict if successful
    """
    res = crud.delete_keylime_policy(db, policy_id)
    if res is None:
        raise HTTPException(404, "Policy is not in database")
    return {}


@router.put("/policy/{policy_id}/activate", tags=["keylime"],
            response_model=Dict[Any, Any],
            responses={404: {"model": bridge.HTTPError, "description": "If policy is not in the database"}})
def activate_keylime_policy(policy_id: str, db: Session = Depends(get_db)) -> Dict[Any, Any]:
    """
    Activate Keylime policy. The old active policy gets deactivated.

    :param policy_id: ID of the Keylime policy
    :param db: Session to DB
    :return: Empty dict if successful
    """
    if not crud.get_keylime_policy(db, policy_id):
        raise HTTPException(404, "Policy is not in database")

    if not crud.activate_keylime_policy(db, policy_id):
        raise HTTPException(500, "Policy could not be activated")

    return {}


@router.put("/policy/{policy_id}/deactivate",
            response_model=Dict[Any, Any],
            responses={404: {"model": bridge.HTTPError, "description": "If policy is not in the database"}})
def deactivate_keylime_policy(policy_id: str, db: Session = Depends(get_db)) -> Dict[Any, Any]:
    """
    Deactivate Keylime policy.

    :param policy_id: ID of the Keylime policy
    :param db: Session to DB
    :return: Empty dict if successful
    """
    if not crud.get_keylime_policy(db, policy_id):
        raise HTTPException(404, "Policy is not in database")

    if not crud.deactivate_keylime_policy(db, policy_id):
        raise HTTPException(500, "Policy could not be deactivated")

    return {}
