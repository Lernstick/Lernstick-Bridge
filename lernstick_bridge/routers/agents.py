'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
from typing import List

from fastapi import HTTPException, APIRouter

from lernstick_bridge.bridge import logic
from lernstick_bridge.config import config, cert_store
from lernstick_bridge.db import crud
from lernstick_bridge.keylime import ek
from lernstick_bridge.schema import bridge

router = APIRouter()


@router.get("/agents", response_model=List[bridge.Agent], tags=["agent_management"])
def list_agents():
    return crud.get_agents()


@router.post("/agents/", response_model=bridge.Agent, tags=["agent_management"])
def create_agent(agent: bridge.AgentCreate):
    db_agent = crud.get_agent(agent.agent_id)
    if db_agent:
        raise HTTPException(status_code=400, detail="Agent already in database")
    if config.validate_ek_registration:
        if not ek.validate_ek(agent.ek_cert.encode("utf-8"), cert_store):
            raise HTTPException(status_code=400, detail="EK could not be validated against cert store")
    return crud.add_agent(agent)


@router.delete("/agents/{agent_id}", tags=["agent_management"])
def delete_agent(agent_id: str):
    db_agent = crud.get_agent(agent_id)
    if not db_agent:
        raise HTTPException(status_code=400, detail="Agent is not in the database")
    crud.delete_agent(agent_id)
    return {}


@router.put("/agents/{agent_id}", tags=["agent_management"])
def update_agent(agent_id: str, agent: bridge.Agent):
    pass


@router.post("/agents/{agent_id}/activate", tags=["agent_attestation"])
def activate_agent(agent_id: str):
    return logic.activate_agent(agent_id)


@router.get("/agents/{agent_id}/status", response_model=bridge.AgentStatus, tags=["agent_attestation"])
def agent_status(agent_id: str):
    # TODO retive also state if active
    agent = crud.get_active_agent(agent_id)
    if agent:
        status = "active"
        if config.mode == "relaxed" and agent.timeout is not None:
            status = "auto-active"
        return bridge.AgentStatus(status=status, token=agent.token)
    db_agent = crud.get_agent(agent_id)
    if db_agent:
        return bridge.AgentStatus(status="inactive")

    raise HTTPException(status_code=400, detail="Agent not active nor in the database")


@router.post("/agents/{agent_id}/deactivate", tags=["agent_attestation"])
def deactivate_agent(agent_id: str):
    return logic.deactivate_agent(agent_id)


@router.post("/verify", response_model=bridge.Token, tags=["agent_attestation"])
def verify_token(token: str):
    token = crud.get_token(token)
    if not token:
        raise HTTPException(status_code=400, detail="Token does not belong to any Agent")
    return token