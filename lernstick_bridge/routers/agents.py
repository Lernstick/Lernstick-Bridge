'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
import base64
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from lernstick_bridge.bridge import logic
from lernstick_bridge.config import cert_store, config
from lernstick_bridge.db import crud
from lernstick_bridge.db.database import get_db
from lernstick_bridge.keylime import ek, verifier
from lernstick_bridge.schema import bridge

router = APIRouter()


@router.get("/agents", response_model=List[bridge.Agent], tags=["agent_management"])
def list_agents(db: Session = Depends(get_db)) -> List[bridge.Agent]:
    """
    List all agents.

    :param db: Session to DB
    :return: List of agents
    """
    return crud.get_agents(db)


@router.post("/agents", response_model=bridge.Agent, tags=["agent_management"],
             responses={409: {"model": bridge.HTTPError, "description": "Agent was already in the database"},
                        412: {"model": bridge.HTTPError, "description": "EK of the agent couldn't be validated."}})
def create_agent(agent: bridge.AgentCreate, db: Session = Depends(get_db)) -> bridge.Agent:
    """
    Create a new agent at the bridge.
    If EK validation is enabled, the ek_cert will be validated against the certificate store.

    :param agent: the agent to create
    :param db: Session to DB
    :return: the agent that was created
    """
    db_agent = crud.get_agent(db, agent.agent_id)
    if db_agent:
        raise HTTPException(status_code=409, detail="Agent already in database")
    if config.validate_ek_registration:
        if not ek.validate_ek(base64.b64decode(agent.ek_cert), cert_store):
            raise HTTPException(status_code=412, detail="EK could not be validated against cert store")
    return crud.add_agent(db, agent)


@router.delete("/agents/{agent_id}", tags=["agent_management"],
               responses={404: {"model": bridge.HTTPError, "description": "Agent is not in the database"}})
def delete_agent(agent_id: str, db: Session = Depends(get_db)) -> Dict[Any, Any]:
    """
    Delete a agent from the bridge.

    :param agent_id: the agent UUID
    :param db: Session to DB
    :return: Empty dict if successful
    """
    db_agent = crud.get_agent(db, agent_id)
    if not db_agent:
        raise HTTPException(status_code=404, detail="Agent is not in the database")
    if not crud.delete_agent(db, agent_id):
        raise HTTPException(status_code=500, detail="Agent could not be deleted")
    return {}


@router.put("/agents/{agent_id}", tags=["agent_management"],
            responses={404: {"model": bridge.HTTPError, "description": "Agent is not in the database"}})
def update_agent(agent_id: str, agent: bridge.Agent, db: Session = Depends(get_db)) -> Dict[Any, Any]:
    """
    Update an agent at the bridge.

    :param agent_id: the agent UUID
    :param agent: the agent with fields not None to update
    :param db: Session to DB
    :return: empty dict if successful
    """
    if not crud.get_agent(db, agent_id):
        raise HTTPException(status_code=404, detail="Agent is not in the database")
    crud.update_agent(db, agent)
    return {}


@router.post("/agents/{agent_id}/activate", tags=["agent_attestation"],
             responses={400: {"model": bridge.HTTPError, "description": "Agent couldn't be activated"},
                        409: {"model": bridge.HTTPError, "description": "Agent already active"}})
def activate_agent(agent_id: str, db: Session = Depends(get_db)) -> Dict[Any, Any]:
    """
    Activate agent at the bridge.

    :param agent_id: the agent UUID
    :param db: Session to DB
    :return: empty dict if successful
    """
    agent = crud.get_active_agent(db, agent_id)
    if agent and agent.timeout is None:
        raise HTTPException(status_code=409, detail="Agent already active")

    activated = logic.activate_agent(db, agent_id)
    if not activated:
        raise HTTPException(status_code=400, detail="Couldn't activate agent")
    return {}


@router.get("/agents/{agent_id}/status", response_model=bridge.AgentStatus, tags=["agent_attestation"],
            responses={404: {"model": bridge.HTTPError, "description": "Agent not active nor in the database"}})
def agent_status(agent_id: str, db: Session = Depends(get_db)) -> bridge.AgentStatus:
    """
    Get the agent status at the bridge.
    status might be:
     - active: the agent is activated at the bridge
     - auto-active: the agent was automatically activated and has a timeout (only relaxed mode)
     - inactive: agent was created at the bridge but currently not active

    :param agent_id: the agent UUID
    :param db: Session to DB
    :return: Agent status
    """
    agent = crud.get_active_agent(db, agent_id)
    if agent:
        status = "active"
        if config.mode == "relaxed" and agent.timeout is not None:
            status = "auto-active"
        return bridge.AgentStatus(status=status, state=verifier.get_agent_state(agent_id), token=agent.token)
    db_agent = crud.get_agent(db, agent_id)
    if db_agent:
        return bridge.AgentStatus(status="inactive")

    raise HTTPException(status_code=404, detail="Agent not active nor in the database")


@router.post("/agents/{agent_id}/deactivate", tags=["agent_attestation"],
             responses={404: {"model": bridge.HTTPError, "description": "Agent not found in active database"},
                        500: {"model": bridge.HTTPError, "description": "Deactivation was not successful"}})
def deactivate_agent(agent_id: str, db: Session = Depends(get_db)) -> Dict[Any, Any]:
    """
    Deactivate agent at the bridge.

    :param agent_id: the agent UUID
    :param db: Session to DB
    :return: empty dict if successful
    """
    if not crud.get_active_agent(db, agent_id):
        raise HTTPException(status_code=404, detail="Agent not active")
    if logic.deactivate_agent(db, agent_id):
        return {}
    raise HTTPException(status_code=500, detail="Deactivation was not successful")


@router.post("/agents/verify", response_model=bridge.Token, tags=["agent_attestation"],
             responses={404: {"model": bridge.HTTPError, "description": "Taken does not belong to any agent"}})
def verify_token(token: str, db: Session = Depends(get_db)) -> bridge.Token:
    """
    Verify token to check if it belongs to an active agent.

    :param token: token to check
    :param db: Session to DB
    :return: Token with agent UUID if the token exits
    """
    db_token = crud.get_token(db, token)
    if not db_token:
        raise HTTPException(status_code=404, detail="Token does not belong to any agent")
    return db_token


@router.get("/agents/active", response_model=List[bridge.ActiveAgent], tags=["agent_attestation"])
def list_active_agents(db: Session = Depends(get_db)) -> List[bridge.ActiveAgent]:
    """
    List active agents at the bridge.

    :param db: Session to DB
    :return: list of active agents.
    """
    return crud.get_active_agents(db)
