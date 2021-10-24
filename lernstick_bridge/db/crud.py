'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
import datetime
from typing import List, Optional

from pydantic import parse_obj_as
from sqlalchemy.exc import SQLAlchemyError

from lernstick_bridge.db import models
from lernstick_bridge.db.database import db
from lernstick_bridge.schema import bridge


def get_agent(agent_id: str) -> Optional[bridge.Agent]:
    """
    Get an agent from the database.

    :param agent_id: the agent UUID
    :return: the agent or None if not found
    """
    try:
        agent = db.query(models.Agent).filter(models.Agent.agent_id == agent_id).first()
    except SQLAlchemyError:
        return None

    if not agent:
        return None
    return bridge.Agent.from_orm(agent)


def get_agents() -> List[bridge.Agent]:
    """
    Get all agents from the database

    :return: List of agents
    """
    agents = db.query(models.Agent).all()
    return parse_obj_as(List[bridge.Agent], agents)


def add_agent(agent: bridge.Agent) -> bridge.Agent:
    """
    Add an agent to the database.
    Note this will not check if the agent already exists in the database.

    :param agent: the agent to add
    :return: the agent stored in the database
    """
    db_agent = models.Agent(**dict(agent))
    db.add(db_agent)
    db.commit()
    db.refresh(db_agent)
    return bridge.Agent.from_orm(db_agent)


def delete_agent(agent_id: str) -> bool:
    """
    Removes an agent from the database.

    :param agent_id: the agent UUID
    :return: True if successful and False if no agent with that agent_id was found the the database
    """
    db_agent = db.query(models.Agent).filter(models.Agent.agent_id == agent_id).first()
    if db_agent is None:
        return False
    db.delete(db_agent)
    db.commit()
    return True


def update_agent(agent: bridge.Agent) -> bool:
    """
    Updates an agent in the database.

    :param agent: agent with fields that should not change set to None
    :return: True if successful
    """
    db_agent = db.query(models.Agent).filter(models.Agent.agent_id == agent.agent_id).first()
    for key, value in agent.dict().items():
        if key is not None:
            setattr(db_agent, key, value)
    db.add(db_agent)
    db.commit()
    return True


def add_active_agent(agent_id: str, token: str, timeout: Optional[datetime.datetime] = None) -> bool:
    """
    Store the activation of an agent in the database.

    :param agent_id: the agent UUID
    :param token: token that is deployed to that agent. Note this value must be unique
    :param timeout: (only used in relaxed mode) when the agent should be removed automatically from attestation.
                    Set to None to never expire.
    :return: True if the action was successful
    """
    if get_active_agent(agent_id):
        return False

    active_agent = models.ActiveAgent(
        agent_id=agent_id,
        token=token,
        timeout=timeout
    )
    db.add(active_agent)
    db.commit()
    return True


def set_timeout_active_agent(agent_id: str, timeout: Optional[datetime.datetime]) -> bool:
    """
    Set or change the timeout of an active agent.

    :param agent_id: the agent UUID
    :param timeout: new timeout to set. Set to None to never expire
    :return: Ture if action was successful and False if agent is not active
    """
    agent = db.query(models.ActiveAgent).filter(models.ActiveAgent.agent_id == agent_id).first()
    if not agent:
        return False
    agent.timeout = timeout
    db.commit()
    return True


def get_active_agent(agent_id: str) -> Optional[bridge.ActiveAgent]:
    """
    Get an active agent.

    :param agent_id: the agent UUID
    :return: The agent or None if not found
    """
    agent = db.query(models.ActiveAgent).filter(models.ActiveAgent.agent_id == agent_id).first()
    if not agent:
        return None
    return bridge.ActiveAgent.from_orm(agent)


def get_active_agents() -> List[bridge.ActiveAgent]:
    """
    Get a list of all active agents.

    :return: the list of all active agents
    """
    agents = db.query(models.ActiveAgent).all()
    return parse_obj_as(List[bridge.ActiveAgent], agents)


def delete_active_agent(agent_id: str) -> bool:
    """
    Delete a active agent.

    :param agent_id: the agent UUID
    :return: True if successful and False if agent is not active
    """
    agent = db.query(models.ActiveAgent).filter(models.ActiveAgent.agent_id == agent_id).first()
    if not agent:
        return False
    db.delete(agent)
    db.commit()
    return True


def get_token(token: str) -> Optional[bridge.Token]:
    """
    Get token object with the agent id from the database.

    :param token: the token as a string
    :return: the token object or None if not found
    """
    token = db.query(models.ActiveAgent).filter(models.ActiveAgent.token == token).first()
    if not token:
        return None
    return bridge.Token.from_orm(token)
