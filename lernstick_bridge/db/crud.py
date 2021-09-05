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
    Returns a agent from the database
    :param agent_id: the agent id
    :return: the Agent or None if not found
    """
    try:
        agent = db.query(models.Agent).filter(models.Agent.agent_id == agent_id).first()
    except SQLAlchemyError as e:
        return None

    if not agent:
        return None
    return bridge.Agent.from_orm(agent)


def get_agents() -> List[bridge.Agent]:
    agents = db.query(models.Agent).all()
    return parse_obj_as(List[bridge.Agent], agents)


def add_agent(agent: bridge.Agent) -> bridge.Agent:
    db_agent = models.Agent(**dict(agent))
    db.add(db_agent)
    db.commit()
    db.refresh(db_agent)
    return bridge.Agent.from_orm(db_agent)


def delete_agent(agent_id: str) -> bool:
    agent = get_agent(agent_id)
    db.delete(agent)
    db.commit()
    return True


def update_agent(agent: bridge.Agent) -> bool:
    db_agent = db.query(models.Agent).filter(models.Agent.agent_id == agent.agent_id).first()
    for key, value in agent.dict().items():
        if key is not None:
            setattr(db_agent, key, value)
    db.add(db_agent)
    db.commit()
    return True


def add_active_agent(agent_id: str, token: str, timeout: Optional[datetime.datetime] = None) -> bool:
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
    agent = db.query(models.ActiveAgent).filter(models.ActiveAgent.agent_id == agent_id).first()
    if not agent:
        return False
    agent.timeout = timeout
    db.commit()
    return True


def get_active_agent(agent_id: str) -> Optional[bridge.ActiveAgent]:
    agent = db.query(models.ActiveAgent).filter(models.ActiveAgent.agent_id == agent_id).first()
    if not agent:
        return None
    return bridge.ActiveAgent.from_orm(agent)


def get_active_agents() -> List[bridge.ActiveAgent]:
    agents = db.query(models.ActiveAgent).all()
    return parse_obj_as(List[bridge.ActiveAgent], agents)


def delete_active_agent(agent_id: str) -> bool:
    agent = db.query(models.ActiveAgent).filter(models.ActiveAgent.agent_id == agent_id).first()
    if not agent:
        return False
    db.delete(agent)
    db.commit()
    return True


def get_token(token: str) -> Optional[bridge.Token]:
    token = db.query(models.ActiveAgent).filter(models.ActiveAgent.token == token).first()
    if not token:
        return None
    return bridge.Token.from_orm(token)
