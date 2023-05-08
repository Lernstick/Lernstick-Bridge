"""
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
"""
import datetime
from typing import List, Optional

from pydantic import parse_obj_as
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from lernstick_bridge.db import models
from lernstick_bridge.schema import bridge
from lernstick_bridge.utils import Flag


def get_agent(db: Session, agent_id: str) -> Optional[bridge.Agent]:
    """
    Get an agent from the database.

    :param db: Session to DB
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


def get_agents(db: Session) -> List[bridge.Agent]:
    """
    Get all agents from the database

    :param db: Session to DB
    :return: List of agents
    """
    agents = db.query(models.Agent).all()
    return parse_obj_as(List[bridge.Agent], agents)


def add_agent(db: Session, agent: bridge.Agent) -> bridge.Agent:
    """
    Add an agent to the database.
    Note this will not check if the agent already exists in the database.

    :param db: Session to DB
    :param agent: the agent to add
    :return: the agent stored in the database
    """
    db_agent = models.Agent(**dict(agent))
    db.add(db_agent)
    db.commit()
    db.refresh(db_agent)
    return bridge.Agent.from_orm(db_agent)


def delete_agent(db: Session, agent_id: str) -> bool:
    """
    Removes an agent from the database.

    :param db: Session to DB
    :param agent_id: the agent UUID
    :return: True if successful and False if no agent with that agent_id was found the the database
    """
    db_agent = db.query(models.Agent).filter(models.Agent.agent_id == agent_id).first()
    if db_agent is None:
        return False
    db.delete(db_agent)
    db.commit()
    return True


def update_agent(db: Session, agent: bridge.Agent) -> bool:
    """
    Updates an agent in the database.

    :param db: Session to DB
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


def add_active_agent(db: Session, agent_id: str, token: str, timeout: Optional[datetime.datetime] = None) -> bool:
    """
    Store the activation of an agent in the database.

    :param db: Session to DB
    :param agent_id: the agent UUID
    :param token: token that is deployed to that agent. Note this value must be unique
    :param timeout: (only used in relaxed mode) when the agent should be removed automatically from attestation.
                    Set to None to never expire.
    :return: True if the action was successful
    """
    if get_active_agent(db, agent_id):
        return False

    active_agent = models.ActiveAgent(agent_id=agent_id, token=token, timeout=timeout)
    db.add(active_agent)
    db.commit()
    return True


def set_timeout_active_agent(db: Session, agent_id: str, timeout: Optional[datetime.datetime]) -> bool:
    """
    Set or change the timeout of an active agent.

    :param db: Session to DB
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


def get_active_agent(db: Session, agent_id: str) -> Optional[bridge.ActiveAgent]:
    """
    Get an active agent.

    :param db: Session to DB
    :param agent_id: the agent UUID
    :return: The agent or None if not found
    """
    agent = db.query(models.ActiveAgent).filter(models.ActiveAgent.agent_id == agent_id).first()
    if not agent:
        return None
    return bridge.ActiveAgent.from_orm(agent)


def get_active_agents(db: Session) -> List[bridge.ActiveAgent]:
    """
    Get a list of all active agents.

    :param db: Session to DB
    :return: the list of all active agents
    """
    agents = db.query(models.ActiveAgent).all()
    return parse_obj_as(List[bridge.ActiveAgent], agents)


def delete_active_agent(db: Session, agent_id: str) -> bool:
    """
    Delete an active agent.

    :param db: Session to DB
    :param agent_id: the agent UUID
    :return: True if successful and False if agent is not active
    """
    agent = db.query(models.ActiveAgent).filter(models.ActiveAgent.agent_id == agent_id).first()
    if not agent:
        return False
    db.delete(agent)
    db.commit()
    return True


def get_token(db: Session, token: str) -> Optional[bridge.Token]:
    """
    Get token object with the agent id from the database.

    :param db: Session to DB
    :param token: the token as a string
    :return: the token object or None if not found
    """
    db_token = db.query(models.ActiveAgent).filter(models.ActiveAgent.token == token).first()
    if not db_token:
        return None
    return bridge.Token.from_orm(db_token)


def get_keylime_policies(db: Session) -> List[bridge.KeylimePolicy]:
    """
    Get all Keylime policies.

    :param db: Session to DB
    :return: List of Keylime policies
    """
    db_policies = db.query(models.KeylimePolicy).all()
    return parse_obj_as(List[bridge.KeylimePolicy], db_policies)


def get_keylime_policy(db: Session, policy_id: str) -> Optional[bridge.KeylimePolicy]:
    """
    Get policy by ID.

    :param db: Session to DB
    :param policy_id: The ID of the policy
    :return: The Keylime policy or None if it does not exists.
    """
    db_keylime_policy = db.query(models.KeylimePolicy).filter(models.KeylimePolicy.policy_id == policy_id).first()
    if db_keylime_policy is None:
        return None
    return bridge.KeylimePolicy.from_orm(db_keylime_policy)


def add_keylime_policy(db: Session, keylime_policy: bridge.KeylimePolicyAdd) -> Optional[bridge.KeylimePolicy]:
    """
    Add a new Keylime policy to the database

    :param db: Session to DB
    :param keylime_policy: The policy that get added
    :return: The added policy or None if already a policy with the same ID exists
    """
    db_entry = db.query(models.KeylimePolicy).filter(models.KeylimePolicy.policy_id == keylime_policy.policy_id).first()
    if db_entry:
        return None

    db_keylime_policy = keylime_policy.to_orm()
    db.add(db_keylime_policy)
    db.commit()
    db.refresh(db_keylime_policy)
    return bridge.KeylimePolicy.from_orm(db_keylime_policy)


def delete_keylime_policy(db: Session, policy_id: str) -> bool:
    """
    Delete Keylime policy from database.

    :param db: Session to DB
    :param policy_id: The ID of the Keylime policy
    :return: The
    """
    db_policy = db.query(models.KeylimePolicy).filter(models.KeylimePolicy.policy_id == policy_id).first()
    if db_policy is None:
        return False
    db.delete(db_policy)
    db.commit()
    return True


def activate_keylime_policy(db: Session, policy_id: str) -> bool:
    """
    Activate a different

    This automatically deactivates the old active policy.

    :param db: Session to DB
    :param policy_id: the ID of the policy
    :return: False if the policy id could not be found and True if successful
    """
    db_new_active = db.query(models.KeylimePolicy).filter(models.KeylimePolicy.policy_id == policy_id).first()
    if db_new_active is None:
        return False
    db_current_active = db.query(models.KeylimePolicy).filter(models.KeylimePolicy.active == Flag.SET).first()
    if db_current_active:
        db_current_active.active = None
    db_new_active.active = Flag.SET  # type: ignore[assignment]
    db.commit()
    return True


def deactivate_keylime_policy(db: Session, policy_id: str) -> bool:
    """
    Deactivates a policy.

    :param db: Session to DB
    :return: False if policy is not found or not active, otherwise True
    """
    db_policy = db.query(models.KeylimePolicy).filter(models.KeylimePolicy.policy_id == policy_id).first()
    if db_policy is None:
        return False
    if db_policy.active is None:
        return False
    db_policy.active = None
    db.commit()
    return True


def get_active_keylime_policy(db: Session) -> Optional[bridge.KeylimePolicy]:
    """
    Get current active policy

    :param db: Session to DB
    :return: Active Policy or None if there is no active policy.
    """
    db_active = db.query(models.KeylimePolicy).filter(models.KeylimePolicy.active == Flag.SET).first()
    if db_active is None:
        return None
    return bridge.KeylimePolicy.from_orm(db_active)
