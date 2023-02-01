'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
# pylint: disable=too-few-public-methods

from sqlalchemy import Column, DateTime, String, Text

from lernstick_bridge.db.database import Base


class Agent(Base):
    """
    Database model for the agents table in strict mode.
    """
    __tablename__ = "agents"

    agent_id = Column(String(100), primary_key=True, index=True)  # Is in our case the ek_cert hashed
    ek_cert = Column(String(10000), nullable=False)  # The hardware vendor cert for the TPM
    # BIOS & UEFI related PCRs should be in general stable
    # Bootloader and Mok entries are getting validated via Keylime policies
    pcr_0 = Column(String(100), nullable=True)
    pcr_1 = Column(String(100), nullable=True)
    pcr_2 = Column(String(100), nullable=True)
    pcr_3 = Column(String(100), nullable=True)
    pcr_4 = Column(String(100), nullable=True)
    pcr_5 = Column(String(100), nullable=True)
    pcr_6 = Column(String(100), nullable=True)
    pcr_7 = Column(String(100), nullable=True)
    # Reference of the boot event log. Used for improving the measured boot policies
    event_log_reference = Column(Text(), nullable=True)


class ActiveAgent(Base):
    """
    Database model for the active agent table.
    """
    __tablename__ = "active_agents"
    agent_id = Column(String(100), primary_key=True, index=True)
    token = Column(String(100), unique=True, index=True)  # Tokens are assumed to be be unique so we enforce that in the database
    timeout = Column(DateTime, nullable=True)  # If timeout is NULL it means that the agent is always valid.
