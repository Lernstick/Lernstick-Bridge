'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
import datetime

from pydantic import BaseModel, PrivateAttr
from typing import Optional
from lernstick_bridge.schema.keylime import Payload
from lernstick_bridge.keylime import util


class Agent(BaseModel):
    """Agent model that is stored in the database"""
    agent_id: str  # Normally the hash of the ek_cert
    ek_cert: Optional[str]  # The hardware vendor cert for the TPM
    # BIOS & UEFI related PCRs should be in general stable
    # Bootloader and Mok entries are getting validated via Keylime policies
    pcr_0: Optional[str]
    pcr_1: Optional[str]
    pcr_2: Optional[str]
    pcr_3: Optional[str]
    pcr_4: Optional[str]
    pcr_5: Optional[str]
    pcr_6: Optional[str]
    pcr_7: Optional[str]
    event_log_reference: Optional[str]  # Reference of the boot event log. Used for improving the measured boot policies

    class Config:
        orm_mode = True


class AgentCreate(Agent):
    ek_cert: str


class AgentStatus(BaseModel):
    status: str
    token: Optional[str]
    state: Optional[str]


class ActiveAgent(BaseModel):
    agent_id: str
    token: str
    timeout: Optional[datetime.datetime]

    class Config:
        orm_mode = True


class Token(BaseModel):
    """Verification token."""
    agent_id: str
    token: str

    _payload: Optional[Payload] = PrivateAttr(None)  # The payload is not added to the database!

    def __init__(self, agent_id: str, token: str = None):
        if token is None:
            token = util.get_random_nonce(20)
        super().__init__(agent_id=agent_id, token=token)

    def to_payload(self):
        if not self._payload:
            self._payload = util.generate_payload(self.token)
        return self._payload

    class Config:
        orm_mode = True


class RevocationMessage(BaseModel):
    agent_id: str
    event_id: str
    severity_level: str
    context: str


class HTTPError(BaseModel):
    """Class that is used for documenting HTTPExceptions"""
    detail: str

    class Config:
        schema_extra = {"example": {"detail": "(HTTPException) Not found."}}