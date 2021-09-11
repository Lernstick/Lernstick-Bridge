'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
# pylint: disable=too-few-public-methods
import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, PrivateAttr

from lernstick_bridge.keylime import util
from lernstick_bridge.schema.keylime import Payload


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
    token: str = Field(default_factory=util.get_random_nonce)

    _payload: Optional[Payload] = PrivateAttr(None)  # The payload is not added to the database!

    def to_payload(self) -> Payload:
        if not self._payload:
            self._payload = util.generate_payload(self.token)
        return self._payload

    def get_payload_k(self) -> Optional[bytes]:
        if not self._payload:
            return None
        return self._payload.k

    class Config:
        orm_mode = True


class RevocationMessage(BaseModel):
    agent_id: str
    event_id: Optional[str]
    severity_label: Optional[str]
    context: Optional[Dict[Any, Any]]


class HTTPError(BaseModel):
    """Class that is used for documenting HTTPExceptions"""
    detail: str

    class Config:
        schema_extra = {"example": {"detail": "(HTTPException) Not found."}}
