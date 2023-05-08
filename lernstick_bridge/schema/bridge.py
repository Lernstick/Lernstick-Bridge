'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
# pylint: disable=too-few-public-methods
import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, PrivateAttr
from pydantic.utils import GetterDict

from lernstick_bridge.db.models import KeylimePolicy as DbKeylimePolicy
from lernstick_bridge.keylime import util
from lernstick_bridge.schema.keylime import AgentState, Payload, RevocationMsg
from lernstick_bridge.utils import Flag


class Agent(BaseModel):
    """
    Agent model that is stored in the database.
    """
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

    class Config:  # pylint: disable=missing-class-docstring
        orm_mode = True


class AgentCreate(Agent):
    """
    Agent model for adding an agent to the bridge.
    This requires the EK cert to be send.
    """
    ek_cert: str


class AgentStatus(BaseModel):
    """
    Agent status at the bridge and the state from the Keylime Verifier.
    """
    status: str
    token: Optional[str]
    state: Optional[AgentState]


class ActiveAgent(BaseModel):
    """
    Active agent model.
    """
    agent_id: str
    token: str
    timeout: Optional[datetime.datetime]

    class Config:  # pylint: disable=missing-class-docstring
        orm_mode = True


class Token(BaseModel):
    """Verification token."""
    agent_id: str
    token: str = Field(default_factory=util.get_random_nonce)

    _payload: Optional[Payload] = PrivateAttr(None)  # The payload is not added to the database!

    def to_payload(self) -> Payload:
        """
        Convert to Keylime Payload.

        :return: Keylime Payload containing the token
        """
        if not self._payload:
            self._payload = util.generate_payload(self.token)
        return self._payload

    class Config:  # pylint: disable=missing-class-docstring
        orm_mode = True

class TokenVerify(BaseModel):
    """Token submitted for verification to the bridge"""
    token: str


class RevocationMessage(BaseModel):
    """
    Revocation message sent to exam systems via SSE.
    """
    agent_id: str
    event_id: Optional[str]
    severity_label: Optional[str]
    context: Optional[Dict[Any, Any]]

    @staticmethod
    def from_revocation_msg(revocation_msg: RevocationMsg) -> "RevocationMessage":
        """
        Convert from Keylime RevocationMsg

        :param revocation_msg: RevocationMsg sent by Keylime
        :return: RevocationMessage that is sent by the Bridge
        """
        return RevocationMessage(agent_id=revocation_msg.agent_id,
                                 event_id=revocation_msg.event_id,
                                 severity_label=revocation_msg.severity_label,
                                 context=revocation_msg.context)


class KeylimePolicyGetter(GetterDict):
    """
    Getter that converts flag into boolean for KeylimePolicy.
    """
    def get(self, key: Any, default: Any = None) -> Any:
        """
        If key is "active" it checks if the flag is set and converts it to a boolean.

        :param key: to look up.
        :param default: default value if key cannot be found:
        :return: The lookup of key or the default value if not found.
        """
        value = getattr(self._obj, key, default)
        if key == "active":
            return value is Flag.SET
        return value


class KeylimePolicy(BaseModel):
    """
    Policy that is used to configure Keylime.

    Note: The ORM model is slightly different, due how we enforce that only one policy can be active at the time
    """
    policy_id: str
    active: bool
    runtime_policy: Optional[Dict[str, Any]]
    mb_refstate: Optional[Dict[Any, Any]]

    class Config:  # pylint: disable=missing-class-docstring
        orm_mode = True
        getter_dict = KeylimePolicyGetter


class KeylimePolicyAdd(BaseModel):
    """
    KeylimePolicy object for adding the configuration to the bridge.
    It excludes the active option, because all policies are inactive by default.
    """
    policy_id: str
    runtime_policy: Optional[Dict[str, Any]]
    mb_refstate: Optional[Dict[Any, Any]]

    def to_orm(self) -> DbKeylimePolicy:
        """
        Creates ORM model object.

        :return: KeylimePolicy database object.
        """
        return DbKeylimePolicy(
            policy_id=self.policy_id,
            active=None,
            runtime_policy=self.runtime_policy,
            mb_refstate=self.mb_refstate,
        )


class HTTPError(BaseModel):
    """Class that is used for documenting HTTPExceptions"""
    detail: str

    class Config:  # pylint: disable=missing-class-docstring
        schema_extra = {"example": {"detail": "(HTTPException) Not found."}}
