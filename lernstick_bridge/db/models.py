'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''

from sqlalchemy import Column, String, ForeignKey

from lernstick_bridge.db.database import Base

class Device(Base):
    __tablename__ = "devices"

    id = Column(String, primary_key=True, index=True)
    ek_cert = Column(String, nullable=False)  # The hardware vendor cert for the TPM
    # BIOS & UEFI related PCRs should be in general stable
    # Bootloader and Mok entries are getting validated via Keylime policies
    pcr_0 = Column(String, nullable=True)
    pcr_1 = Column(String, nullable=True)
    pcr_2 = Column(String, nullable=True)
    pcr_3 = Column(String, nullable=True)
    pcr_4 = Column(String, nullable=True)
    pcr_5 = Column(String, nullable=True)
    pcr_6 = Column(String, nullable=True)
    pcr_7 = Column(String, nullable=True)
    # Reference of the boot event log. Used for improving the measured boot policies
    event_log_reference = Column(String, nullable=True)

class Tokens(Base):
    __tablename__ = "tokens"
    token = Column(String, primary_key=True, index=True)
    device = Column(String, ForeignKey("devices.id"))

"""
class ActiveDevices(Base):
    __tablename__ = "active_devices"
"""

"""
class ActiveDevice(Base):
    __tablename__ = "active_devices"
    id = ForeignKey()
    activated = Column(Boolean)
"""
