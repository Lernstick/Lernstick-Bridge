'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
import datetime

from pydantic import parse_obj_as
from typing import List, Optional

from lernstick_bridge.db import models
from lernstick_bridge.schema import bridge
from lernstick_bridge.db.database import db


def get_device(device_id: str):
    device = db.query(models.Device).filter(models.Device.id == device_id).first()
    if not device:
        return None
    return bridge.Device.from_orm(device)


def get_devices() -> List[bridge.Device]:
    devices = db.query(models.Device).all()
    return parse_obj_as(List[bridge.Device], devices)


def add_device(device: bridge.Device):
    db_device = models.Device(**dict(device))
    db.add(db_device)
    db.commit()
    db.refresh(db_device)
    return db_device


def delete_device(device_id: str) -> bool:
    device = get_device(device_id)
    db.delete(device)
    db.commit()
    return True


def update_device(device: bridge.Device):
    raise NotImplementedError()


def add_active_device(device_id: str, token: str, timeout=None):
    if get_active_device(device_id):
        return False

    active_device = models.ActiveDevice(
        device_id=device_id,
        token=token,
        timeout=timeout
    )
    db.add(active_device)
    db.commit()
    return True


def set_timeout_active_device(device_id: str, timeout: Optional[datetime.datetime]) -> bool:
    device = db.query(models.ActiveDevice).filter(models.ActiveDevice.device_id == device_id).first()
    if not device:
        return False
    device.timeout = timeout
    db.commit()
    return True


def get_active_device(device_id: str) -> Optional[bridge.ActiveDevice]:
    device = db.query(models.ActiveDevice).filter(models.ActiveDevice.device_id == device_id).first()
    if not device:
        return None
    return bridge.ActiveDevice.from_orm(device)


def get_active_devices() -> List[bridge.ActiveDevice]:
    devices = db.query(models.ActiveDevice).all()
    return parse_obj_as(List[bridge.ActiveDevice], devices)


def delete_active_device(device_id: str) -> bool:
    device = db.query(models.ActiveDevice).filter(models.ActiveDevice.device_id == device_id).first()
    if not device:
        return False
    db.delete(device)
    db.commit()
    return True


def get_token(token: str) -> Optional[bridge.Token]:
    token = db.query(models.ActiveDevice).filter(models.ActiveDevice.token == token).first()
    if not token:
        return None
    return bridge.Token.from_orm(token)
