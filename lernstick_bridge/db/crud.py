'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''

from pydantic import parse_obj_as
from typing import List

from lernstick_bridge.db import models
from lernstick_bridge.schema import bridge
from lernstick_bridge.db.database import get_db

db = get_db()


def get_device(device_id: str):
    device = db.query(models.Device).filter(models.Device.id == device_id).first()
    if not device:
        return None
    return bridge.Device.from_orm(device)


def get_devices():
    devices = db.query(models.Device).all()
    return parse_obj_as(List[bridge.Device], devices)


def add_device(device: bridge.Device):
    db_device = models.Device(**dict(device))
    db.add(db_device)
    db.commit()
    db.refresh(db_device)
    return db_device


def delete_device(device_id: str):
    device = get_device(device_id)
    db.delete(device)
    db.commit()
    return True


def update_device(device: bridge.Device):
    pass


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


def set_timeout_active_device(device_id: str, timeout):
    device = db.query(models.ActiveDevice).filter(models.ActiveDevice.device_id == device_id).first()
    if not device:
        return False
    device.timeout = timeout
    db.commit()
    return True


def get_active_device(device_id: str):
    device = db.query(models.ActiveDevice).filter(models.ActiveDevice.device_id == device_id).first()
    if not device:
        return None
    return device


def get_active_devices() -> List[bridge.ActiveDevice]:
    devices = db.query(models.ActiveDevice).all()
    return parse_obj_as(List[bridge.ActiveDevice], devices)


def delete_active_device(device_id: str):
    device = db.query(models.ActiveDevice).filter(models.ActiveDevice.device_id == device_id).first()
    if not device:
        return False
    db.delete(device)
    db.commit()
    return True


def get_token(token: str):
    token = db.query(models.ActiveDevice).filter(models.ActiveDevice.token == token).first()
    if not token:
        return False
    return bridge.Token.from_orm(token)
