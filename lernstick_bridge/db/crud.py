'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''

from sqlalchemy.orm import Session
from pydantic import parse_obj_as
from typing import List

from lernstick_bridge.db import models
from lernstick_bridge.schema import bridge


def get_device(db: Session, device_id: str):
    device = db.query(models.Device).filter(models.Device.id == device_id).first()
    if not device:
        return None
    return bridge.Device.from_orm(device)


def get_devices(db: Session):
    devices = db.query(models.Device).all()
    return parse_obj_as(List[bridge.Device], devices)


def add_device(db: Session, device: bridge.Device):
    db_device = models.Device(**dict(device))
    db.add(db_device)
    db.commit()
    db.refresh(db_device)
    return db_device


def delete_device(db: Session, device_id: str):
    device = get_device(db, device_id)
    db.delete(device)
    db.commit()
    return True


def update_device(db: Session, device: bridge.Device):
    pass


def get_token(db: Session, token: str):
    pass


def add_token(db: Session, token: bridge.Token):
    pass


def delete_token(db: Session, token: str):
    pass
