'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
from typing import List

from fastapi import HTTPException, APIRouter

from lernstick_bridge.bridge import logic
from lernstick_bridge.config import config, cert_store
from lernstick_bridge.db import crud
from lernstick_bridge.keylime import ek
from lernstick_bridge.schema import bridge

router = APIRouter()


@router.get("/devices", response_model=List[bridge.Device], tags=["device_management"])
def list_devices():
    return crud.get_devices()


@router.post("/devices/", response_model=bridge.Device, tags=["device_management"])
def create_device(device: bridge.DeviceCreate):
    db_device = crud.get_device(device.id)
    if db_device:
        raise HTTPException(status_code=400, detail="Device already in database")
    if config.validate_ek_registration:
        if not ek.validate_ek(device.ek_cert.encode("utf-8"), cert_store):
            raise HTTPException(status_code=400, detail="EK could not be validated against cert store")
    return crud.add_device(device)


@router.delete("/devices/{device_id}", tags=["device_management"])
def delete_device(device_id: str):
    db_device = crud.get_device(device_id)
    if not db_device:
        raise HTTPException(status_code=400, detail="Device is not in the database")
    crud.delete_device(device_id)
    return "Ok" # TODO better response object


@router.put("/devices/{device_id}", tags=["device_management"])
def update_device(device_id: str, device: bridge.Device):
    pass


@router.post("/devices/{device_id}/activate", tags=["device_attestation"])
def activate_device(device_id: str):
    return logic.activate_device(device_id)


@router.get("/devices/{device_id}/status", response_model=bridge.DeviceStatus, tags=["device_attestation"])
def device_status(device_id: str):
    # TODO retive also state if active
    device = crud.get_active_device(device_id)
    if device:
        status = "active"
        if config.mode == "relaxed" and device.timeout is not None:
            status = "auto-active"
        return bridge.DeviceStatus(status=status, token=device.token)
    device_db = crud.get_device(device_id)
    if device_db:
        return bridge.DeviceStatus(status="inactive")

    raise HTTPException(status_code=400, detail="Device not active nor in the database")


@router.post("/devices/{device_id}/deactivate", tags=["device_attestation"])
def deactivate_device(device_id: str):
    return logic.deactivate_device(device_id)


@router.post("/verify", response_model=bridge.Token, tags=["device_attestation"])
def verify_token(token: str):
    token = crud.get_token(token)
    if not token:
        raise HTTPException(status_code=400, detail="Token does not belong to any device")
    return token