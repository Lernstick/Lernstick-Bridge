'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
from fastapi import FastAPI, HTTPException
from typing import List

from lernstick_bridge.db import models, crud
from lernstick_bridge.schema import bridge
from lernstick_bridge.db.database import engine
from lernstick_bridge.config import get_db, config, cert_store
from lernstick_bridge.bridge import logic
from lernstick_bridge.keylime import ek

models.Base.metadata.create_all(bind=engine)
app = FastAPI()


@app.get("/devices", response_model=List[bridge.Device])
def list_devices():
    return crud.get_devices()


@app.post("/devices/", response_model=bridge.Device)
def create_device(device: bridge.DeviceCreate):
    db_device = crud.get_device(device.id)
    if db_device:
        raise HTTPException(status_code=400, detail="Device already in database")
    if config.validate_ek_registration:
        if not ek.validate_ek(device.ek_cert.encode("utf-8"), cert_store):
            raise HTTPException(status_code=400, detail="EK could not be validated against cert store")
    return crud.add_device(device)


@app.delete("/devices/{device_id}")
def delete_device(device_id: str):
    db_device = crud.get_device(device_id)
    if not db_device:
        raise HTTPException(status_code=400, detail="Device is not in the database")
    crud.delete_device(device_id)
    return "Ok" # TODO better response object


@app.put("/devices/{device_id}")
def update_device(device_id: str, device: bridge.Device):
    pass


@app.post("/devices/{device_id}/activate")
def activate_device(device_id: str):
    return logic.activate_device(device_id)


@app.get("/devices/{device_id}/status", response_model=bridge.DeviceStatus)
def device_status(device_id: str):
    # TODO retive also state if active
    device = crud.get_active_device(device_id)
    if device:
        return bridge.DeviceStatus(status="active", token=device.token)
    device_db = crud.get_device(device_id)
    if device_db:
        return bridge.DeviceStatus(status="inactive")

    raise HTTPException(status_code=400, detail="Device not active nor in the database")


@app.post("/devices/{device_id}/deactivate")
def deactivate_device(device_id: str):
    return logic.deactivate_device(device_id)


@app.post("/verify", response_model=bridge.Token)
def verify_token(token: str):
    token = crud.get_token(token)
    if not token:
        raise HTTPException(status_code=400, detail="Token does not belong to any device")
    return token


@app.on_event("shutdown")
def cleanup():
    # Remove all active devices
    for device in crud.get_active_devices():
        logic.deactivate_device(device.device_id)

    # Close database connection
    get_db().close()
