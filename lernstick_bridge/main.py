'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
from fastapi import Depends, FastAPI, HTTPException
from typing import List
from sqlalchemy.orm import Session

from lernstick_bridge.db import models, crud
from lernstick_bridge.schema import bridge
from lernstick_bridge.db.database import engine
from lernstick_bridge.bridge.config import get_db

models.Base.metadata.create_all(bind=engine) # TODO this line should probably not be here
app = FastAPI()

@app.get("/")
def test():
    agent = bridge.Agent("D432FBB3-D2F1-4A97-9EF7-75BD81C00000", strict=False)
    print(agent.deploy_token())
    return agent.add_to_verifier()


@app.get("/devices", response_model=List[bridge.Device])
def list_devices(db: Session = Depends(get_db)):
    return crud.get_devices(db)


@app.post("/devices/", response_model=bridge.Device)
def create_device(device: bridge.Device, db: Session = Depends(get_db)):
    db_device = crud.get_device(db, device.id)
    if db_device:
        raise HTTPException(status_code=400, detail="Device already in database")
    return crud.add_device(db, device)


@app.delete("/devices/{device_id}")
def delete_device(device_id: str, db: Session = Depends((get_db))):
    db_device = crud.get_device(db, device_id)
    if not db_device:
        raise HTTPException(status_code=400, detail="Device is not in the database")
    crud.delete_device(db, device_id)
    return "Ok" # TODO better response object


@app.put("/devices/{device_id}")
def update_device(device_id: str, device: bridge.Device, db: Session = Depends(get_db)):
    pass


@app.post("/verfiy", response_model=bridge.Token)
def verfiy_token(token: str, db: Session = Depends(get_db)):
    token = crud.get_token(db, token)
    if not token:
        raise HTTPException(status_code=400, detail="Token does not belong to any device")
    return token
