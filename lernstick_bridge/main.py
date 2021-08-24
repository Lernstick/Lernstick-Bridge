'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
import time

import requests
from fastapi import FastAPI

from lernstick_bridge.db import models, crud
from lernstick_bridge.db.database import engine, db
from lernstick_bridge.config import config, REGISTRAR_URL
from lernstick_bridge.bridge import logic
from lernstick_bridge.bridge_logger import logger
from lernstick_bridge.routers import keylime, devices

models.Base.metadata.create_all(bind=engine)

tags_metadata = [
    {
        "name": "device_attestation",
        "description": "Add and remove devices from Remote Attestation and verify their identity."
    },
    {
        "name": "device_management",
        "description": "Store and manage device specific information for Remote Attestation. Only used in strict mode."
    },
    {
        "name": "keylime",
        "description": "API entrypoint that is called by Keylime."
    },
]

app = FastAPI(
    title="Lernstick Bridge",
    version="0.0.1",
    description="Simplify interactions with Keylime for Remote Attestation",
    openapi_tags=tags_metadata
)

app.include_router(devices.router)
app.include_router(keylime.router)


@app.on_event("shutdown")
def cleanup():
    logger.info("Starting shutdown actions")
    # Remove all active devices
    logger.info("Remove all currently active devices.")
    for device in crud.get_active_devices():
        logic.deactivate_device(device.device_id)

    # Close database connection
    logger.info("Close database connection.")
    db.close()


@app.on_event("startup")
async def startup():
    logger.info(f"Started in {config.mode} mode.")
    if not config.validate_ek_registration:
        logger.warn("EK validation is disabled!")

    if config.mode == "relaxed":
        # Wait for registrar to come available
        while True:
            try:
                requests.get(REGISTRAR_URL, verify=False, cert=(config.registrar.tls_cert, config.registrar.tls_priv_key))
                break
            except requests.exceptions.ConnectionError as e:
                time.sleep(1)
                pass
        logger.info("Starting loop")
        await logic.relaxed_loop()
