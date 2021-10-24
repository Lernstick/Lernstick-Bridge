'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
import time

import requests
from fastapi import FastAPI

from lernstick_bridge.bridge import logic
from lernstick_bridge.bridge_logger import logger
from lernstick_bridge.config import REGISTRAR_URL, config
from lernstick_bridge.db import crud
from lernstick_bridge.db.database import Base, db, engine
from lernstick_bridge.routers import agents, keylime

Base.metadata.create_all(bind=engine)

tags_metadata = [
    {
        "name": "agent_attestation",
        "description": "Add and remove agents from Remote Attestation and verify their identity."
    },
    {
        "name": "agent_management",
        "description": "Store and manage agents specific information for Remote Attestation. Only used in strict mode."
    },
    {
        "name": "keylime",
        "description": "API entrypoint that is called by Keylime. "
                       "See '/revocation' callbacks for message format that is send to the exam system."
    },
]

app = FastAPI(
    title="Lernstick Bridge",
    version="0.0.1",
    description="Simplify interactions with Keylime for Remote Attestation",
    openapi_tags=tags_metadata
)

app.include_router(agents.router)
app.include_router(keylime.router)


@app.on_event("shutdown")
def cleanup() -> None:
    """
    Deactive all active agents on shutdown.

    :return: None
    """
    logger.info("Starting shutdown actions")
    # Remove all active agents
    logger.info("Remove all currently active agents.")
    for active_agents in crud.get_active_agents():
        logic.deactivate_agent(active_agents.agent_id)

    # Close database connection
    logger.info("Close database connection.")
    db.close()


@app.on_event("startup")
async def startup() -> None:
    """
    - Add warnings if EK validation is disabled or webhook is not configured.
    - Start loop for relaxed mode.

    :return: None
    """
    logger.info(f"Started in {config.mode} mode.")
    if not config.validate_ek_registration:
        logger.warning("EK validation is disabled!")
    if not config.revocation_webhook:
        logger.warning("No revocation webhook is specified. Systems will not be notified when a revocation occurs!")

    if config.mode == "relaxed":
        # Wait for registrar to come available
        while True:
            try:
                requests.get(REGISTRAR_URL, verify=False, cert=(config.registrar.tls_cert, config.registrar.tls_priv_key))
                break
            except requests.exceptions.ConnectionError:
                time.sleep(1)

        logger.info("Starting loop")
        await logic.relaxed_loop()
