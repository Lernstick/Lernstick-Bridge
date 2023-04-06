'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
import time

import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from lernstick_bridge.bridge import logic
from lernstick_bridge.bridge_logger import logger
from lernstick_bridge.config import REGISTRAR_URL, VERIFIER_URL, config
from lernstick_bridge.db import crud
from lernstick_bridge.db.database import Base, SessionLocal, engine
from lernstick_bridge.routers import agents, keylime
from lernstick_bridge.utils import RetrySession

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

if config.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"]
    )


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
    with SessionLocal() as db:
        keylime_policy = crud.get_active_keylime_policy(db)
    if keylime_policy is None:
        logger.warning("No Keylime policy is currently active!")
    else:
        logger.info("Current active Keylime policy is %s", keylime_policy.policy_id)

    # Wait for registrar and verifier to come available
    session = RetrySession(ignore_hostname=True)
    session.cert = (config.registrar.tls_cert, config.registrar.tls_priv_key)
    session.verify = config.registrar.ca_cert
    while True:
        try:
            session.get(REGISTRAR_URL)
            session.get(VERIFIER_URL)
            break
        except requests.exceptions.ConnectionError:
            time.sleep(1)

    logger.info("Remove old active agents.")
    db = SessionLocal()
    for active_agents in crud.get_active_agents(db):
        logic.deactivate_agent(db, active_agents.agent_id)
    db.close()

    if config.mode == "relaxed":
        logger.info("Starting loop")
        await logic.relaxed_loop()
