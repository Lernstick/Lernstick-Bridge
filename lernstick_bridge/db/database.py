'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''

from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

from lernstick_bridge.config import config

SQLALCHEMY_DATABASE_URL = config.db_url

_connect_args = {}
if config.db_url.startswith("sqlite://"):
    _connect_args["check_same_thread"] = False

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,
    connect_args=_connect_args
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Iterator[Session]:
    """
    Get DB Session for API routes.

    :return: DB Session that gets closed after use
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
