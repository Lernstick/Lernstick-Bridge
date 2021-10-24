'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from lernstick_bridge.config import config

_retries = Retry(
    total=config.retry_attempts,
    status_forcelist=[500, 502, 504]
)


class RetrySession(Session):
    """
    requests Session that retries on [500,502,504] automatically.
    Retry interval can be specified in the bridge configuration.
    """
    def __init__(self) -> None:
        super().__init__()
        adapter = HTTPAdapter(max_retries=_retries)
        self.mount("http://", adapter)
        self.mount("https://", adapter)
