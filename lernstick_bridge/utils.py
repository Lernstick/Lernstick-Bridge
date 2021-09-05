'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
from urllib3.util import Retry
from requests import Session
from requests.adapters import HTTPAdapter

from lernstick_bridge.config import config


_retries = Retry(
    total=config.retry_attempts,
    status_forcelist=[500, 502, 504]
)


class RetrySession(Session):
    def __init__(self) -> None:
        super().__init__()
        adapter = HTTPAdapter(max_retries=_retries)
        self.mount("http://", adapter)
        self.mount("https://", adapter)
