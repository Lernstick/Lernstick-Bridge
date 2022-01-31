'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''

from typing import Any

import requests
from requests import Session
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager  # pylint: disable=import-error
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
    def __init__(self, ignore_hostname: bool = False) -> None:
        super().__init__()
        adapter = HTTPAdapter(max_retries=_retries)
        if ignore_hostname:
            adapter = HostNameIgnoreAdapter(max_retries=_retries)
        self.mount("http://", adapter)
        self.mount("https://", adapter)


class HostNameIgnoreAdapter(HTTPAdapter):
    """
    This HTTPAdapter just ignores the Hostname validation.
    It is required because in most cases we don't know the hostname during certificate generation.
    """

    def init_poolmanager(self, connections: Any, maxsize: int, block: bool = requests.adapters.DEFAULT_POOLBLOCK,
                         **pool_kwargs: Any) -> None:
        """Initializes a urllib3 PoolManager with assert_hostname set to False.

        This method should not be called from user code, and is only
        exposed for use when subclassing the
        :class:`HTTPAdapter <requests.adapters.HTTPAdapter>`.

        :param connections: The number of urllib3 connection pools to cache.
        :param maxsize: The maximum number of connections to save in the pool.
        :param block: Block when no free connections are available.
        :param pool_kwargs: Extra keyword arguments used to initialize the Pool Manager.
        """
        # save these values for pickling
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block

        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       strict=True,
                                       assert_hostname=False, **pool_kwargs)
