'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
'''
import os.path
from tempfile import TemporaryDirectory
from typing import Any, List, Optional, Tuple, Union

import requests
from fastapi import WebSocket
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
    _tmp_dir: Optional[TemporaryDirectory]  # type: ignore

    def __init__(self, verify_cert: Optional[str] = None, verify: Optional[Union[bool, str]] = None, cert: Optional[Tuple[str, str]] = None,
                 ignore_hostname: bool = False) -> None:
        super().__init__()
        self._tmp_dir = None
        self.verify_cert = verify_cert
        if verify is not None:
            self.verify = verify
        if cert is not None:
            self.cert = cert

        adapter = HTTPAdapter(max_retries=_retries)
        if ignore_hostname:
            adapter = HostNameIgnoreAdapter(max_retries=_retries)
        self.mount("http://", adapter)
        self.mount("https://", adapter)

    def __enter__(self) -> Any:
        # This is a hacky workaround for SslContext not being able to load certificates directly
        if self.verify_cert:
            self._tmp_dir = TemporaryDirectory(prefix="lernstick-")
            cert_path = os.path.join(self._tmp_dir.name, "cert.crt")
            with open(cert_path, "w", encoding="utf-8") as file:
                file.write(self.verify_cert)
            self.verify = cert_path
        return self

    def __exit__(self, *_: Any) -> None:
        if self._tmp_dir is not None:
            self._tmp_dir.cleanup()


class WebsocketConnectionManager:
    """
    Simple websocket connection manager.
    """
    active_connections: List[WebSocket]

    def __init__(self) -> None:
        self.active_connections = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str) -> None:
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass


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
