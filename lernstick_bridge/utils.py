"""
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
"""
import enum
import os.path
from tempfile import TemporaryDirectory
from typing import Any, List, Optional, Tuple, Union

import requests
from redis.asyncio import ConnectionPool, Redis
from requests import Session
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager  # pylint: disable=import-error
from urllib3.util import Retry

from lernstick_bridge.config import config

_retries = Retry(total=config.retry_attempts, status_forcelist=[500, 502, 504])


class RetrySession(Session):
    """
    requests Session that retries on [500,502,504] automatically.
    Retry interval can be specified in the bridge configuration.
    """

    _tmp_dir: Optional[TemporaryDirectory]  # type: ignore

    def __init__(
        self,
        verify_cert: Optional[str] = None,
        verify: Optional[Union[bool, str]] = None,
        cert: Optional[Tuple[str, str]] = None,
        ignore_hostname: bool = False,
    ) -> None:
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


def create_redis_pool(host: str, port: int) -> ConnectionPool:
    """
    Creates a new Redis pool and sets the option, so that messages are decoded
    :param host: Redis host IP
    :param port: Redis host port
    :return: New ConnectionPool
    """
    return ConnectionPool(
        host=host,
        port=port,
        db=0,
        decode_responses=True,
    )


class RedisStream:
    """
    Simple stream m -> n implementation using Redis
    """

    redis_instance: Redis  # type:ignore[type-arg]
    stream_key: str
    max_messages: Optional[int]
    _last_id: Optional[str]

    def __init__(
        self,
        stream_key: str,
        connection_pool: ConnectionPool,
        max_messages: Optional[int] = None,
    ):
        """
        Constructs a new RedisStream.

        :param stream_key: the key where the messages are either added or read
        :param connection_pool: a Redis connection pool
        :param max_messages: the maximal amount of messages that should be in the stream. Trim is implemented in the add function.
        """
        self.redis_instance = Redis(connection_pool=connection_pool)
        self.stream_key = stream_key
        self._last_id = None
        self.max_messages = max_messages

    async def add(self, data: str) -> None:
        """
        Adds data to the stream. Trims stream data if max_messages is not None
        """
        # TODO: verify efficiency of calling trim every time
        if self.max_messages is not None:
            await self.redis_instance.xtrim(self.stream_key, self.max_messages)
        await self.redis_instance.xadd(self.stream_key, {"data": data})

    async def get(self, block: Optional[int] = None) -> List[str]:
        """
        Gets the data from the stream. Only messages are considered after the first time that get was called.

        :param block: How many ms this function should block. Use 0 to block until next message
        :return: List of the data from the stream
        """
        last_id = self._last_id if self._last_id else "$"
        data = await self.redis_instance.xread({self.stream_key: last_id}, block=block)
        if len(data) == 0:
            return []
        new_items = data[0][1]
        self._last_id = new_items[-1][0]
        result_list = []
        for _, item in new_items:
            result_list.append(item["data"])
        return result_list

    async def close(self) -> None:
        """
        Closes the connection
        """
        await self.redis_instance.close()


class HostNameIgnoreAdapter(HTTPAdapter):
    """
    This HTTPAdapter just ignores the Hostname validation.
    It is required because in most cases we don't know the hostname during certificate generation.
    """

    def init_poolmanager(
        self,
        connections: Any,
        maxsize: int,
        block: bool = requests.adapters.DEFAULT_POOLBLOCK,
        **pool_kwargs: Any,
    ) -> None:
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

        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            strict=True,
            assert_hostname=False,
            **pool_kwargs,
        )


class Flag(enum.Enum):
    """
    Flag that is used by the SQL layer to implement exclusive flag entries.
    """

    SET = True
