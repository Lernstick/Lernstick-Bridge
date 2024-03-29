"""
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer
"""

import uvicorn

from lernstick_bridge.config import config


def main() -> None:
    """
    Start bridge with IP and Port specified in the configuration.

    :return: None
    """
    uvicorn.run(
        "lernstick_bridge.main:app",
        host=str(config.ip),
        port=config.port,
        log_level=config.log_level,
    )


if __name__ == "__main__":
    main()
