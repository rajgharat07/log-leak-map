"""Benign startup log — must stay unflagged."""

import logging

logger = logging.getLogger("api")


def start() -> None:
    logger.info("Server started on port 8080")
    logger.info("ready to accept connections")
