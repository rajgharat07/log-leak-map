"""Webhook ingress — dumps the raw body (Authorization often rides along)."""

import logging

logger = logging.getLogger("webhooks")


def handle(request) -> None:
    logger.debug("payload: %s", request.body)
