"""Tiny payments API — leaks the Stripe key and a card into info logs."""

import logging
import os

logger = logging.getLogger("payments")

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "sk_live_demo")


def charge(card: str, amount: int) -> None:
    # Looks harmless in code review. In Datadog it is a live secret dump.
    logger.info(f"charging {card} key {STRIPE_SECRET_KEY}")
