"""Background worker — emails + exception text go to the error log."""

import logging

log = logging.getLogger("worker")


def process(user) -> None:
    try:
        raise RuntimeError("payment gateway timeout")
    except Exception as e:
        logging.error(f"failed for {user.email}: {e}")
