"""Name classification and reconstructed log-line shapes."""

from __future__ import annotations

import re

from logleak.classes import (
    ENV_TOKENS,
    PII_TOKENS,
    PII_WEAK_TOKENS,
    REQUEST_TOKENS,
    SECRET_TOKENS,
)

_SPLIT = re.compile(r"[^a-z0-9]+")


def normalize_name(name: str) -> str:
    return name.strip().lower().replace("-", "_")


def name_parts(name: str) -> list[str]:
    n = normalize_name(name)
    parts = [p for p in _SPLIT.split(n) if p]
    # also keep dotted tail: user.email -> email, user
    if "." in n:
        parts.extend(n.split("."))
        parts.append(n)
    # camelCase split
    camel = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    parts.extend(p for p in normalize_name(camel).split("_") if p)
    # collapsed form api_key -> apikey
    collapsed = n.replace("_", "").replace(".", "")
    parts.append(collapsed)
    return list(dict.fromkeys(parts))


def is_secret_name(name: str) -> bool:
    n = normalize_name(name)
    if n in SECRET_TOKENS or n.replace(".", "_") in SECRET_TOKENS:
        return True
    parts = name_parts(name)
    collapsed = n.replace("_", "").replace(".", "")
    if collapsed in SECRET_TOKENS:
        return True
    # STRIPE_SECRET_KEY, AWS_SECRET_ACCESS_KEY, process.env.API_KEY
    if "secret" in parts or "password" in parts or "passwd" in parts or "credential" in parts:
        return True
    if "token" in parts or "jwt" in parts or "bearer" in parts:
        return True
    if ("key" in parts or "apikey" in collapsed) and any(
        p in {"api", "access", "private", "stripe", "aws", "auth", "client", "signing"}
        for p in parts
    ):
        return True
    if "authorization" in parts or "authheader" in collapsed:
        return True
    return False


def is_pii_name(name: str) -> bool:
    n = normalize_name(name)
    parts = name_parts(name)
    if n in PII_TOKENS or n in PII_WEAK_TOKENS:
        return True
    for tok in PII_TOKENS | PII_WEAK_TOKENS:
        if tok in parts or tok.replace("_", "") in {p.replace("_", "") for p in parts}:
            return True
    if n.endswith(".email") or n.endswith(".ssn") or n.endswith(".phone"):
        return True
    if "card" in parts and "discard" not in parts:
        return True
    return False


def is_request_dump_name(name: str) -> bool:
    n = normalize_name(name)
    if n in REQUEST_TOKENS:
        return True
    if n.endswith(".body") or n.endswith(".headers") or n.endswith(".cookies"):
        # request.body, req.body, event.body, webhook.body
        head = n.rsplit(".", 1)[0]
        if any(
            k in head
            for k in ("request", "req", "event", "webhook", "http", "incoming")
        ):
            return True
    if n in {"payload", "raw_payload", "rawbody", "raw_body"}:
        return True
    return False


def is_env_access(name: str) -> bool:
    n = normalize_name(name)
    if n in ENV_TOKENS:
        return True
    if n.startswith("process.env") or n.startswith("os.environ") or n.startswith("os.getenv"):
        return True
    return False


def is_exception_name(name: str) -> bool:
    n = normalize_name(name)
    tail = n.split(".")[-1]
    return tail in {"e", "err", "error", "exc", "exception", "tb", "traceback"} or n in {
        "traceback.format_exc",
        "traceback.print_exc",
        "sys.exc_info",
    }


def redact_shape(name: str) -> str:
    n = normalize_name(name)
    parts = name_parts(name)
    if is_env_access(name) or "key" in parts or "secret" in parts:
        if "stripe" in parts:
            return "sk_live_•••"
        if "aws" in parts:
            return "AKIA••••"
        return "••••"
    if "jwt" in parts or "token" in parts:
        return "eyJ•••"
    if "password" in parts or "passwd" in parts:
        return "••••"
    if "email" in parts or n.endswith(".email"):
        return "user@••••"
    if "card" in parts or "cvv" in parts or "pan" in parts:
        return "4242••••"
    if "ssn" in parts:
        return "***-**-••••"
    if "phone" in parts or "mobile" in parts:
        return "+1••••"
    if is_request_dump_name(name):
        if "header" in n:
            return "{Authorization: Bearer •••}"
        return "{…request dump…}"
    if is_exception_name(name):
        return "<exception>"
    return "•••"


def reconstruct_line(source: str, names: list[str]) -> str:
    """Replace identifiers in a log call with redacted shapes (keep string literals)."""
    out = " ".join(source.strip().split())
    if not names:
        return out
    ordered = sorted(set(names), key=len, reverse=True)

    for name in ordered:
        shape = redact_shape(name)
        out = out.replace("{" + name + "}", "{" + shape + "}")

    holes: list[str] = []

    def _stash(m: re.Match[str]) -> str:
        holes.append(m.group(0))
        return f"\x00{len(holes) - 1}\x00"

    # f-strings already had {name} rewritten; stash remaining quoted text.
    masked = re.sub(r"f?(['\"`])(?:\\.|(?!\1).)*\1", _stash, out)
    for name in ordered:
        shape = redact_shape(name)
        masked = re.sub(rf"\b{re.escape(name)}\b", shape, masked)

    def _unstash(m: re.Match[str]) -> str:
        return holes[int(m.group(1))]

    return re.sub(r"\x00(\d+)\x00", _unstash, masked)
