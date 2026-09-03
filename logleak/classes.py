"""Leak classes, name tables, Finding model."""

from __future__ import annotations

from dataclasses import dataclass, field

CLASS_SECRET = "SECRET-IN-LOG"
CLASS_PII = "PII-IN-LOG"
CLASS_REQUEST = "REQUEST-DUMP"
CLASS_EXCEPTION = "EXCEPTION-LEAK"

SEVERITY_CONFIRMED = "CONFIRMED SINK"
SEVERITY_SENSITIVE = "SENSITIVE"
SEVERITY_SUSPICIOUS = "SUSPICIOUS"
SEVERITY_NEEDS_REVIEW = "NEEDS-REVIEW"

CONFIDENCE_HIGH = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW = "LOW"

# Identifier fragments that mean "this value is a secret"
SECRET_TOKENS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "secretkey",
        "api_key",
        "apikey",
        "api-key",
        "access_key",
        "accesskey",
        "private_key",
        "privatekey",
        "token",
        "jwt",
        "bearer",
        "authorization",
        "auth_header",
        "credential",
        "credentials",
        "client_secret",
        "clientsecret",
        "refresh_token",
        "session_key",
        "session_secret",
        "signing_key",
        "stripe_secret",
        "stripe_key",
        "aws_secret",
        "aws_key",
        "sk_live",
        "sk_test",
        "id_token",
        "access_token",
        "auth_token",
    }
)

# Identifier fragments that mean PII
PII_TOKENS: frozenset[str] = frozenset(
    {
        "email",
        "e_mail",
        "mail",
        "ssn",
        "social_security",
        "phone",
        "phonenumber",
        "mobile",
        "credit_card",
        "card_number",
        "cardnumber",
        "pan",
        "cvv",
        "cvc",
        "passport",
        "national_id",
        "dob",
        "date_of_birth",
        "home_address",
        "street_address",
    }
)

# Extra PII that is still sensitive when logged as a whole value
PII_WEAK_TOKENS: frozenset[str] = frozenset(
    {
        "card",
        "cc",
        "ssn",
    }
)

REQUEST_TOKENS: frozenset[str] = frozenset(
    {
        "request.body",
        "request.json",
        "request.data",
        "request.headers",
        "request.cookies",
        "request.raw_body",
        "req.body",
        "req.headers",
        "req.cookies",
        "req.rawbody",
        "event.body",
        "event.headers",
        "payload",
        "raw_body",
        "rawbody",
        "http_body",
    }
)

ENV_TOKENS: frozenset[str] = frozenset(
    {
        "os.environ",
        "os.getenv",
        "process.env",
        "os.environ.get",
        "dotenv",
    }
)

LOG_ATTRS: frozenset[str] = frozenset(
    {
        "debug",
        "info",
        "warning",
        "warn",
        "error",
        "critical",
        "exception",
        "fatal",
        "trace",
        "log",
        "verbose",
        "silly",
    }
)

LOGGER_NAMES: frozenset[str] = frozenset(
    {
        "log",
        "logger",
        "logging",
        "loguru",
        "console",
        "syslog",
        "winston",
        "pino",
        "bunyan",
        "log4js",
        "nlog",
        "_log",
        "applog",
        "app_log",
    }
)

SOURCE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".mjs",
        ".cjs",
        ".go",
        ".rb",
        ".java",
        ".kt",
        ".php",
    }
)

SKIP_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".bzr",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "venv",
        ".idea",
        ".vscode",
        "dist",
        "build",
        "target",
        "coverage",
        ".next",
        ".nuxt",
        ".turbo",
        ".cache",
    }
)

DEPS_DIR_NAMES: frozenset[str] = frozenset(
    {
        "node_modules",
        "site-packages",
        "vendor",
        ".pnpm",
        "bower_components",
    }
)


@dataclass
class Finding:
    leak_class: str
    path: str
    line: int
    col: int
    severity: str
    confidence: str
    sink: str
    source: str
    leaked_names: list[str] = field(default_factory=list)
    reconstructed: str = ""
    evidence: str = ""
    recommendation: str = ""
    modifiers: list[str] = field(default_factory=list)
    also: list[str] = field(default_factory=list)


@dataclass
class FileStatus:
    path: str
    status: str
    reason: str = ""
    findings: list[Finding] = field(default_factory=list)
