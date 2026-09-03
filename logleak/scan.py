"""Detect log sinks that interpolate secrets, PII, request dumps, or leftovers."""

from __future__ import annotations

import ast
import re
from logleak.classes import (
    CLASS_EXCEPTION,
    CLASS_PII,
    CLASS_REQUEST,
    CLASS_SECRET,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    Finding,
    LOG_ATTRS,
    LOGGER_NAMES,
    SEVERITY_CONFIRMED,
    SEVERITY_SENSITIVE,
    SEVERITY_SUSPICIOUS,
)
from logleak.patterns import (
    is_env_access,
    is_exception_name,
    is_pii_name,
    is_request_dump_name,
    is_secret_name,
    reconstruct_line,
)

_REC_SECRET = (
    "Do not interpolate this value into logs. Log a stable id instead, "
    "and keep the secret in a vault / env that never reaches the log sink."
)
_REC_PII = (
    "Log a user/account id, not the identifier itself. Mask email/card/phone "
    "if you must keep a forensic breadcrumb."
)
_REC_REQ = (
    "Never dump request.body / headers wholesale. Log a request id and the "
    "route. Headers often carry Authorization."
)
_REC_EXC = (
    "Treat `{e}` / `err` in a log call as untrusted output: exception strings "
    "can include request fragments. Log the exception type plus a stable id."
)
_REC_DBG = (
    "Delete leftover print / console.log / .debug calls that pass sensitive "
    "names. Static analysis cannot see the destination pipeline — only the sink."
)


def _attr_chain(node: ast.AST) -> str:
    parts: list[str] = []
    cur: ast.AST | None = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    elif isinstance(cur, ast.Call):
        inner = _attr_chain(cur.func)
        if inner:
            parts.append(inner)
    elif isinstance(cur, ast.Subscript):
        base = _attr_chain(cur.value)
        sl = cur.slice
        if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
            parts.append(sl.value)
            parts.append(base)
            return ".".join(reversed(parts))
        if base:
            parts.append(base)
    return ".".join(reversed(parts))


def _collect_names(node: ast.AST) -> list[str]:
    names: list[str] = []

    class V(ast.NodeVisitor):
        def visit_Name(self, n: ast.Name) -> None:
            names.append(n.id)

        def visit_Attribute(self, n: ast.Attribute) -> None:
            chain = _attr_chain(n)
            if chain:
                names.append(chain)
            self.generic_visit(n)

        def visit_Subscript(self, n: ast.Subscript) -> None:
            chain = _attr_chain(n)
            if chain:
                names.append(chain)
            self.generic_visit(n)

        def visit_JoinedStr(self, n: ast.JoinedStr) -> None:
            for v in n.values:
                if isinstance(v, ast.FormattedValue):
                    self.visit(v.value)

        def visit_Call(self, n: ast.Call) -> None:
            fn = _attr_chain(n.func)
            if fn in {"os.getenv", "os.environ.get", "os.environ"}:
                names.append(fn)
                for a in n.args:
                    if isinstance(a, ast.Constant) and isinstance(a.value, str):
                        names.append(a.value)
            self.generic_visit(n)

    V().visit(node)
    # unique, stable
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _is_log_sink(node: ast.Call) -> tuple[bool, str, bool]:
    """Return (is_sink, sink_name, is_exception_sink)."""
    func = node.func
    if isinstance(func, ast.Name) and func.id in {"print", "pprint"}:
        return True, func.id, False
    chain = _attr_chain(func)
    if not chain:
        return False, "", False
    low = chain.lower()
    tail = chain.split(".")[-1].lower()
    head = chain.split(".")[0].lower()

    if chain in {"traceback.print_exc", "traceback.print_exception", "sys.stdout.write", "sys.stderr.write"}:
        return True, chain, "print_exc" in chain or "print_exception" in chain

    if tail in LOG_ATTRS and (
        head in LOGGER_NAMES
        or "log" in head
        or "logger" in low
        or low.startswith("logging.")
        or low.startswith("console.")
    ):
        return True, chain, tail == "exception"

    # logger = getLogger(); logger.info(...)
    if tail in LOG_ATTRS and isinstance(func, ast.Attribute):
        return True, chain, tail == "exception"

    return False, chain, False


def _looks_debug_leftover(source: str, sink: str) -> bool:
    s = source.lower()
    if "debug" in s or "todo" in s or "leftover" in s or "tmp" in s:
        return True
    if sink in {"print", "pprint"}:
        return True
    if sink.lower().endswith(".debug") or sink.lower().startswith("console."):
        return True
    return False


def _classify(names: list[str], sink: str, source: str, is_exc_sink: bool) -> Finding | None:
    """One sink call → one finding. DEBUG is a modifier, not a class."""
    secrets = [n for n in names if is_secret_name(n) or is_env_access(n)]
    envish = [n for n in names if is_env_access(n)]
    pii = [n for n in names if is_pii_name(n)]
    reqs = [n for n in names if is_request_dump_name(n)]
    excs = [n for n in names if is_exception_name(n)]
    has_exc = is_exc_sink or bool(excs)

    signals: list[tuple[str, str, str, str]] = []
    if secrets or envish:
        hit = secrets or envish
        signals.append(
            (
                CLASS_SECRET,
                SEVERITY_CONFIRMED,
                CONFIDENCE_HIGH,
                f"secret/env/token-like name(s) are arguments to this sink: {', '.join(hit[:6])}",
            )
        )
    if pii:
        signals.append(
            (
                CLASS_PII,
                SEVERITY_SENSITIVE,
                CONFIDENCE_HIGH,
                f"PII-shaped identifier(s) are arguments to this sink: {', '.join(pii[:6])}",
            )
        )
    if reqs:
        signals.append(
            (
                CLASS_REQUEST,
                SEVERITY_SUSPICIOUS,
                CONFIDENCE_MEDIUM,
                f"request/payload object(s) dumped at this sink: {', '.join(reqs[:6])} "
                "(not proven secret)",
            )
        )
    if has_exc:
        signals.append(
            (
                CLASS_EXCEPTION,
                SEVERITY_SUSPICIOUS,
                CONFIDENCE_MEDIUM,
                "exception object/string is an argument to this sink (not proven secret)",
            )
        )
    if not signals:
        return None

    rank = {
        CLASS_SECRET: 0,
        CLASS_PII: 1,
        CLASS_REQUEST: 2,
        CLASS_EXCEPTION: 3,
    }
    signals.sort(key=lambda s: rank.get(s[0], 9))
    primary_class, severity, confidence, evidence = signals[0]
    also = [s[0] for s in signals[1:]]
    extra_why = [s[3] for s in signals[1:]]
    if extra_why:
        evidence = evidence + "; " + "; ".join(extra_why)

    modifiers: list[str] = []
    if _looks_debug_leftover(source, sink):
        modifiers.append("DEBUG")
        evidence = evidence + f"; leftover debug-style sink `{sink}`"

    rec = _recommendation(primary_class)
    if "DEBUG" in modifiers:
        rec = rec + " " + _REC_DBG

    return Finding(
        leak_class=primary_class,
        path="",
        line=0,
        col=0,
        severity=severity,
        confidence=confidence,
        sink=sink,
        source=source[:400],
        leaked_names=[],
        reconstructed="",
        evidence=evidence,
        recommendation=rec,
        modifiers=modifiers,
        also=also,
    )


def _recommendation(leak_class: str) -> str:
    return {
        CLASS_SECRET: _REC_SECRET,
        CLASS_PII: _REC_PII,
        CLASS_REQUEST: _REC_REQ,
        CLASS_EXCEPTION: _REC_EXC,
    }.get(leak_class, _REC_SECRET)


def _finish(finding: Finding, path: str, line: int, col: int, leaked: list[str], recon: str) -> Finding:
    finding.path = path
    finding.line = line
    finding.col = col
    finding.leaked_names = leaked
    finding.reconstructed = recon[:400]
    finding.sink = finding.sink
    finding.source = finding.source[:400]
    return finding


def scan_python(path: str, source: str) -> list[Finding]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return scan_js_like(path, source)  # fallback line scan

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        is_sink, sink, is_exc = _is_log_sink(node)
        if not is_sink:
            continue
        names = _collect_names(node)
        # drop the sink itself
        names = [n for n in names if n.lower() not in LOGGER_NAMES and n.split(".")[-1].lower() not in LOG_ATTRS]
        snippet = ast.get_source_segment(source, node) or sink
        snippet = " ".join(snippet.strip().split())
        hit = _classify(names, sink, snippet, is_exc)
        if hit is None:
            continue
        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0) + 1
        leaked = [
            n
            for n in names
            if is_secret_name(n)
            or is_pii_name(n)
            or is_request_dump_name(n)
            or is_env_access(n)
            or is_exception_name(n)
        ]
        recon = reconstruct_line(snippet, leaked)
        findings.append(_finish(hit, path, line, col, leaked, recon))
    return findings


_JS_SINK = re.compile(
    r"""(?P<sink>
            console\.(?:log|debug|info|warn|error|trace)
          | logger\.(?:log|debug|info|warn|error|trace|fatal|verbose)
          | log\.(?:debug|info|warn|error|trace|fatal)
          | winston\.(?:debug|info|warn|error)
          | pino\(\)[^\n]{0,40}\.(?:debug|info|warn|error)
        )\s*\((?P<args>[^;\n]{0,500})\)""",
    re.VERBOSE | re.IGNORECASE,
)

_JS_NAME = re.compile(
    r"\b("
    r"process\.env(?:\.[A-Za-z0-9_]+|\[.?\w+.?\])?"
    r"|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+"
    r"|[A-Za-z_][A-Za-z0-9_]*"
    r")\b"
)


def _js_arg_names(args: str) -> list[str]:
    names: list[str] = []
    stripped = re.sub(r"(['\"`])(?:\\.|(?!\1).)*\1", " ", args)
    for m in _JS_NAME.finditer(stripped):
        token = m.group(1)
        if token in {
            "true",
            "false",
            "null",
            "undefined",
            "this",
            "new",
            "const",
            "let",
            "var",
            "JSON",
            "stringify",
            "console",
            "logger",
            "log",
        }:
            continue
        names.append(token)
    return names


def scan_js_like(path: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
            continue
        for m in _JS_SINK.finditer(line):
            sink = m.group("sink")
            args = m.group("args") or ""
            names = _js_arg_names(args)
            snippet = line.strip()
            is_exc = "error" in sink.lower() and any(is_exception_name(n) for n in names)
            hit = _classify(names, sink, snippet, is_exc)
            if hit is None:
                continue
            leaked = [
                n
                for n in names
                if is_secret_name(n)
                or is_pii_name(n)
                or is_request_dump_name(n)
                or is_env_access(n)
                or is_exception_name(n)
            ]
            recon = reconstruct_line(snippet, leaked)
            col = m.start() + 1
            findings.append(_finish(hit, path, i, col, leaked, recon))
    return findings


_GO_SINK = re.compile(
    r"""(?P<sink>log\.(?:Print(?:ln|f)?|Fatal(?:ln|f)?|Panic(?:ln|f)?)|fmt\.(?:Print(?:ln|f)?))\s*\((?P<args>[^;\n]{0,400})\)""",
    re.VERBOSE,
)


def scan_go_like(path: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(source.splitlines(), start=1):
        for m in _GO_SINK.finditer(line):
            sink = m.group("sink")
            names = _js_arg_names(m.group("args") or "")
            snippet = line.strip()
            hit = _classify(names, sink, snippet, False)
            if hit is None:
                continue
            leaked = [
                n
                for n in names
                if is_secret_name(n) or is_pii_name(n) or is_request_dump_name(n) or is_env_access(n)
            ]
            recon = reconstruct_line(snippet, leaked)
            findings.append(_finish(hit, path, i, m.start() + 1, leaked, recon))
    return findings


def scan_text(path: str, source: str) -> list[Finding]:
    lower = path.lower()
    if lower.endswith(".py"):
        return scan_python(path, source)
    if lower.endswith((".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs")):
        return scan_js_like(path, source)
    if lower.endswith(".go"):
        return scan_go_like(path, source)
    if lower.endswith((".rb", ".php", ".java", ".kt")):
        return scan_js_like(path, source)
    return []
