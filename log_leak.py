#!/usr/bin/env python3
"""Log Leak Map — CLI entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from logleak.classes import (
    FileStatus,
    SEVERITY_CONFIRMED,
    SEVERITY_SENSITIVE,
    SEVERITY_SUSPICIOUS,
)
from logleak.discover import discover_files, read_text_safe
from logleak.report import Report, render_markdown, render_text
from logleak.scan import scan_text


def run_scan(
    repo_path: str,
    *,
    include_deps: bool = False,
    scope: str | None = None,
    max_bytes: int = 1_000_000,
    output_format: str = "md",
) -> tuple[Report, str]:
    root = Path(repo_path).resolve()
    candidates = discover_files(
        root,
        include_deps=include_deps,
        scope=scope,
    )

    findings = []
    statuses: list[FileStatus] = []
    scanned = skipped = unavailable = 0

    for abs_path, rel in candidates:
        content, reason = read_text_safe(abs_path, max_bytes=max_bytes)
        if content is None:
            status = "SKIPPED" if reason.startswith("SKIPPED") else "UNAVAILABLE"
            statuses.append(FileStatus(path=rel, status=status, reason=reason))
            if status == "SKIPPED":
                skipped += 1
            else:
                unavailable += 1
            continue
        try:
            file_findings = scan_text(rel, content)
        except Exception as exc:  # never crash a whole run on one file
            statuses.append(
                FileStatus(
                    path=rel,
                    status="UNAVAILABLE",
                    reason=f"UNAVAILABLE — scan error: {exc}",
                )
            )
            unavailable += 1
            continue
        statuses.append(FileStatus(path=rel, status="SCANNED", findings=file_findings))
        findings.extend(file_findings)
        scanned += 1

    findings.sort(key=lambda f: (f.path, f.line, f.col, f.leak_class))

    report = Report(
        findings=findings,
        file_statuses=statuses,
        repo_path=str(root),
        files_scanned=scanned,
        files_skipped=skipped,
        files_unavailable=unavailable,
        include_deps=include_deps,
        scope=scope,
    )

    if output_format == "text":
        output = render_text(report)
    else:
        output = render_markdown(report)
    return report, output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Log Leak Map — find secrets and PII your app would print into its logs.",
        epilog="Everyone hunts secrets in git history. This hunts the lines that leak them at runtime.",
    )
    parser.add_argument(
        "repo_path",
        nargs="?",
        default=".",
        help="Path to repository to scan (default: current directory)",
    )
    parser.add_argument(
        "--scope",
        default=None,
        help="Optional glob(s) to narrow files (comma-separated)",
    )
    parser.add_argument(
        "--deps",
        action="store_true",
        help="Include dependency directories (node_modules, site-packages, vendor)",
    )
    parser.add_argument(
        "--format",
        choices=("md", "text"),
        default="md",
        help="Output format (default: md)",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Optional output file path (default: stdout)",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=1_000_000,
        help="Skip files larger than this many bytes (default: 1000000)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("confirmed", "suspicious", "any", "none"),
        default="none",
        help="Exit code 1 if findings at or above threshold (default: none)",
    )

    args = parser.parse_args(argv)

    try:
        report, output = run_scan(
            repo_path=args.repo_path,
            include_deps=args.deps,
            scope=args.scope,
            max_bytes=args.max_bytes,
            output_format=args.format,
        )
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Report written to {args.out}", file=sys.stderr)
    else:
        try:
            print(output)
        except UnicodeEncodeError:
            sys.stdout.buffer.write(output.encode("utf-8", errors="replace"))
            sys.stdout.buffer.write(b"\n")

    if args.fail_on == "confirmed":
        if any(f.severity == SEVERITY_CONFIRMED for f in report.findings):
            return 1
    elif args.fail_on == "suspicious":
        if any(
            f.severity in (SEVERITY_CONFIRMED, SEVERITY_SENSITIVE, SEVERITY_SUSPICIOUS)
            for f in report.findings
        ):
            return 1
    elif args.fail_on == "any":
        if report.findings:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
