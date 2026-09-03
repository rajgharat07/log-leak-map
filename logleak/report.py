"""Banner verdict, Leak Ledger table, markdown/text renderers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from logleak.classes import (
    Finding,
    FileStatus,
    SEVERITY_CONFIRMED,
    SEVERITY_NEEDS_REVIEW,
    SEVERITY_SENSITIVE,
    SEVERITY_SUSPICIOUS,
)

_SEV_ICON = {
    SEVERITY_CONFIRMED: "🔴",
    SEVERITY_SENSITIVE: "🟠",
    SEVERITY_SUSPICIOUS: "🟡",
    SEVERITY_NEEDS_REVIEW: "⚪",
}


@dataclass
class Report:
    findings: list[Finding]
    file_statuses: list[FileStatus]
    repo_path: str
    files_scanned: int
    files_skipped: int
    files_unavailable: int
    include_deps: bool = False
    scope: Optional[str] = None

    @property
    def confirmed(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == SEVERITY_CONFIRMED]

    @property
    def sensitive(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == SEVERITY_SENSITIVE]

    @property
    def suspicious(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == SEVERITY_SUSPICIOUS]

    @property
    def needs_review(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == SEVERITY_NEEDS_REVIEW]

    @property
    def verdict(self) -> str:
        if self.confirmed:
            return "LEAKING"
        if self.sensitive:
            return "SENSITIVE"
        if self.suspicious:
            return "RISKY"
        if self.needs_review:
            return "NEEDS-REVIEW"
        return "CLEAN"

    @property
    def counts_line(self) -> str:
        n = len(self.confirmed)
        sink_word = "CONFIRMED SINK" if n == 1 else "CONFIRMED SINKS"
        return (
            f"{n} {sink_word}, "
            f"{len(self.sensitive)} SENSITIVE, "
            f"{len(self.suspicious)} SUSPICIOUS"
        )

    @property
    def verdict_banner(self) -> str:
        v = self.verdict
        if v == "LEAKING":
            return f"LEAKING — {self.counts_line}"
        if v == "SENSITIVE":
            return f"SENSITIVE — {len(self.sensitive)} identifier(s) passed to a log sink"
        if v == "RISKY":
            return f"RISKY — {len(self.suspicious)} suspicious log sink(s)"
        if v == "NEEDS-REVIEW":
            return f"NEEDS-REVIEW — {len(self.needs_review)} ambiguous log line(s)"
        return "CLEAN — no sensitive names at a log/output sink"


def _esc(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _mark(finding: Finding) -> str:
    return f"{_SEV_ICON.get(finding.severity, '•')} {finding.severity}"


def render_markdown(report: Report) -> str:
    lines: list[str] = []
    banner = report.verdict_banner
    bar = "=" * max(64, len(banner) + 4)
    lines.append("# Log Leak Map")
    lines.append("")
    lines.append("```")
    lines.append(bar)
    lines.append(f"  {banner}")
    lines.append(bar)
    lines.append("```")
    lines.append("")
    lines.append(f"**Repo:** `{report.repo_path}`  ")
    lines.append(
        f"**Scanned:** {report.files_scanned} files · "
        f"**Skipped:** {report.files_skipped} · "
        f"**Unavailable:** {report.files_unavailable}  "
    )
    if report.scope:
        lines.append(f"**Scope:** `{report.scope}`  ")
    lines.append(f"**Deps included:** `{report.include_deps}`  ")
    lines.append("")

    lines.append("## The Leak Ledger")
    lines.append("")
    if not report.findings:
        lines.append("_No sensitive log/output sinks found._")
        lines.append("")
    else:
        lines.append("| # | severity | class | modifiers | file:line | sink | reconstructed |")
        lines.append("|---|---|---|---|---|---|---|")
        for i, f in enumerate(report.findings, start=1):
            loc = f"{f.path}:{f.line}"
            mods = ",".join(f.modifiers) if f.modifiers else "—"
            klass = f.leak_class
            if f.also:
                klass = f"{f.leak_class} (+{','.join(f.also)})"
            lines.append(
                f"| {i} | {_mark(f)} | `{klass}` | `{mods}` | `{loc}` | `{_esc(f.sink)}` | "
                f"`{_esc(f.reconstructed or f.source)}` |"
            )
        lines.append("")

    lines.append("## Evidence")
    lines.append("")
    if not report.findings:
        lines.append("_None._")
        lines.append("")
    else:
        for i, f in enumerate(report.findings, start=1):
            extras = ""
            if f.modifiers:
                extras += f" modifiers=`{','.join(f.modifiers)}`"
            if f.also:
                extras += f" also=`{','.join(f.also)}`"
            lines.append(
                f"### {i}. {_mark(f)} `{f.leak_class}` @ `{f.path}:{f.line}:{f.col}` "
                f"({f.confidence}){extras}"
            )
            lines.append("")
            lines.append(f"- **Sink:** `{f.sink}`")
            lines.append(f"- **Source:** `{_esc(f.source)}`")
            lines.append(f"- **Reconstruction (redacted):** `{_esc(f.reconstructed)}`")
            if f.leaked_names:
                lines.append(f"- **Names:** {', '.join(f'`{n}`' for n in f.leaked_names)}")
            lines.append(f"- **Why:** {f.evidence}")
            lines.append(f"- **Fix:** {f.recommendation}")
            lines.append("")

    lines.append("## Recommendations")
    lines.append("")
    if report.verdict == "CLEAN":
        lines.append("- Nothing to fix. Re-run when someone adds a `print` / `console.log` / `logger.info`.")
    else:
        lines.append("1. **CONFIRMED SINK** means a secret/env/token-**like name** is an argument to a log/output call. It does not prove the runtime value is a live secret.")
        lines.append("2. **SENSITIVE** means an email/card/phone-shaped identifier is an argument. Log `user_id`, not `user.email`.")
        lines.append("3. **SUSPICIOUS** means a request dump or exception object hit a sink. Not proven secret.")
        lines.append("4. **DEBUG** is a modifier on leftover `print` / `console.log` / `.debug` — not a second finding.")
        lines.append("5. This tool does not know whether the sink is stdout, a file, or a vendor pipeline. It knows the call site.")
        lines.append("6. Re-run in CI with `--fail-on confirmed`.")
    lines.append("")

    degraded = [fs for fs in report.file_statuses if fs.status != "SCANNED"]
    if degraded:
        lines.append("## Degradation ledger")
        lines.append("")
        for fs in degraded[:50]:
            lines.append(f"- `{fs.path}` — **{fs.status}** — {fs.reason}")
        if len(degraded) > 50:
            lines.append(f"- … and {len(degraded) - 50} more")
        lines.append("")

    lines.append("---")
    lines.append("_Log Leak Map · read-only · zero adapters · stdlib only · static analysis only_")
    lines.append("")
    return "\n".join(lines)


def render_text(report: Report) -> str:
    lines: list[str] = []
    banner = report.verdict_banner
    bar = "=" * max(64, len(banner) + 4)
    lines.append(bar)
    lines.append(f"  {banner}")
    lines.append(bar)
    lines.append(f"Repo: {report.repo_path}")
    lines.append(
        f"Scanned={report.files_scanned}  Skipped={report.files_skipped}  "
        f"Unavailable={report.files_unavailable}"
    )
    lines.append("")
    lines.append("THE LEAK LEDGER")
    lines.append("-" * 64)
    if not report.findings:
        lines.append("  (no sinks)")
    else:
        for i, f in enumerate(report.findings, start=1):
            extras = ""
            if f.modifiers:
                extras += f"  [{', '.join(f.modifiers)}]"
            if f.also:
                extras += f"  +{','.join(f.also)}"
            lines.append(
                f"{i:3d}. {_mark(f)}  {f.leak_class}{extras}  {f.path}:{f.line}"
            )
            lines.append(f"     sink  : {f.sink}")
            lines.append(f"     source: {f.source}")
            lines.append(f"     would : {f.reconstructed}")
            lines.append(f"     why   : {f.evidence}")
            lines.append("")
    return "\n".join(lines)
