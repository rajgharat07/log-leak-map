"""Walk a repo for source files that can emit logs."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Optional

from logleak.classes import DEPS_DIR_NAMES, SKIP_DIR_NAMES, SOURCE_EXTENSIONS


def _is_source(path: Path) -> bool:
    return path.suffix.lower() in SOURCE_EXTENSIONS


def _matches_scope(rel: str, scope: Optional[str]) -> bool:
    if not scope:
        return True
    patterns = [p.strip() for p in scope.split(",") if p.strip()]
    if not patterns:
        return True
    norm = rel.replace("\\", "/")
    for pat in patterns:
        if fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(Path(norm).name, pat):
            return True
        if fnmatch.fnmatch(norm, f"**/{pat}"):
            return True
    return False


def discover_files(
    repo_path: str | Path,
    *,
    include_deps: bool = False,
    scope: Optional[str] = None,
    max_files: int = 4000,
) -> list[tuple[Path, str]]:
    root = Path(repo_path).resolve()
    if not root.exists():
        return []
    if root.is_file():
        rel = root.name
        if _is_source(root) and _matches_scope(rel, scope):
            return [(root, rel)]
        return []

    results: list[tuple[Path, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        pruned = []
        for d in list(dirnames):
            if d in SKIP_DIR_NAMES:
                continue
            if not include_deps and d in DEPS_DIR_NAMES:
                continue
            pruned.append(d)
        dirnames[:] = pruned

        for fname in filenames:
            abs_path = Path(dirpath) / fname
            try:
                rel = abs_path.relative_to(root).as_posix()
            except ValueError:
                continue
            if not _matches_scope(rel, scope):
                continue
            if not _is_source(abs_path):
                continue
            results.append((abs_path, rel))
            if len(results) >= max_files:
                return results
    return results


def read_text_safe(
    path: Path,
    max_bytes: int = 1_000_000,
) -> tuple[Optional[str], str]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"UNAVAILABLE — cannot stat: {exc}"

    if size > max_bytes:
        return None, f"SKIPPED — size {size} > max_bytes {max_bytes}"

    try:
        raw = path.read_bytes()
    except OSError as exc:
        return None, f"UNAVAILABLE — cannot read: {exc}"

    if raw.count(b"\x00") > 0 and raw.count(b"\x00") / max(len(raw), 1) > 0.01:
        return None, "SKIPPED — binary (NUL density)"

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception as exc:  # pragma: no cover
            return None, f"UNAVAILABLE — decode failed: {exc}"

    return text, ""
