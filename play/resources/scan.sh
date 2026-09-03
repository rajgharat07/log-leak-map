#!/usr/bin/env bash
set -euo pipefail

REPO_PATH="${1:?repo_path required}"
INCLUDE_DEPS="${2:-false}"
SCOPE="${3:-}"

TOOL_DIR="/tmp/log-leak-map-tool"
TOOL_REPO="https://github.com/rajgharat07/log-leak-map.git"

if [ ! -f "$TOOL_DIR/log_leak.py" ]; then
  rm -rf "$TOOL_DIR"
  git clone --depth 1 "$TOOL_REPO" "$TOOL_DIR"
fi

if [ ! -f "$TOOL_DIR/log_leak.py" ]; then
  echo "log leak map tool missing after clone" >&2
  exit 1
fi

CMD=(python3 "$TOOL_DIR/log_leak.py" "$REPO_PATH" --format md)
case "${INCLUDE_DEPS,,}" in
  true|1|yes|y) CMD+=(--deps) ;;
esac
if [ -n "$SCOPE" ]; then
  CMD+=(--scope "$SCOPE")
fi

"${CMD[@]}"
