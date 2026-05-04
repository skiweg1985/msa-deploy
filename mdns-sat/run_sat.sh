#!/usr/bin/env bash
set -euo pipefail
BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_DIR="$(dirname "$BASE_DIR")"
VENV="$REPO_DIR/venv"

if [[ ! -x "$VENV/bin/python" ]]; then
  echo "Fehler: venv nicht gefunden. Bitte ./install_msa.sh im Repo-Root mit 'Nur venv installieren' ausführen."
  exit 1
fi

cd "$BASE_DIR"
exec "$VENV/bin/python" mdns_sat.py "$@"
