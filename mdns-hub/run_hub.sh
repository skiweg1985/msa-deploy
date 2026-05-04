#!/usr/bin/env bash
set -euo pipefail

# Basis ermitteln
BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_DIR="$(dirname "$BASE_DIR")"
VENV="$REPO_DIR/venv"

# Prüfen, ob venv existiert
if [[ ! -x "$VENV/bin/python" ]]; then
  echo ""
  echo "❌ Fehler: Die Python-venv wurde nicht gefunden."
  echo "   Erwartet unter: $VENV"
  echo ""
  echo "   Bitte aus dem Repo-Root ausführen:"
  echo "     sudo ./install_msa.sh"
  echo "   und dort Option '0) Nur venv installieren' wählen."
  echo ""
  exit 1
fi

echo ""
echo "▶ Starte mDNS-Hub im Standalone-Modus (Venv)…"
echo ""

cd "$BASE_DIR"
exec "$VENV/bin/uvicorn" main:app --host 0.0.0.0 --port 8000 "$@"