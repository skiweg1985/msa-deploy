#!/usr/bin/env bash
set -euo pipefail

echo "=== mDNS Sat Setup (Ubuntu/Debian/Raspi) ==="

if [[ "$EUID" -ne 0 ]]; then
  echo "Bitte als root ausführen (sudo)."
  exit 1
fi

# -----------------------------------------------------------------------------
# Basis: Pfad zum Repo (msa) = Ordner, in dem dieses Script liegt
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
SAT_DIR="$SCRIPT_DIR/mdns-sat"

if [[ ! -d "$SAT_DIR" ]]; then
  echo "Fehler: Verzeichnis '$SAT_DIR' nicht gefunden."
  echo "Bitte das Repo 'msa' mit Unterordner 'mdns-sat' verwenden."
  exit 1
fi

# -----------------------------------------------------------------------------
# Pakete installieren
# -----------------------------------------------------------------------------
echo "[1/4] apt update & Grundpakete installieren..."
apt update
apt install -y python3 python3-venv python3-pip git curl \
               net-tools vlan

echo "[2/4] Verwende Sat-Verzeichnis: $SAT_DIR"
cd "$SAT_DIR"

# -----------------------------------------------------------------------------
# Virtualenv anlegen
# -----------------------------------------------------------------------------
echo "[3/4] Python Virtualenv anlegen..."
python3 -m venv venv
./venv/bin/pip install --upgrade pip

echo "[4/4] Benötigte Python-Pakete installieren..."
./venv/bin/pip install \
  "uvicorn[standard]" \
  fastapi \
  netifaces \
  requests \
  zeroconf \
  pyyaml

echo ""
echo "FERTIG. Sat-Umgebung ist eingerichtet."
echo "Repo-Basis: $SCRIPT_DIR"
echo "Sat-Verzeichnis: $SAT_DIR"
echo ""
echo "Teststart:"
echo "  cd $SAT_DIR"
echo "  ./venv/bin/python mdns_sat.py"
echo ""
echo "Später können wir hier ein systemd-Unit-File 'mdns-sat.service' ergänzen."