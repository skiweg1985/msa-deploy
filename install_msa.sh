#!/usr/bin/env bash
set -euo pipefail

echo "=== MSA Setup / Management (Hub & Sat, gemeinsame venv) ==="

if [[ "$EUID" -ne 0 ]]; then
  echo "Bitte als root ausführen (sudo ./install_msa.sh)."
  exit 1
fi

BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

SAT_DIR="$BASE_DIR/mdns-sat"
HUB_DIR="$BASE_DIR/mdns-hub"

VENV_DIR="$BASE_DIR/venv"
MANAGE_SCRIPT="$BASE_DIR/manage_services.py"

# ─────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────

ask_yes_no() {
  local prompt="$1"
  local default="${2:-y}"  # y oder n
  local answer

  while true; do
    if [[ "$default" == "y" ]]; then
      read -rp "$prompt [Y/n] " answer || true
      answer="${answer:-y}"
    else
      read -rp "$prompt [y/N] " answer || true
      answer="${answer:-n}"
    fi

    case "${answer,,}" in
      y|yes) return 0 ;;
      n|no)  return 1 ;;
      *) echo "Bitte 'y' oder 'n' eingeben." ;;
    esac
  done
}

ensure_base_packages() {
  echo "--- apt update & Grundpakete installieren ---"
  apt update
  apt install -y python3 python3-venv python3-pip git curl net-tools vlan fping
}

ensure_venv() {
  echo ""
  echo "=== Gemeinsame venv prüfen/anlegen ==="
  echo "Pfad: $VENV_DIR"

  if [[ ! -d "$VENV_DIR" ]]; then
    echo "[VENV] Erzeuge venv ..."
    python3 -m venv "$VENV_DIR"
  else
    echo "[VENV] venv existiert bereits."
  fi

  echo "[VENV] Upgrade pip ..."
  "$VENV_DIR/bin/pip" install --upgrade pip

  echo "[VENV] Installiere benötigte Python-Pakete für HUB & SAT ..."
  "$VENV_DIR/bin/pip" install \
    "uvicorn[standard]" \
    fastapi \
    netifaces \
    requests \
    pyyaml \
    pydantic \
    jinja2 \
    python-multipart

  echo "=== venv fertig ==="
}

ensure_manage_script() {
  if [[ ! -x "$MANAGE_SCRIPT" ]]; then
    if [[ -f "$MANAGE_SCRIPT" ]]; then
      chmod +x "$MANAGE_SCRIPT"
    else
      echo "❌ manage_services.py nicht gefunden unter $MANAGE_SCRIPT"
      echo "   Ohne dieses Script funktionieren Install/Uninstall der systemd-Services nicht."
      exit 1
    fi
  fi
}

# ─────────────────────────────────────────────
# Nur venv / Requirements installieren
# ─────────────────────────────────────────────

install_venv_only() {
  echo ""
  echo "=== Nur venv / Python-Requirements installieren/aktualisieren ==="
  ensure_base_packages
  ensure_venv
  echo "=== venv-Setup abgeschlossen (keine Services angefasst) ==="
}

# ─────────────────────────────────────────────
# SAT installieren / deinstallieren
# ─────────────────────────────────────────────

install_sat() {
  if [[ ! -d "$SAT_DIR" ]]; then
    echo "⚠ SAT-Verzeichnis $SAT_DIR nicht gefunden – abbrechen."
    return 1
  fi

  echo ""
  echo "=== SAT installieren ==="
  ensure_base_packages
  ensure_venv
  ensure_manage_script

  # Run-Script für Standalone-Test
  local run_script="$SAT_DIR/run_sat.sh"
  cat > "$run_script" <<'EOF'
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
EOF
  chmod +x "$run_script"
  echo "[SAT] Run-Script erstellt: $run_script"

  echo "[SAT] Installiere systemd-Service via manage_services.py ..."
  "$MANAGE_SCRIPT" install sat

  echo "=== SAT-Installation abgeschlossen ==="
}

uninstall_sat() {
  echo ""
  echo "=== SAT deinstallieren ==="
  ensure_manage_script
  "$MANAGE_SCRIPT" uninstall sat || true
  echo "=== SAT-Deinstallation abgeschlossen ==="
}

# ─────────────────────────────────────────────
# HUB installieren / deinstallieren
# ─────────────────────────────────────────────

install_hub() {
  if [[ ! -d "$HUB_DIR" ]]; then
    echo "⚠ HUB-Verzeichnis $HUB_DIR nicht gefunden – abbrechen."
    return 1
  fi

  echo ""
  echo "=== HUB installieren ==="
  ensure_base_packages
  ensure_venv
  ensure_manage_script

  local use_hub_user=false
  local hub_user="mdnshub"

  if ask_yes_no "[HUB] Eigenen Systemuser (mdnshub) anlegen & Verzeichnis gehören lassen?" "y"; then
    use_hub_user=true
    if ! id "$hub_user" >/dev/null 2>&1; then
      echo "[HUB] Lege Systemuser $hub_user an ..."
      useradd -r -s /usr/sbin/nologin "$hub_user"
    else
      echo "[HUB] Systemuser $hub_user existiert bereits."
    fi
    chown -R "$hub_user":"$hub_user" "$HUB_DIR"
    echo "[HUB] Besitzer von $HUB_DIR → $hub_user"
  fi

  # Run-Script für Standalone-Test
  local run_script="$HUB_DIR/run_hub.sh"
  cat > "$run_script" <<'EOF'
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
exec "$VENV/bin/uvicorn" main:app --host 0.0.0.0 --port 8000 "$@"
EOF
  chmod +x "$run_script"
  echo "[HUB] Run-Script erstellt: $run_script"

  echo "[HUB] Installiere systemd-Service via manage_services.py ..."
  "$MANAGE_SCRIPT" install hub

  if [[ "$use_hub_user" == true ]]; then
    echo ""
    echo "Hinweis:"
    echo "  Der systemd-Service läuft aktuell noch als root."
    echo "  Wenn du möchtest, können wir die Unit-Datei anpassen (User=$hub_user)."
  fi

  echo "=== HUB-Installation abgeschlossen ==="
}

uninstall_hub() {
  echo ""
  echo "=== HUB deinstallieren ==="
  ensure_manage_script
  "$MANAGE_SCRIPT" uninstall hub || true
  echo "=== HUB-Deinstallation abgeschlossen ==="
}

# ─────────────────────────────────────────────
# Venv ggf. entfernen
# ─────────────────────────────────────────────

ask_remove_venv_if_unused() {
  echo ""
  if [[ ! -d "$VENV_DIR" ]]; then
    return
  fi

  echo "Die gemeinsame venv liegt unter: $VENV_DIR"
  if ask_yes_no "venv ebenfalls entfernen?" "n"; then
    rm -rf "$VENV_DIR"
    echo "[VENV] entfernt."
  else
    echo "[VENV] bleibt erhalten."
  fi
}

# ─────────────────────────────────────────────
# Menü
# ─────────────────────────────────────────────

show_menu() {
  echo ""
  echo "Repo: $BASE_DIR"
  echo "SAT : $SAT_DIR"
  echo "HUB : $HUB_DIR"
  echo ""
  echo "Was möchtest du tun?"
  echo "  0) Nur venv / Python-Requirements installieren/aktualisieren"
  echo "  1) SAT installieren"
  echo "  2) HUB installieren"
  echo "  3) SAT + HUB installieren"
  echo "  4) SAT deinstallieren"
  echo "  5) HUB deinstallieren"
  echo "  6) SAT + HUB deinstallieren"
  echo "  q) Beenden"
  echo ""

  read -rp "Auswahl: " choice || true

  case "${choice,,}" in
    0)
      install_venv_only
      ;;
    1)
      install_sat
      ;;
    2)
      install_hub
      ;;
    3)
      install_sat
      install_hub
      ;;
    4)
      uninstall_sat
      ask_remove_venv_if_unused
      ;;
    5)
      uninstall_hub
      ask_remove_venv_if_unused
      ;;
    6)
      uninstall_sat
      uninstall_hub
      ask_remove_venv_if_unused
      ;;
    q)
      echo "Tschüss 👋"
      exit 0
      ;;
    *)
      echo "Ungültige Auswahl."
      ;;
  esac
}

# ─────────────────────────────────────────────
# Start
# ─────────────────────────────────────────────

while true; do
  show_menu
done