#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
SAT_DIR="$BASE_DIR/mdns-sat"
HUB_DIR="$BASE_DIR/mdns-hub"
VENV_DIR="$BASE_DIR/venv"
MANAGE_SCRIPT="$BASE_DIR/manage_services.py"

APT_PACKAGES=(
  python3
  python3-venv
  python3-pip
  git
  curl
  net-tools
  vlan
  fping
)

INTERACTIVE=true
ACTION=""
HAS_TTY=false
USE_COLOR=false
SUCCESS_STEPS=0
FAILED_STEPS=0
SUMMARY_ITEMS=()
WARNING_ITEMS=()
STATUS_SERVICES=()
CONFIG_ACTION=""

if [[ -t 0 && -t 1 ]]; then
  HAS_TTY=true
fi

if [[ "$HAS_TTY" == true && -z "${NO_COLOR:-}" && "${TERM:-}" != "dumb" ]]; then
  USE_COLOR=true
fi

if [[ "$USE_COLOR" == true ]]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_DIM=$'\033[2m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_CYAN=$'\033[36m'
else
  C_RESET=""
  C_BOLD=""
  C_DIM=""
  C_RED=""
  C_GREEN=""
  C_YELLOW=""
  C_BLUE=""
  C_CYAN=""
fi

print_banner() {
  printf "%s%sMSA Setup / Management%s\n" "$C_BOLD" "$C_CYAN" "$C_RESET"
  printf "%sRepo:%s %s\n" "$C_DIM" "$C_RESET" "$BASE_DIR"
}

print_section() {
  local title="$1"
  printf "\n%s== %s ==%s\n" "$C_BOLD" "$title" "$C_RESET"
}

print_info() {
  printf "%s[INFO]%s %s\n" "$C_BLUE" "$C_RESET" "$1"
}

print_warn() {
  printf "%s[WARN]%s %s\n" "$C_YELLOW" "$C_RESET" "$1"
}

print_error() {
  printf "%s[FAIL]%s %s\n" "$C_RED" "$C_RESET" "$1" >&2
}

print_ok() {
  printf "%s[ OK ]%s %s\n" "$C_GREEN" "$C_RESET" "$1"
}

reset_summary() {
  SUCCESS_STEPS=0
  FAILED_STEPS=0
  SUMMARY_ITEMS=()
  WARNING_ITEMS=()
  STATUS_SERVICES=()
}

add_summary() {
  SUMMARY_ITEMS+=("$1")
}

add_warning() {
  WARNING_ITEMS+=("$1")
}

register_service_hint() {
  local service="$1"
  local existing
  for existing in "${STATUS_SERVICES[@]}"; do
    if [[ "$existing" == "$service" ]]; then
      return 0
    fi
  done
  STATUS_SERVICES+=("$service")
}

run_step() {
  local label="$1"
  shift

  printf "%s[....]%s %s\n" "$C_CYAN" "$C_RESET" "$label"
  set +e
  "$@"
  local rc=$?
  set -e

  if [[ $rc -eq 0 ]]; then
    SUCCESS_STEPS=$((SUCCESS_STEPS + 1))
    print_ok "$label"
  else
    FAILED_STEPS=$((FAILED_STEPS + 1))
    print_error "$label"
  fi

  return "$rc"
}

require_root() {
  [[ "$EUID" -eq 0 ]]
}

require_dir() {
  [[ -d "$1" ]]
}

require_file() {
  [[ -f "$1" ]]
}

require_command() {
  command -v "$1" >/dev/null 2>&1
}

ask_yes_no() {
  local prompt="$1"
  local default="${2:-y}"
  local answer

  if [[ "$INTERACTIVE" != true || "$HAS_TTY" != true ]]; then
    [[ "$default" == "y" ]]
    return
  fi

  while true; do
    if [[ "$default" == "y" ]]; then
      read -r -p "$prompt [Y/n] " answer || true
      answer="${answer:-y}"
    else
      read -r -p "$prompt [y/N] " answer || true
      answer="${answer:-n}"
    fi

    case "${answer,,}" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
      *) print_warn "Bitte 'y' oder 'n' eingeben." ;;
    esac
  done
}

ask_input() {
  local prompt="$1"
  local default="$2"
  local result_var="$3"
  local answer

  if [[ "$INTERACTIVE" != true || "$HAS_TTY" != true ]]; then
    printf -v "$result_var" "%s" "$default"
    return 0
  fi

  read -r -p "$prompt [$default] " answer || true
  answer="${answer:-$default}"
  printf -v "$result_var" "%s" "$answer"
}

sanitize_token() {
  local value="${1,,}"
  value="${value//[^a-z0-9-]/-}"
  value="$(printf "%s" "$value" | sed -E 's/^-+//; s/-+$//; s/-+/-/g')"
  printf "%s" "${value:-sat}"
}

default_hostname_token() {
  local host
  host="$(hostname -s 2>/dev/null || hostname || echo sat)"
  sanitize_token "$host"
}

generate_default_sat_id() {
  local host="$1"
  printf "%s-%04d" "$host" $((RANDOM % 10000))
}

show_file_preview() {
  local path="$1"
  print_section "Datei: $path"
  sed -n '1,200p' "$path"
}

choose_existing_config_action() {
  local label="$1"
  local path="$2"
  local choice

  if [[ ! -f "$path" ]]; then
    CONFIG_ACTION="create"
    return 0
  fi

  if [[ "$INTERACTIVE" != true || "$HAS_TTY" != true ]]; then
    print_info "[$label] Bestehende Konfiguration bleibt erhalten: $path"
    CONFIG_ACTION="keep"
    return 0
  fi

  while true; do
    printf "%s[INFO]%s %s existiert bereits: %s\n" "$C_BLUE" "$C_RESET" "$label" "$path"
    printf "  k) behalten\n"
    printf "  o) ueberschreiben\n"
    printf "  a) anzeigen\n"
    read -r -p "Auswahl [k/o/a] " choice || true
    choice="${choice:-k}"

    case "${choice,,}" in
      k) CONFIG_ACTION="keep"; return 0 ;;
      o) CONFIG_ACTION="overwrite"; return 0 ;;
      a) show_file_preview "$path" ;;
      *) print_warn "Bitte 'k', 'o' oder 'a' eingeben." ;;
    esac
  done
}

set_yaml_value() {
  local file="$1"
  local key="$2"
  local value="$3"

  if grep -Eq "^${key}:" "$file"; then
    sed -i -E "s|^${key}:.*$|${key}: \"${value}\"|" "$file"
  else
    printf "\n%s: \"%s\"\n" "$key" "$value" >>"$file"
  fi
}

copy_file() {
  local source="$1"
  local target="$2"
  cp "$source" "$target"
}

ensure_base_packages() {
  print_section "Systempakete"
  run_step "APT Paketindex aktualisieren" apt update || return 1
  run_step "Grundpakete installieren" apt install -y "${APT_PACKAGES[@]}" || return 1
}

ensure_venv() {
  print_section "Python venv"
  print_info "Pfad: $VENV_DIR"

  if [[ ! -d "$VENV_DIR" ]]; then
    run_step "Python venv erstellen" python3 -m venv "$VENV_DIR" || return 1
    add_summary "venv erstellt: $VENV_DIR"
  else
    print_info "venv existiert bereits und wird weiterverwendet."
    add_summary "venv wiederverwendet: $VENV_DIR"
  fi

  run_step "pip in der venv aktualisieren" "$VENV_DIR/bin/pip" install --upgrade pip || return 1
  run_step \
    "Python-Abhaengigkeiten installieren" \
    "$VENV_DIR/bin/pip" install \
    "uvicorn[standard]" \
    fastapi \
    netifaces \
    requests \
    pyyaml \
    pydantic \
    jinja2 \
    python-multipart || return 1
}

ensure_manage_script() {
  if [[ -x "$MANAGE_SCRIPT" ]]; then
    return 0
  fi

  if [[ -f "$MANAGE_SCRIPT" ]]; then
    run_step "manage_services.py ausfuehrbar machen" chmod +x "$MANAGE_SCRIPT" || return 1
    return 0
  fi

  print_error "manage_services.py fehlt: $MANAGE_SCRIPT"
  return 1
}

configure_sat_bootstrap_values() {
  local target="$1"
  local host sat_default sat_id

  host="$(default_hostname_token)"
  sat_default="$(generate_default_sat_id "$host")"
  ask_input "[SAT] SAT-ID setzen" "$sat_default" sat_id
  sat_id="$(sanitize_token "$sat_id")"

  if [[ -z "$sat_id" ]]; then
    sat_id="$sat_default"
  fi

  run_step "SAT-ID in sat_config.yaml setzen" set_yaml_value "$target" "sat_id" "$sat_id" || return 1
  run_step "Hostname in sat_config.yaml setzen" set_yaml_value "$target" "hostname" "$host" || return 1
  add_summary "SAT Konfiguration aktiv: $target (sat_id=$sat_id, hostname=$host)"
}

prepare_sat_config() {
  local target="$SAT_DIR/sat_config.yaml"
  local example="$SAT_DIR/sat_config.example.yaml"
  local action

  print_section "SAT Konfiguration"
  choose_existing_config_action "SAT" "$target"
  action="$CONFIG_ACTION"

  case "$action" in
    keep)
      add_summary "SAT Konfiguration beibehalten: $target"
      ;;
    create)
      run_step "SAT Beispielkonfiguration kopieren" copy_file "$example" "$target" || return 1
      configure_sat_bootstrap_values "$target" || return 1
      ;;
    overwrite)
      run_step "SAT Konfiguration mit Beispiel ueberschreiben" copy_file "$example" "$target" || return 1
      configure_sat_bootstrap_values "$target" || return 1
      ;;
    *)
      print_error "Unbekannte SAT Konfigurationsaktion: $action"
      return 1
      ;;
  esac
}

prepare_hub_config() {
  local target="$HUB_DIR/hub_config.yaml"
  local example="$HUB_DIR/hub_config.example.yaml"
  local action

  print_section "HUB Konfiguration"
  choose_existing_config_action "HUB" "$target"
  action="$CONFIG_ACTION"

  case "$action" in
    keep)
      add_summary "HUB Konfiguration beibehalten: $target"
      ;;
    create)
      run_step "HUB Beispielkonfiguration kopieren" copy_file "$example" "$target" || return 1
      add_summary "HUB Konfiguration erstellt: $target"
      ;;
    overwrite)
      run_step "HUB Konfiguration mit Beispiel ueberschreiben" copy_file "$example" "$target" || return 1
      add_summary "HUB Konfiguration ueberschrieben: $target"
      ;;
    *)
      print_error "Unbekannte HUB Konfigurationsaktion: $action"
      return 1
      ;;
  esac
}

ensure_run_script() {
  local label="$1"
  local run_script="$2"

  if [[ ! -f "$run_script" ]]; then
    add_summary "$label fehlt: $run_script"
    print_error "$label fehlt. Bitte Datei bereitstellen: $run_script"
    return 1
  fi

  run_step "$label ausfuehrbar machen" chmod +x "$run_script" || return 1
  add_summary "$label vorhanden und ausfuehrbar: $run_script"
}

maybe_prepare_hub_user() {
  local use_hub_user=false
  local hub_user="mdnshub"

  print_section "HUB Benutzer"
  if ask_yes_no "[HUB] Systemuser '$hub_user' anlegen und Besitz uebernehmen?" "y"; then
    use_hub_user=true

    if id "$hub_user" >/dev/null 2>&1; then
      print_info "Systemuser $hub_user existiert bereits."
    else
      run_step "Systemuser $hub_user anlegen" useradd -r -s /usr/sbin/nologin "$hub_user" || return 1
    fi

    run_step "Besitzrechte fuer $HUB_DIR setzen" chown -R "$hub_user:$hub_user" "$HUB_DIR" || return 1
    add_summary "HUB Verzeichnis gehoert $hub_user: $HUB_DIR"
  else
    add_summary "HUB Verzeichnisbesitz unveraendert gelassen."
  fi

  if [[ "$use_hub_user" == true ]]; then
    add_warning "Der systemd-Service laeuft weiterhin gemaess manage_services.py. Bei Bedarf Unit-Datei auf User=$hub_user anpassen."
  fi
}

install_venv_only() {
  ensure_base_packages
  ensure_venv
}

install_sat() {
  print_section "SAT Installation"
  ensure_base_packages
  ensure_venv
  ensure_manage_script
  prepare_sat_config
  ensure_run_script "SAT Run-Skript" "$SAT_DIR/run_sat.sh" || return 1
  run_step "SAT systemd-Service installieren" "$MANAGE_SCRIPT" install sat || return 1
  register_service_hint "mdns-sat"
  add_summary "SAT Service installiert: mdns-sat"
}

install_hub() {
  print_section "HUB Installation"
  ensure_base_packages
  ensure_venv
  ensure_manage_script
  prepare_hub_config
  maybe_prepare_hub_user
  ensure_run_script "HUB Run-Skript" "$HUB_DIR/run_hub.sh" || return 1
  run_step "HUB systemd-Service installieren" "$MANAGE_SCRIPT" install hub || return 1
  register_service_hint "mdns-hub"
  add_summary "HUB Service installiert: mdns-hub"
}

uninstall_sat() {
  print_section "SAT Deinstallation"
  ensure_manage_script
  run_step "SAT systemd-Service entfernen" "$MANAGE_SCRIPT" uninstall sat || return 1
  register_service_hint "mdns-sat"
  add_summary "SAT Service deinstalliert: mdns-sat"
}

uninstall_hub() {
  print_section "HUB Deinstallation"
  ensure_manage_script
  run_step "HUB systemd-Service entfernen" "$MANAGE_SCRIPT" uninstall hub || return 1
  register_service_hint "mdns-hub"
  add_summary "HUB Service deinstalliert: mdns-hub"
}

ask_remove_venv_if_unused() {
  if [[ ! -d "$VENV_DIR" ]]; then
    return 0
  fi

  print_section "Gemeinsame venv"
  print_info "Vorhanden unter: $VENV_DIR"

  if ask_yes_no "venv ebenfalls entfernen?" "n"; then
    run_step "venv entfernen" rm -rf "$VENV_DIR" || return 1
    add_summary "venv entfernt: $VENV_DIR"
  else
    add_summary "venv behalten: $VENV_DIR"
  fi
}

preflight_common() {
  print_section "Preflight"
  run_step "Root-Rechte pruefen" require_root || return 1
  run_step "Arbeitsverzeichnis pruefen" require_dir "$BASE_DIR" || return 1
  run_step "APT Verfuegbarkeit pruefen" require_command apt || return 1
  run_step "sed Verfuegbarkeit pruefen" require_command sed || return 1
}

preflight_sat_install() {
  preflight_common
  run_step "SAT Verzeichnis pruefen" require_dir "$SAT_DIR" || return 1
  run_step "SAT Hauptskript pruefen" require_file "$SAT_DIR/mdns_sat.py" || return 1
  run_step "SAT Beispielkonfiguration pruefen" require_file "$SAT_DIR/sat_config.example.yaml" || return 1
  run_step "manage_services.py pruefen" require_file "$MANAGE_SCRIPT" || return 1
}

preflight_hub_install() {
  preflight_common
  run_step "HUB Verzeichnis pruefen" require_dir "$HUB_DIR" || return 1
  run_step "HUB Hauptskript pruefen" require_file "$HUB_DIR/main.py" || return 1
  run_step "HUB Beispielkonfiguration pruefen" require_file "$HUB_DIR/hub_config.example.yaml" || return 1
  run_step "manage_services.py pruefen" require_file "$MANAGE_SCRIPT" || return 1
}

preflight_venv_only() {
  preflight_common
}

preflight_sat_uninstall() {
  preflight_common
  run_step "manage_services.py pruefen" require_file "$MANAGE_SCRIPT" || return 1
}

preflight_hub_uninstall() {
  preflight_common
  run_step "manage_services.py pruefen" require_file "$MANAGE_SCRIPT" || return 1
}

run_preflight_for_action() {
  local selected_action="$1"

  case "$selected_action" in
    venv-only)
      preflight_venv_only
      ;;
    install-sat)
      preflight_sat_install
      ;;
    install-hub)
      preflight_hub_install
      ;;
    install-all)
      preflight_sat_install
      preflight_hub_install
      ;;
    uninstall-sat)
      preflight_sat_uninstall
      ;;
    uninstall-hub)
      preflight_hub_uninstall
      ;;
    uninstall-all)
      preflight_sat_uninstall
      preflight_hub_uninstall
      ;;
    *)
      print_error "Unbekannte Aktion: $selected_action"
      return 1
      ;;
  esac
}

action_label() {
  case "$1" in
    venv-only) printf "Nur venv installieren/aktualisieren" ;;
    install-sat) printf "SAT installieren" ;;
    install-hub) printf "HUB installieren" ;;
    install-all) printf "SAT + HUB installieren" ;;
    uninstall-sat) printf "SAT deinstallieren" ;;
    uninstall-hub) printf "HUB deinstallieren" ;;
    uninstall-all) printf "SAT + HUB deinstallieren" ;;
    *) printf "%s" "$1" ;;
  esac
}

print_summary() {
  local selected_action="$1"
  local label
  local item
  local service

  label="$(action_label "$selected_action")"
  print_section "Zusammenfassung"
  printf "%sAktion:%s %s\n" "$C_BOLD" "$C_RESET" "$label"
  printf "%sSchritte erfolgreich:%s %d\n" "$C_BOLD" "$C_RESET" "$SUCCESS_STEPS"
  printf "%sSchritte fehlgeschlagen:%s %d\n" "$C_BOLD" "$C_RESET" "$FAILED_STEPS"

  if [[ ${#SUMMARY_ITEMS[@]} -gt 0 ]]; then
    printf "%sNotizen:%s\n" "$C_BOLD" "$C_RESET"
    for item in "${SUMMARY_ITEMS[@]}"; do
      printf "  - %s\n" "$item"
    done
  fi

  if [[ ${#WARNING_ITEMS[@]} -gt 0 ]]; then
    printf "%sHinweise:%s\n" "$C_BOLD" "$C_RESET"
    for item in "${WARNING_ITEMS[@]}"; do
      printf "  - %s\n" "$item"
    done
  fi

  if [[ ${#STATUS_SERVICES[@]} -gt 0 ]]; then
    printf "%ssystemd Checks:%s\n" "$C_BOLD" "$C_RESET"
    for service in "${STATUS_SERVICES[@]}"; do
      printf "  - systemctl status %s --no-pager\n" "$service"
      printf "  - journalctl -u %s -n 50 --no-pager\n" "$service"
    done
    printf "  - Logs unter /var/log/msa/ pruefen\n"
  fi
}

print_usage() {
  cat <<EOF
Verwendung: $(basename "$0") [--non-interactive] [aktion]

Aktionen:
  venv-only
  install-sat
  install-hub
  install-all
  uninstall-sat
  uninstall-hub
  uninstall-all

Ohne Aktion startet interaktiv das Menue.
Mit --non-interactive ist die Default-Aktion: install-all
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --non-interactive)
        INTERACTIVE=false
        ;;
      -h|--help)
        print_usage
        exit 0
        ;;
      venv-only|install-sat|install-hub|install-all|uninstall-sat|uninstall-hub|uninstall-all)
        if [[ -n "$ACTION" ]]; then
          print_error "Mehrere Aktionen angegeben."
          exit 1
        fi
        ACTION="$1"
        ;;
      *)
        print_error "Unbekanntes Argument: $1"
        print_usage
        exit 1
        ;;
    esac
    shift
  done
}

show_menu() {
  local choice

  print_section "Menue"
  printf "  0) Nur venv / Python-Requirements installieren oder aktualisieren\n"
  printf "  1) SAT installieren\n"
  printf "  2) HUB installieren\n"
  printf "  3) SAT + HUB installieren\n"
  printf "  4) SAT deinstallieren\n"
  printf "  5) HUB deinstallieren\n"
  printf "  6) SAT + HUB deinstallieren\n"
  printf "  q) Beenden\n\n"

  read -r -p "Auswahl: " choice || true

  case "${choice,,}" in
    0) ACTION="venv-only" ;;
    1) ACTION="install-sat" ;;
    2) ACTION="install-hub" ;;
    3) ACTION="install-all" ;;
    4) ACTION="uninstall-sat" ;;
    5) ACTION="uninstall-hub" ;;
    6) ACTION="uninstall-all" ;;
    q)
      printf "Beendet.\n"
      exit 0
      ;;
    *)
      print_warn "Ungueltige Auswahl."
      ACTION=""
      ;;
  esac
}

execute_action() {
  local selected_action="$1"

  run_preflight_for_action "$selected_action"

  case "$selected_action" in
    venv-only)
      install_venv_only
      ;;
    install-sat)
      install_sat
      ;;
    install-hub)
      install_hub
      ;;
    install-all)
      install_sat
      install_hub
      ;;
    uninstall-sat)
      uninstall_sat
      ask_remove_venv_if_unused
      ;;
    uninstall-hub)
      uninstall_hub
      ask_remove_venv_if_unused
      ;;
    uninstall-all)
      uninstall_sat
      uninstall_hub
      ask_remove_venv_if_unused
      ;;
    *)
      print_error "Unbekannte Aktion: $selected_action"
      return 1
      ;;
  esac
}

run_selected_action() {
  local selected_action="$1"
  local rc

  reset_summary
  set +e
  execute_action "$selected_action"
  rc=$?
  set -e
  print_summary "$selected_action"
  return "$rc"
}

main() {
  local rc

  parse_args "$@"
  print_banner

  if [[ -z "$ACTION" && "$INTERACTIVE" == true ]]; then
    while true; do
      show_menu
      [[ -z "$ACTION" ]] && continue
      set +e
      run_selected_action "$ACTION"
      rc=$?
      set -e
      if [[ $rc -ne 0 ]]; then
        print_warn "Aktion endete mit Fehlercode $rc."
      fi
      ACTION=""
    done
  fi

  if [[ -z "$ACTION" ]]; then
    ACTION="install-all"
    print_info "Nicht-interaktiv ohne Aktion: verwende Default '$ACTION'."
  fi

  set +e
  run_selected_action "$ACTION"
  rc=$?
  set -e
  return "$rc"
}

main "$@"
