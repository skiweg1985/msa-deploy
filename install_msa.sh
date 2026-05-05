#!/usr/bin/env bash
set -euo pipefail

# ── Pfade ──────────────────────────────────────────────────────────────────
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

APT_LOCK_TIMEOUT="${MSA_APT_LOCK_TIMEOUT:-120}"
APT_CMD_TIMEOUT="${MSA_APT_CMD_TIMEOUT:-900}"
APT_RETRIES="${MSA_APT_RETRIES:-2}"
APT_RETRY_BACKOFF_SECONDS="${MSA_APT_RETRY_BACKOFF_SECONDS:-10}"

# ── Zustand ────────────────────────────────────────────────────────────────
INTERACTIVE=true
ACTION=""
HAS_TTY=false
USE_COLOR=false
HAS_GUM=false
AUTO_INSTALL_GUM=false
LOG_FILE="${MSA_LOG_FILE:-}"
SUCCESS_STEPS=0
FAILED_STEPS=0
SUMMARY_ITEMS=()
WARNING_ITEMS=()
STATUS_SERVICES=()
CONFIG_ACTION=""

# ── Terminal-Erkennung ─────────────────────────────────────────────────────
if [[ -t 0 && -t 1 ]]; then
  HAS_TTY=true
fi

if [[ "$HAS_TTY" == true && -z "${NO_COLOR:-}" && "${TERM:-}" != "dumb" ]]; then
  USE_COLOR=true
fi

refresh_has_gum() {
  HAS_GUM=false
  if [[ "$HAS_TTY" == true ]] && command -v gum >/dev/null 2>&1; then
    HAS_GUM=true
  fi
}

refresh_has_gum

# ── Farben ─────────────────────────────────────────────────────────────────
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

# ═══════════════════════════════════════════════════════════════════════════
# UI-Abstraktionsschicht
#   gum (TUI) wenn vorhanden, sonst klassisches read/echo.
# ═══════════════════════════════════════════════════════════════════════════

ui_header() {
  local title="$1"
  local subtitle="${2:-}"
  if [[ "$HAS_GUM" == true ]]; then
    printf "\n"
    if [[ -n "$subtitle" ]]; then
      gum style --border rounded --padding "1 3" --border-foreground 6 \
        "$title" "$subtitle"
    else
      gum style --border rounded --padding "1 3" --border-foreground 6 "$title"
    fi
  else
    printf "%s%s%s%s\n" "$C_BOLD" "$C_CYAN" "$title" "$C_RESET"
    [[ -n "$subtitle" ]] && printf "%s%s%s\n" "$C_DIM" "$subtitle" "$C_RESET"
  fi
}

ui_choose() {
  local header="$1"
  shift
  local options=("$@")

  if [[ "$HAS_GUM" == true ]]; then
    gum choose --header "$header" "${options[@]}"
    return
  fi

  printf "\n%s%s%s\n" "$C_BOLD" "$header" "$C_RESET" >&2
  local i
  for i in "${!options[@]}"; do
    printf "  %d) %s\n" "$i" "${options[$i]}" >&2
  done
  printf "\n" >&2

  local idx
  read -r -p "Auswahl: " idx || true
  if [[ "$idx" =~ ^[0-9]+$ && $idx -ge 0 && $idx -lt ${#options[@]} ]]; then
    printf "%s" "${options[$idx]}"
  fi
}

ui_confirm() {
  local prompt="$1"
  local default="${2:-y}"

  if [[ "$INTERACTIVE" != true || "$HAS_TTY" != true ]]; then
    [[ "$default" == "y" ]]
    return
  fi

  if [[ "$HAS_GUM" == true ]]; then
    if [[ "$default" == "y" ]]; then
      gum confirm --default=yes --affirmative "Ja" --negative "Nein" "$prompt"
    else
      gum confirm --default=no --affirmative "Ja" --negative "Nein" "$prompt"
    fi
    return
  fi

  local answer
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
      n|no)  return 1 ;;
      *) printf "%s[WARN]%s Bitte 'y' oder 'n' eingeben.\n" "$C_YELLOW" "$C_RESET" >&2 ;;
    esac
  done
}

ui_input() {
  local prompt="$1"
  local default="${2:-}"

  if [[ "$INTERACTIVE" != true || "$HAS_TTY" != true ]]; then
    printf "%s" "$default"
    return 0
  fi

  if [[ "$HAS_GUM" == true ]]; then
    gum input --header "$prompt" --placeholder "$default" --value "$default"
    return
  fi

  local answer
  read -r -p "$prompt [$default] " answer || true
  printf "%s" "${answer:-$default}"
}

ui_secret() {
  local prompt="$1"

  if [[ "$INTERACTIVE" != true || "$HAS_TTY" != true ]]; then
    printf ""
    return 0
  fi

  if [[ "$HAS_GUM" == true ]]; then
    gum input --header "$prompt" --password --placeholder "********"
    return
  fi

  local answer
  read -r -s -p "$prompt: " answer || true
  printf "\n" >&2
  printf "%s" "$answer"
}

ui_step() {
  local label="$1"
  shift
  local use_spinner=false

  if [[ "$HAS_GUM" == true && "$INTERACTIVE" == true ]] \
     && ! declare -F "$1" >/dev/null 2>&1; then
    use_spinner=true
  fi

  if [[ "$use_spinner" == true ]]; then
    if [[ -n "$LOG_FILE" ]]; then
      gum spin --spinner dot --title "  $label" \
        -- bash -c '"$@" >>"$0" 2>&1' "$LOG_FILE" "$@"
    else
      gum spin --spinner dot --title "  $label" -- "$@"
    fi
  else
    if [[ "$HAS_GUM" != true ]]; then
      printf "%s[....]%s %s\n" "$C_CYAN" "$C_RESET" "$label"
    fi
    if [[ -n "$LOG_FILE" ]]; then
      "$@" >>"$LOG_FILE" 2>&1
    else
      "$@"
    fi
  fi
}

ui_error() {
  if [[ "$HAS_GUM" == true ]]; then
    gum style --foreground 1 "✗ $1" >&2
  else
    printf "%s[FAIL]%s %s\n" "$C_RED" "$C_RESET" "$1" >&2
  fi
}

ui_warn() {
  if [[ "$HAS_GUM" == true ]]; then
    gum style --foreground 3 "⚠ $1"
  else
    printf "%s[WARN]%s %s\n" "$C_YELLOW" "$C_RESET" "$1"
  fi
}

ui_summary() {
  local selected_action="$1"
  local label item service
  label="$(action_label "$selected_action")"

  local border_color=2
  [[ $FAILED_STEPS -gt 0 ]] && border_color=1

  local summary_lines=()
  summary_lines+=("Aktion:          $label")
  summary_lines+=("Erfolgreich:     $SUCCESS_STEPS")
  [[ $FAILED_STEPS -gt 0 ]] && summary_lines+=("Fehlgeschlagen:  $FAILED_STEPS")

  if [[ ${#SUMMARY_ITEMS[@]} -gt 0 ]]; then
    summary_lines+=("")
    summary_lines+=("Ergebnis:")
    for item in "${SUMMARY_ITEMS[@]}"; do
      summary_lines+=("  • $item")
    done
  fi

  if [[ ${#WARNING_ITEMS[@]} -gt 0 ]]; then
    summary_lines+=("")
    summary_lines+=("Hinweise:")
    for item in "${WARNING_ITEMS[@]}"; do
      summary_lines+=("  ⚠ $item")
    done
  fi

  if [[ ${#STATUS_SERVICES[@]} -gt 0 ]]; then
    summary_lines+=("")
    summary_lines+=("Service-Befehle:")
    for service in "${STATUS_SERVICES[@]}"; do
      summary_lines+=("  systemctl status $service --no-pager")
      summary_lines+=("  journalctl -u $service -n 50 --no-pager")
    done
    summary_lines+=("")
    summary_lines+=("Logs: /var/log/msa/")
  fi

  [[ -n "$LOG_FILE" ]] && summary_lines+=("Logfile: $LOG_FILE")

  printf "\n"
  {
    gum style --bold "Zusammenfassung"
    printf "\n"
    printf "%s\n" "${summary_lines[@]}"
  } | gum style --border double --padding "1 3" --border-foreground "$border_color"
}

# ── Ausgabehilfen ──────────────────────────────────────────────────────────

print_banner() {
  ui_header "MSA Setup / Management" "Repo: $BASE_DIR"
}

print_section() {
  local title="$1"
  if [[ "$HAS_GUM" == true ]]; then
    printf "\n"
    gum style --bold --foreground 6 "── $title ──"
  else
    printf "\n%s== %s ==%s\n" "$C_BOLD" "$title" "$C_RESET"
  fi
}

print_info() {
  if [[ "$HAS_GUM" == true ]]; then
    gum style --foreground 4 "ℹ $1"
  else
    printf "%s[INFO]%s %s\n" "$C_BLUE" "$C_RESET" "$1"
  fi
}

print_warn() { ui_warn "$1"; }

print_error() { ui_error "$1"; }

print_ok() {
  if [[ "$HAS_GUM" == true ]]; then
    gum style --foreground 2 "✓ $1"
  else
    printf "%s[ OK ]%s %s\n" "$C_GREEN" "$C_RESET" "$1"
  fi
}

# ── gum (optional, Linux) ─────────────────────────────────────────────────

gum_linux_arch_slug() {
  local m
  m="$(uname -m 2>/dev/null || echo "")"
  case "$m" in
    x86_64|amd64)        printf "x86_64" ;;
    aarch64|arm64)       printf "arm64" ;;
    armv7l)              printf "armv7" ;;
    armv6l)              printf "armv6" ;;
    armv5*)              printf "armv6" ;;
    armhf)               printf "armv7" ;;
    i686|i386)           printf "i386" ;;
    *)                   return 1 ;;
  esac
}

gum_vendor_release_subdir() {
  local a
  a="$(gum_linux_arch_slug)" || return 1
  printf "Linux_%s" "$a"
}

gum_vendored_binary_path() {
  local root sub
  root="${GUM_VENDOR_ROOT:-}"
  [[ -n "$root" ]] || return 1
  sub="$(gum_vendor_release_subdir)" || return 1
  printf "%s/%s/gum" "$root" "$sub"
}

install_gum_copy_to_prefix() {
  local gum_bin="$1"
  local prefix="${GUM_INSTALL_PREFIX:-/usr/local/bin}"

  if ! mkdir -p "$prefix"; then
    ui_error "gum: Zielverzeichnis nicht anlegbar: $prefix"
    return 1
  fi
  if ! install -m 0755 "$gum_bin" "$prefix/gum"; then
    ui_error "gum: Kopieren nach $prefix/gum fehlgeschlagen."
    return 1
  fi
  hash -r 2>/dev/null || true
  return 0
}

install_gum_from_vendor() {
  local src=""
  if [[ -n "${MSA_GUM_BINARY:-}" ]]; then
    src="$MSA_GUM_BINARY"
  else
    src="$(gum_vendored_binary_path)" || return 1
  fi
  if [[ ! -f "$src" || ! -s "$src" ]]; then
    return 1
  fi
  install_gum_copy_to_prefix "$src"
}

gum_download() {
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --max-time 300 "$url" -o "$out"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$out" --timeout=300 "$url"
  else
    return 1
  fi
}

gum_resolve_version() {
  if [[ -n "${GUM_VERSION:-}" ]]; then
    printf "%s" "$GUM_VERSION"
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    local v
    v="$(python3 <<'PY'
import json
import urllib.request

req = urllib.request.Request(
    "https://api.github.com/repos/charmbracelet/gum/releases/latest",
    headers={"User-Agent": "msa-install_msa", "Accept": "application/vnd.github+json"},
)
with urllib.request.urlopen(req, timeout=60) as resp:
    tag = json.load(resp)["tag_name"]
print(tag[1:] if tag.startswith("v") else tag)
PY
)" && [[ -n "$v" ]] && printf "%s" "$v" && return 0
  fi
  local json tag
  json="$(curl -fsSL --max-time 60 \
    -H "Accept: application/vnd.github+json" \
    -A "msa-install_msa" \
    "https://api.github.com/repos/charmbracelet/gum/releases/latest")" || return 1
  tag="$(printf "%s" "$json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\([^"]*\)".*/\1/p' | head -n1)"
  [[ -n "$tag" ]] || return 1
  printf "%s" "$tag"
}

install_gum_from_github() {
  local ver arch_slug url tmpdir tgz gum_bin
  arch_slug="$(gum_linux_arch_slug)" || {
    ui_error "gum: Nicht unterstuetzte CPU-Architektur: $(uname -m 2>/dev/null || echo unknown)"
    return 1
  }
  ver="$(gum_resolve_version)" || {
    ui_error "gum: Release-Version konnte nicht ermittelt werden."
    return 1
  }
  url="https://github.com/charmbracelet/gum/releases/download/v${ver}/gum_${ver}_Linux_${arch_slug}.tar.gz"

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/msa-gum.XXXXXX")" || return 1
  tgz="$tmpdir/gum.tgz"

  set +e
  gum_download "$url" "$tgz"
  local dl_rc=$?
  set -e
  if [[ $dl_rc -ne 0 ]]; then
    rm -rf "$tmpdir"
    ui_error "gum: Download fehlgeschlagen (${url})."
    return 1
  fi

  if ! tar -xzf "$tgz" -C "$tmpdir"; then
    rm -rf "$tmpdir"
    ui_error "gum: Archiv konnte nicht entpackt werden."
    return 1
  fi

  gum_bin="$(find "$tmpdir" -type f -name gum 2>/dev/null | head -n1)"
  if [[ -z "$gum_bin" || ! -f "$gum_bin" ]]; then
    rm -rf "$tmpdir"
    ui_error "gum: Binary nicht im Archiv gefunden."
    return 1
  fi

  set +e
  install_gum_copy_to_prefix "$gum_bin"
  local inst_rc=$?
  set -e
  rm -rf "$tmpdir"
  if [[ $inst_rc -ne 0 ]]; then
    return 1
  fi
  return 0
}

install_gum_from_vendor_or_github() {
  GUM_LAST_INSTALL_SOURCE=""
  if install_gum_from_vendor; then
    GUM_LAST_INSTALL_SOURCE="vendor"
    return 0
  fi
  if install_gum_from_github; then
    GUM_LAST_INSTALL_SOURCE="github"
    return 0
  fi
  return 1
}

msa_no_auto_gum_active() {
  case "${MSA_NO_AUTO_GUM:-}" in
    1|true|TRUE|yes|Yes|y|Y) return 0 ;;
    *) return 1 ;;
  esac
}

maybe_offer_gum_install() {
  if command -v gum >/dev/null 2>&1; then
    refresh_has_gum
    return 0
  fi

  if [[ "$(uname -s)" != "Linux" ]]; then
    [[ "$AUTO_INSTALL_GUM" == true ]] \
      && print_warn "gum: Installation nur unter Linux moeglich."
    return 0
  fi

  if [[ "$EUID" -ne 0 ]]; then
    [[ "$AUTO_INSTALL_GUM" == true ]] \
      && print_warn "gum: Installation erfordert Root (z. B. sudo $0)."
    return 0
  fi

  if msa_no_auto_gum_active && [[ "$AUTO_INSTALL_GUM" != true ]]; then
    return 0
  fi

  print_info "gum fehlt – Installation wird versucht (${GUM_INSTALL_PREFIX:-/usr/local/bin}; MSA_GUM_BINARY / GUM_VENDOR_ROOT, sonst GitHub) …"
  set +e
  install_gum_from_vendor_or_github
  local rc=$?
  set -e

  refresh_has_gum

  if [[ $rc -eq 0 ]]; then
    case "${GUM_LAST_INSTALL_SOURCE:-}" in
      vendor) print_ok "gum installiert (lokale Quelle)." ;;
      github) print_ok "gum installiert (GitHub-Release)." ;;
      *)      print_ok "gum installiert." ;;
    esac
    return 0
  fi
  print_warn "gum wurde nicht installiert; es erfolgt weiterhin klassische Textein-/ausgabe."
  return 0
}

# ── Summary-Tracking ──────────────────────────────────────────────────────

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

# ── Schritt-Ausfuehrung ──────────────────────────────────────────────────

run_step() {
  local label="$1"
  shift
  local rc=0

  set +e
  ui_step "$label" "$@"
  rc=$?
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

# ── Pruefhilfen ───────────────────────────────────────────────────────────

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

# ── Eingabehilfen (Wrapper um UI-Layer) ───────────────────────────────────

ask_yes_no() {
  ui_confirm "$1" "${2:-y}"
}

ask_input() {
  local prompt="$1"
  local default="$2"
  local result_var="$3"
  local answer
  answer="$(ui_input "$prompt" "$default")"
  printf -v "$result_var" "%s" "$answer"
}

ask_secret_required() {
  local prompt="$1"
  local result_var="$2"
  local answer=""

  if [[ "$INTERACTIVE" != true || "$HAS_TTY" != true ]]; then
    printf -v "$result_var" "%s" ""
    return 0
  fi

  while true; do
    answer="$(ui_secret "$prompt")"
    if [[ -n "$answer" ]]; then
      printf -v "$result_var" "%s" "$answer"
      return 0
    fi
    ui_warn "Eingabe darf nicht leer sein."
  done
}

# ── Token / Hostname ─────────────────────────────────────────────────────

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

# ── Datei- und YAML-Hilfen ───────────────────────────────────────────────

show_file_preview() {
  local path="$1"
  print_section "Datei: $path"
  sed -n '1,200p' "$path"
}

choose_existing_config_action() {
  local label="$1"
  local path="$2"

  if [[ ! -f "$path" ]]; then
    CONFIG_ACTION="create"
    return 0
  fi

  if [[ "$INTERACTIVE" != true || "$HAS_TTY" != true ]]; then
    print_info "[$label] Bestehende Konfiguration bleibt erhalten: $path"
    CONFIG_ACTION="keep"
    return 0
  fi

  print_info "$label existiert bereits: $path"

  if [[ "$HAS_GUM" == true ]]; then
    local choice
    while true; do
      choice="$(gum choose --header "Konfiguration: $path" \
        "Behalten" "Ueberschreiben" "Anzeigen")" || true
      case "$choice" in
        "Behalten")        CONFIG_ACTION="keep";      return 0 ;;
        "Ueberschreiben")  CONFIG_ACTION="overwrite";  return 0 ;;
        "Anzeigen")        show_file_preview "$path" ;;
        *)                 ui_warn "Bitte eine Option waehlen." ;;
      esac
    done
  else
    local choice
    while true; do
      printf "%s[INFO]%s %s existiert bereits: %s\n" "$C_BLUE" "$C_RESET" "$label" "$path"
      printf "  k) behalten\n"
      printf "  o) ueberschreiben\n"
      printf "  a) anzeigen\n"
      read -r -p "Auswahl [k/o/a] " choice || true
      choice="${choice:-k}"
      case "${choice,,}" in
        k) CONFIG_ACTION="keep";      return 0 ;;
        o) CONFIG_ACTION="overwrite";  return 0 ;;
        a) show_file_preview "$path" ;;
        *) print_warn "Bitte 'k', 'o' oder 'a' eingeben." ;;
      esac
    done
  fi
}

set_yaml_value() {
  local file="$1"
  local key="$2"
  local value="$3"
  local escaped

  escaped="$(printf "%s" "$value" | sed -e 's/[\\&|]/\\&/g' -e 's/"/\\"/g')"

  if grep -Eq "^${key}:" "$file"; then
    sed -i -E "s|^${key}:.*$|${key}: \"${escaped}\"|" "$file"
  else
    printf "\n%s: \"%s\"\n" "$key" "$escaped" >>"$file"
  fi
}

set_hub_security_string() {
  local file="$1"
  local key="$2"
  local value="$3"
  local escaped

  escaped="$(printf "%s" "$value" | sed -e 's/[\\&|]/\\&/g' -e 's/"/\\"/g')"

  if grep -Eq "^[[:space:]]{2}${key}:" "$file"; then
    sed -i -E "s|^[[:space:]]{2}${key}:.*$|  ${key}: \"${escaped}\"|" "$file"
  else
    sed -i -E "/^security:/a\  ${key}: \"${escaped}\"" "$file"
  fi
}

set_hub_security_bool() {
  local file="$1"
  local key="$2"
  local value="$3"

  if grep -Eq "^[[:space:]]{2}${key}:" "$file"; then
    sed -i -E "s|^[[:space:]]{2}${key}:.*$|  ${key}: ${value}|" "$file"
  else
    sed -i -E "/^security:/a\  ${key}: ${value}" "$file"
  fi
}

copy_file() {
  local source="$1"
  local target="$2"
  cp "$source" "$target"
}

# ── SAT/HUB Konfiguration ───────────────────────────────────────────────

configure_sat_bootstrap_values() {
  local target="$1"
  local host sat_default sat_id hub_url

  host="$(default_hostname_token)"
  sat_default="$(generate_default_sat_id "$host")"
  ask_input "[SAT] SAT-ID setzen" "$sat_default" sat_id
  sat_id="$(sanitize_token "$sat_id")"

  if [[ -z "$sat_id" ]]; then
    sat_id="$sat_default"
  fi

  ask_input "[SAT] HUB-URL setzen (ohne Slash am Ende)" "http://hub.example.local:8080" hub_url

  run_step "SAT-ID in sat_config.yaml setzen" set_yaml_value "$target" "sat_id" "$sat_id" || return 1
  run_step "Hostname in sat_config.yaml setzen" set_yaml_value "$target" "hostname" "$host" || return 1
  run_step "HUB-URL in sat_config.yaml setzen" set_yaml_value "$target" "hub_url" "$hub_url" || return 1
  add_summary "SAT Konfiguration aktiv: $target (sat_id=$sat_id, hostname=$host, hub_url=$hub_url)"
}

configure_sat_security_values() {
  local target="$1"
  local shared_secret=""

  print_section "SAT Security"
  ask_secret_required "[SAT] Shared Secret fuer Hub-Kommunikation" shared_secret

  if [[ -n "$shared_secret" ]]; then
    run_step "Shared Secret in sat_config.yaml setzen" set_yaml_value "$target" "shared_secret" "$shared_secret" || return 1
    add_summary "SAT Shared Secret gesetzt: $target"
  else
    add_warning "SAT Shared Secret wurde nicht gesetzt (nicht-interaktiv). Bitte manuell in $target eintragen."
  fi
}

configure_hub_security_values() {
  local target="$1"
  local ui_auth_enabled="true"
  local admin_username="admin"
  local admin_password=""
  local shared_secret=""

  print_section "HUB Security"

  if ask_yes_no "[HUB] Frontend-Authentifizierung aktivieren?" "y"; then
    ui_auth_enabled="true"
    ask_input "[HUB] Admin-Benutzername" "admin" admin_username
    ask_secret_required "[HUB] Admin-Passwort" admin_password
  else
    ui_auth_enabled="false"
  fi

  ask_secret_required "[HUB] Shared Secret fuer SAT-Kommunikation" shared_secret

  run_step "ui_auth_enabled in hub_config.yaml setzen" set_hub_security_bool "$target" "ui_auth_enabled" "$ui_auth_enabled" || return 1

  if [[ "$ui_auth_enabled" == "true" && -z "$admin_password" ]]; then
    add_warning "HUB UI-Auth wurde ohne Passwort angefordert. Setze ui_auth_enabled=false (sicherer Default)."
    ui_auth_enabled="false"
    run_step "ui_auth_enabled in hub_config.yaml auf false setzen" set_hub_security_bool "$target" "ui_auth_enabled" "false" || return 1
  fi

  if [[ "$ui_auth_enabled" == "true" ]]; then
    run_step "admin_username in hub_config.yaml setzen" set_hub_security_string "$target" "admin_username" "$admin_username" || return 1
    run_step "admin_password in hub_config.yaml setzen" set_hub_security_string "$target" "admin_password" "$admin_password" || return 1
    add_summary "HUB UI-Auth aktiviert: $target (admin_username=$admin_username)"
  else
    add_summary "HUB UI-Auth deaktiviert: $target"
  fi

  if [[ -n "$shared_secret" ]]; then
    run_step "shared_secret in hub_config.yaml setzen" set_hub_security_string "$target" "shared_secret" "$shared_secret" || return 1
    add_summary "HUB Shared Secret gesetzt: $target"
  else
    add_warning "HUB Shared Secret wurde nicht gesetzt (nicht-interaktiv). Bitte manuell in $target eintragen."
  fi
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
      configure_sat_security_values "$target" || return 1
      ;;
    overwrite)
      run_step "SAT Konfiguration mit Beispiel ueberschreiben" copy_file "$example" "$target" || return 1
      configure_sat_bootstrap_values "$target" || return 1
      configure_sat_security_values "$target" || return 1
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
      configure_hub_security_values "$target" || return 1
      add_summary "HUB Konfiguration erstellt: $target"
      ;;
    overwrite)
      run_step "HUB Konfiguration mit Beispiel ueberschreiben" copy_file "$example" "$target" || return 1
      configure_hub_security_values "$target" || return 1
      add_summary "HUB Konfiguration ueberschrieben: $target"
      ;;
    *)
      print_error "Unbekannte HUB Konfigurationsaktion: $action"
      return 1
      ;;
  esac
}

# ── System-Hilfen ────────────────────────────────────────────────────────

apt_base_opts() {
  printf "%s\n" \
    "-o" "DPkg::Lock::Timeout=${APT_LOCK_TIMEOUT}" \
    "-o" "Dpkg::Options::=--force-confdef" \
    "-o" "Dpkg::Options::=--force-confold"
}

apt_with_retry() {
  local label="$1"
  shift

  local attempt=1
  local max_attempts="$APT_RETRIES"
  local rc=0

  while true; do
    if timeout "${APT_CMD_TIMEOUT}s" "$@"; then
      return 0
    fi

    rc=$?
    if [[ $attempt -ge $max_attempts ]]; then
      print_error "$label fehlgeschlagen nach ${attempt} Versuch(en)."
      print_error "Wenn ein unterbrochener dpkg-Zustand vorliegt, pruefe manuell: dpkg --configure -a && apt-get -f install"
      return "$rc"
    fi

    print_warn "$label fehlgeschlagen (Versuch ${attempt}/${max_attempts}, rc=$rc)."
    if [[ "$rc" -eq 124 ]]; then
      print_warn "Timeout nach ${APT_CMD_TIMEOUT}s (evtl. Lock oder blockierende Paketkonfiguration)."
    fi

    if ! apt_try_repair_noninteractive; then
      print_warn "Automatischer Repair war nicht erfolgreich; erneuter Versuch folgt trotzdem."
    fi

    sleep "$APT_RETRY_BACKOFF_SECONDS"
    attempt=$((attempt + 1))
  done
}

apt_run_update() {
  local apt_opts=()
  mapfile -t apt_opts < <(apt_base_opts)

  apt_with_retry \
    "APT update" \
    env DEBIAN_FRONTEND=noninteractive apt-get "${apt_opts[@]}" update
}

apt_run_install() {
  local packages=("$@")
  local apt_opts=()
  mapfile -t apt_opts < <(apt_base_opts)

  apt_with_retry \
    "APT install" \
    env DEBIAN_FRONTEND=noninteractive apt-get "${apt_opts[@]}" install -y "${packages[@]}"
}

apt_try_repair_noninteractive() {
  local apt_opts=()
  mapfile -t apt_opts < <(apt_base_opts)

  print_info "Versuche automatische APT/DPKG-Reparatur (non-interactive)."

  if ! timeout "${APT_CMD_TIMEOUT}s" env DEBIAN_FRONTEND=noninteractive dpkg --configure -a; then
    print_warn "dpkg --configure -a fehlgeschlagen."
    return 1
  fi

  if ! timeout "${APT_CMD_TIMEOUT}s" env DEBIAN_FRONTEND=noninteractive apt-get "${apt_opts[@]}" -f install -y; then
    print_warn "apt-get -f install fehlgeschlagen."
    return 1
  fi

  return 0
}

ensure_base_packages() {
  print_section "Systempakete"
  run_step "APT Paketindex aktualisieren" apt_run_update || return 1
  run_step "Grundpakete installieren" apt_run_install "${APT_PACKAGES[@]}" || return 1
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

# ── Installation / Deinstallation ────────────────────────────────────────

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

# ── Preflight ────────────────────────────────────────────────────────────

preflight_common() {
  print_section "Preflight"
  run_step "Root-Rechte pruefen" require_root || return 1
  run_step "Arbeitsverzeichnis pruefen" require_dir "$BASE_DIR" || return 1
  run_step "APT Verfuegbarkeit pruefen" require_command apt-get || return 1
  run_step "timeout Verfuegbarkeit pruefen" require_command timeout || return 1
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
    venv-only)      preflight_venv_only ;;
    install-sat)    preflight_sat_install ;;
    install-hub)    preflight_hub_install ;;
    install-all)    preflight_sat_install; preflight_hub_install ;;
    uninstall-sat)  preflight_sat_uninstall ;;
    uninstall-hub)  preflight_hub_uninstall ;;
    uninstall-all)  preflight_sat_uninstall; preflight_hub_uninstall ;;
    *)
      print_error "Unbekannte Aktion: $selected_action"
      return 1
      ;;
  esac
}

# ── Review-Screen ────────────────────────────────────────────────────────

show_review() {
  local selected_action="$1"
  local label
  label="$(action_label "$selected_action")"

  local lines=()
  lines+=("Aktion:          $label")

  case "$selected_action" in install-sat|install-all)
    lines+=("SAT-Verzeichnis: $SAT_DIR") ;; esac
  case "$selected_action" in install-hub|install-all)
    lines+=("HUB-Verzeichnis: $HUB_DIR") ;; esac
  case "$selected_action" in uninstall-sat|uninstall-all)
    lines+=("SAT-Verzeichnis: $SAT_DIR") ;; esac
  case "$selected_action" in uninstall-hub|uninstall-all)
    lines+=("HUB-Verzeichnis: $HUB_DIR") ;; esac
  case "$selected_action" in install-*|venv-only)
    lines+=("Python venv:     $VENV_DIR") ;; esac

  lines+=("")
  lines+=("Geplante Schritte:")

  case "$selected_action" in
    venv-only)
      lines+=("  - APT-Pakete installieren/aktualisieren")
      lines+=("  - Python venv erstellen/aktualisieren")
      ;;
    install-sat)
      lines+=("  - APT-Pakete installieren/aktualisieren")
      lines+=("  - Python venv erstellen/aktualisieren")
      lines+=("  - SAT konfigurieren")
      lines+=("  - SAT systemd-Service anlegen")
      ;;
    install-hub)
      lines+=("  - APT-Pakete installieren/aktualisieren")
      lines+=("  - Python venv erstellen/aktualisieren")
      lines+=("  - HUB konfigurieren")
      lines+=("  - HUB systemd-Service anlegen")
      ;;
    install-all)
      lines+=("  - APT-Pakete installieren/aktualisieren")
      lines+=("  - Python venv erstellen/aktualisieren")
      lines+=("  - SAT + HUB konfigurieren")
      lines+=("  - SAT + HUB systemd-Services anlegen")
      ;;
    uninstall-sat)
      lines+=("  - SAT systemd-Service entfernen")
      ;;
    uninstall-hub)
      lines+=("  - HUB systemd-Service entfernen")
      ;;
    uninstall-all)
      lines+=("  - SAT + HUB systemd-Services entfernen")
      ;;
  esac

  if [[ "$HAS_GUM" == true ]]; then
    printf "\n"
    {
      gum style --bold --foreground 4 "Aktionsuebersicht"
      printf "\n"
      printf "%s\n" "${lines[@]}"
    } | gum style --border rounded --padding "1 2" --border-foreground 4
  else
    print_section "Aktionsuebersicht"
    local line
    for line in "${lines[@]}"; do
      printf "  %s\n" "$line"
    done
  fi

  if [[ "$INTERACTIVE" == true && "$HAS_TTY" == true ]]; then
    printf "\n"
    ui_confirm "Fortfahren?" "y" || { printf "Abgebrochen.\n"; return 1; }
  fi
}

# ── Menue und Aktionen ──────────────────────────────────────────────────

action_label() {
  case "$1" in
    venv-only)      printf "Nur venv installieren/aktualisieren" ;;
    install-sat)    printf "SAT installieren" ;;
    install-hub)    printf "HUB installieren" ;;
    install-all)    printf "SAT + HUB installieren" ;;
    uninstall-sat)  printf "SAT deinstallieren" ;;
    uninstall-hub)  printf "HUB deinstallieren" ;;
    uninstall-all)  printf "SAT + HUB deinstallieren" ;;
    *)              printf "%s" "$1" ;;
  esac
}

show_menu() {
  if [[ "$HAS_GUM" == true ]]; then
    local items=(
      "SAT installieren"
      "HUB installieren"
      "SAT + HUB installieren"
      "venv-only"
      "SAT deinstallieren"
      "HUB deinstallieren"
      "Alles deinstallieren"
      "Beenden"
    )
    local choice
    choice="$(gum choose --header "MSA Setup" "${items[@]}")" || true

    case "$choice" in
      "SAT installieren")         ACTION="install-sat" ;;
      "HUB installieren")         ACTION="install-hub" ;;
      "SAT + HUB installieren")   ACTION="install-all" ;;
      "venv-only")                ACTION="venv-only" ;;
      "SAT deinstallieren")       ACTION="uninstall-sat" ;;
      "HUB deinstallieren")       ACTION="uninstall-hub" ;;
      "Alles deinstallieren")     ACTION="uninstall-all" ;;
      "Beenden")
        printf "Beendet.\n"
        exit 0
        ;;
      *) ACTION="" ;;
    esac
  else
    print_section "Menue"
    printf "  0) Nur venv / Python-Requirements installieren oder aktualisieren\n"
    printf "  1) SAT installieren\n"
    printf "  2) HUB installieren\n"
    printf "  3) SAT + HUB installieren\n"
    printf "  4) SAT deinstallieren\n"
    printf "  5) HUB deinstallieren\n"
    printf "  6) SAT + HUB deinstallieren\n"
    printf "  q) Beenden\n\n"

    local choice
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
  fi
}

execute_action() {
  local selected_action="$1"

  run_preflight_for_action "$selected_action"

  case "$selected_action" in
    venv-only)      install_venv_only ;;
    install-sat)    install_sat ;;
    install-hub)    install_hub ;;
    install-all)    install_sat; install_hub ;;
    uninstall-sat)  uninstall_sat; ask_remove_venv_if_unused ;;
    uninstall-hub)  uninstall_hub; ask_remove_venv_if_unused ;;
    uninstall-all)  uninstall_sat; uninstall_hub; ask_remove_venv_if_unused ;;
    *)
      print_error "Unbekannte Aktion: $selected_action"
      return 1
      ;;
  esac
}

print_summary() {
  local selected_action="$1"
  local label item service
  label="$(action_label "$selected_action")"

  if [[ "$HAS_GUM" == true ]]; then
    ui_summary "$selected_action"
    return
  fi

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

  [[ -n "$LOG_FILE" ]] && printf "%sLogfile:%s %s\n" "$C_BOLD" "$C_RESET" "$LOG_FILE"
}

# ── Aktionsausfuehrung ──────────────────────────────────────────────────

run_selected_action() {
  local selected_action="$1"
  local rc

  reset_summary

  show_review "$selected_action" || return 1

  set +e
  execute_action "$selected_action"
  rc=$?
  set -e

  print_summary "$selected_action"
  return "$rc"
}

# ── CLI ──────────────────────────────────────────────────────────────────

print_usage() {
  cat <<EOF
Verwendung: $(basename "$0") [optionen] [aktion]

Optionen:
  --non-interactive   Keine interaktiven Fragen
  --install-gum       gum-Installation auch bei gesetztem MSA_NO_AUTO_GUM=1 versuchen

Hinweis: Unter Linux als Root wird fehlendes gum installiert: MSA_GUM_BINARY oder
  GUM_VENDOR_ROOT/Linux_<Arch>/gum, sonst GitHub. MSA_NO_AUTO_GUM=1 unterbindet den Versuch.

Aktionen:
  venv-only
  install-sat
  install-hub
  install-all
  uninstall-sat
  uninstall-hub
  uninstall-all

Umgebungsvariablen:
  MSA_LOG_FILE         Pfad zu einer Logdatei
  MSA_NO_AUTO_GUM      1/true/y: keinen automatischen gum-Install-Versuch (Root/Linux)
  NO_COLOR             Farbausgabe deaktivieren
  GUM_VERSION          z. B. 0.17.0 (Default: aktuelles GitHub-Release)
  GUM_INSTALL_PREFIX   Zielverzeichnis fuer gum (Default: /usr/local/bin)
  GUM_VENDOR_ROOT      Verzeichnis mit Linux_<arch>/gum (leer = kein lokaler Baum)
  MSA_GUM_BINARY       Voller Pfad zu gum (vor GUM_VENDOR_ROOT)

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
      --install-gum)
        AUTO_INSTALL_GUM=true
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

main() {
  local rc

  parse_args "$@"
  maybe_offer_gum_install
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
