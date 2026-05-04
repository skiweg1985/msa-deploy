#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Gemeinsame venv im Repo-Root
VENV_DIR = BASE_DIR / "venv"
VENV_PYTHON = VENV_DIR / "bin" / "python"

# Logging
LOG_DIR = Path("/var/log/msa")
LOGROTATE_DIR = Path("/etc/logrotate.d")

SERVICES = {
    "sat": {
        "name": "mdns-sat",
        "workdir": BASE_DIR / "mdns-sat",
        "exec": BASE_DIR / "mdns-sat" / "mdns_sat.py",
    },
    "hub": {
        "name": "mdns-hub",
        "workdir": BASE_DIR / "mdns-hub",
        "exec": BASE_DIR / "mdns-hub" / "main.py",
    },
}


def run(cmd: list[str]):
    print(f"$ {' '.join(cmd)}")
    subprocess.check_call(cmd)


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    """
    Einfaches Yes/No-Prompt.
    default=True bedeutet: Enter = Yes, default=False → Enter = No
    """
    default_str = "Y/n" if default else "y/N"

    while True:
        try:
            answer = input(f"{prompt} [{default_str}] ").strip().lower()
        except EOFError:
            # Falls keine TTY vorhanden ist: immer Default
            return default

        if not answer:
            return default

        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False

        print("Bitte 'y' oder 'n' eingeben.")


def get_python_exec() -> str:
    """
    Bevorzugt die Python-Exe aus der gemeinsamen venv.
    Fällt zurück auf das aktuelle Python, falls venv fehlt.
    """
    if VENV_PYTHON.exists():
        return str(VENV_PYTHON)
    # Fallback – sollte im Idealfall nie nötig sein
    return sys.executable


def build_unit(service_key: str) -> str:
    """
    Erzeugt den Inhalt der Unit-Datei für hub oder sat.
    Nutzt die venv im Repo-Root und schreibt Logs nach /var/log/msa/.
    """
    s = SERVICES[service_key]
    python_exec = get_python_exec()
    log_file = LOG_DIR / f"{s['name']}.log"

    return f"""[Unit]
Description=mDNS {service_key.upper()} Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={s['workdir']}
ExecStart={python_exec} {s['exec']}
Restart=on-failure
RestartSec=5
Environment=PYTHONUNBUFFERED=1
StandardOutput=append:{log_file}
StandardError=append:{log_file}

[Install]
WantedBy=multi-user.target
"""


def build_logrotate_content(service_name: str, log_path: Path) -> str:
    """
    logrotate-Konfiguration für einen Dienst.
    """
    return f"""{log_path} {{
    daily
    rotate 14
    size 10M
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}}
"""


def install_service(service_key: str):
    if os.geteuid() != 0:
        print("Bitte als root oder mit sudo ausführen.")
        sys.exit(1)

    if service_key not in SERVICES and service_key != "all":
        print("Unbekannter Service. Nutze: hub | sat | all")
        sys.exit(1)

    if service_key == "all":
        for s in SERVICES:
            install_service(s)
        return

    s = SERVICES[service_key]
    unit_file = Path("/etc/systemd/system") / f"{s['name']}.service"

    # Existiert das Hauptskript?
    if not s["exec"].exists():
        print(f"❌ ERROR: Hauptskript {s['exec']} nicht gefunden!")
        sys.exit(1)

    # Log-Verzeichnis sicherstellen
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"❌ Konnte Log-Verzeichnis {LOG_DIR} nicht anlegen: {e}")
        sys.exit(1)

    log_file = LOG_DIR / f"{s['name']}.log"
    if not log_file.exists():
        # Leere Datei anlegen
        log_file.touch(exist_ok=True)

    # Merken, ob der Service vorher schon existiert hat
    service_existed_before = unit_file.exists()

    # Unit schreiben
    print(f"→ Installiere Service {s['name']} …")
    content = build_unit(service_key)
    unit_file.write_text(content, encoding="utf-8")

    # logrotate-Konfig schreiben
    logrotate_file = LOGROTATE_DIR / s["name"]
    lr_content = build_logrotate_content(s["name"], log_file)
    print(f"→ Schreibe logrotate-Konfiguration: {logrotate_file}")
    logrotate_file.write_text(lr_content, encoding="utf-8")

    # systemd neu einlesen
    run(["systemctl", "daemon-reload"])

    if not service_existed_before:
        # Frische Installation: enable + start
        run(["systemctl", "enable", "--now", s["name"]])
        print(f"✅ Service '{s['name']}' installiert & gestartet.\n")
    else:
        # Update einer bestehenden Unit
        print(f"⚠ Service {s['name']} existierte bereits.")
        # sicherstellen, dass er enabled ist (starten machen wir getrennt)
        run(["systemctl", "enable", s["name"]])

        if ask_yes_no("Unit-Datei wurde aktualisiert. Service jetzt neu starten?", default=True):
            run(["systemctl", "restart", s["name"]])
            print(f"🔄 Service '{s['name']}' wurde neu gestartet.\n")
        else:
            print(f"⏭ Service '{s['name']}' wurde NICHT neu gestartet.\n")

    print(f"   Logfile: {log_file}")
    print(f"   logrotate: {logrotate_file}")


def uninstall_service(service_key: str):
    if os.geteuid() != 0:
        print("Bitte als root oder mit sudo ausführen.")
        sys.exit(1)

    if service_key == "all":
        for s in SERVICES:
            uninstall_service(s)
        return

    if service_key not in SERVICES:
        print("Unbekannter Service. Nutze: hub | sat | all")
        sys.exit(1)

    s = SERVICES[service_key]
    unit_file = Path("/etc/systemd/system") / f"{s['name']}.service"
    logrotate_file = LOGROTATE_DIR / s["name"]

    print(f"→ Entferne Service {s['name']} …")

    # Service stoppen / deaktivieren
    try:
        run(["systemctl", "disable", "--now", s["name"]])
    except subprocess.CalledProcessError:
        print(f"⚠ Konnte {s['name']} ggf. nicht stoppen/deaktivieren (evtl. nicht existent).")

    # Unit-Datei löschen
    if unit_file.exists():
        print(f"→ Lösche {unit_file}")
        unit_file.unlink()

    # logrotate-Konfig löschen
    if logrotate_file.exists():
        print(f"→ Lösche logrotate-Konfig {logrotate_file}")
        logrotate_file.unlink()

    run(["systemctl", "daemon-reload"])

    print(f"🗑️  Service '{s['name']}' entfernt.\n")
    print("   Hinweis: Logfiles unter /var/log/msa/ bleiben erhalten.")


def service_status(service_key: str):
    if service_key == "all":
        for s in SERVICES:
            service_status(s)
        return

    if service_key not in SERVICES:
        print("Unbekannter Service. Nutze: hub | sat | all")
        sys.exit(1)

    run(["systemctl", "status", SERVICES[service_key]["name"]])


def service_restart(service_key: str):
    if service_key == "all":
        for s in SERVICES:
            service_restart(s)
        return

    if service_key not in SERVICES:
        print("Unbekannter Service. Nutze: hub | sat | all")
        sys.exit(1)

    run(["systemctl", "restart", SERVICES[service_key]["name"]])
    print(f"🔄 Service {SERVICES[service_key]['name']} restarted.\n")


def usage():
    print("""
Nutzen:
  manage_services.py install hub
  manage_services.py install sat
  manage_services.py install all

  manage_services.py uninstall hub
  manage_services.py uninstall sat
  manage_services.py uninstall all

  manage_services.py status hub|sat|all
  manage_services.py restart hub|sat|all
""")
    sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()

    action = sys.argv[1].lower()
    target = sys.argv[2].lower()

    if action == "install":
        install_service(target)
    elif action == "uninstall":
        uninstall_service(target)
    elif action == "status":
        service_status(target)
    elif action == "restart":
        service_restart(target)
    else:
        usage()