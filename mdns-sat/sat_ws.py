# sat_ws.py
import asyncio
import json
import logging
import threading
from typing import Any, Dict, Callable, Optional
from urllib.parse import urlencode

import websockets  # in requirements aufnehmen
from mdns_mode import is_publish_to_hub_enabled

logger = logging.getLogger("mdns-sat.ws")

class SatWebSocketClient:
    """
    Einfacher WS-Client für den Sat.
    - Baut eine persistente Verbindung zum Hub auf.
    - Schickt regelmäßig Status/Service-Meldungen.
    - Reagiert auf hub.config.update / hub.assignments.update.
    """

    def __init__(
        self,
        cfg: Dict[str, Any],
        on_message: Callable[[Dict[str, Any]], None],
        stop_event: threading.Event,
    ):
        self.cfg = cfg
        self.on_message = on_message
        self.stop_event = stop_event
        self.thread: Optional[threading.Thread] = None

        self.status_interval = int(cfg.get("hub_ws_status_interval", 30))
        self.send_services = bool(cfg.get("hub_ws_send_services", True)) and is_publish_to_hub_enabled(cfg)
        self.reconnect_interval = int(cfg.get("hub_ws_reconnect_interval", 5))

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        asyncio.run(self._loop())

    async def _loop(self):
        ws_url = self._build_ws_url()
        logger.info(f"[WS] Verbinde zu Hub-WS: {ws_url}")

        while not self.stop_event.is_set():
            try:
                async with websockets.connect(ws_url, ping_interval=30, ping_timeout=10) as ws:
                    logger.info("[WS] Verbindung zum Hub aufgebaut.")
                    await self._on_open(ws)

                    # zwei Tasks:
                    # - Reader: eingehende Messages
                    # - Periodic: Status/Services senden
                    consumer = asyncio.create_task(self._consumer(ws))
                    producer = asyncio.create_task(self._producer(ws))

                    done, pending = await asyncio.wait(
                        {consumer, producer},
                        return_when=asyncio.FIRST_EXCEPTION,
                    )
                    for task in pending:
                        task.cancel()

            except Exception as e:
                if self.stop_event.is_set():
                    break
                logger.warning(f"[WS] Verbindung verloren: {e}")
                await asyncio.sleep(self.reconnect_interval)

        logger.info("[WS] Client-Loop beendet.")

    def _build_ws_url(self) -> str:
        base = self.cfg.get("hub_ws_url")
        if not base:
            # von hub_url ableiten: http->ws, https->wss
            hub_url = self.cfg["hub_url"]
            if hub_url.startswith("https://"):
                base = "wss://" + hub_url[len("https://"):]
            elif hub_url.startswith("http://"):
                base = "ws://" + hub_url[len("http://"):]
            else:
                # Fallback
                base = "ws://" + hub_url
            # Endpunkt
            if not base.rstrip("/").endswith("/ws/sat"):
                base = base.rstrip("/") + "/ws/sat"

        params = urlencode({
            "sat_id": self.cfg["sat_id"],
            "token": self.cfg["shared_secret"],
        })
        return f"{base}?{params}"

    async def _on_open(self, ws):
        # initiale Hello/Register-Nachricht
        msg = {
            "type": "sat.hello",
            "sat_id": self.cfg["sat_id"],
            "payload": {
                "hostname": self.cfg.get("hostname"),
                "software_version": self.cfg.get("software_version", "0.2.0"),
                "capabilities": [
                    "telemetry",
                    "services_snapshot",
                    # später: "logs", "iface_stats", ...
                ],
            },
        }
        await ws.send(json.dumps(msg))
        logger.info("[WS] sat.hello sent")

    async def _consumer(self, ws):
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning(f"[WS] Ungültiges JSON vom Hub: {raw!r}")
                continue
            self.on_message(msg)


    async def _producer(self, ws):
        """
        Periodisch Telemetrie und ggf. Services an den Hub schicken.
        (Services erstmal optional / seltener).
        """
        last_services_push = 0.0
        loop = asyncio.get_event_loop()

        while not self.stop_event.is_set():
            # Telemetrie
            telemetry_msg = await loop.run_in_executor(None, self._build_telemetry_message)
            if telemetry_msg:
                await ws.send(telemetry_msg)

            # Services evtl. mit größerem Intervall
            now = loop.time()
            if self.send_services and now - last_services_push > 60:  # z.B. alle 60s
                services_msg = await loop.run_in_executor(None, self._build_services_message)
                if services_msg:
                    await ws.send(services_msg)
                last_services_push = now

            await asyncio.sleep(self.status_interval)



    def _build_telemetry_message(self) -> Optional[str]:
        """
        Baut die Telemetrie-Nachricht für den Hub.
        Hier kannst du später CPU, RAM, Interface-Status etc. ergänzen.
        """
        from mdns_utils import SERVICE_CACHE, CACHE_LOCK

        with CACHE_LOCK:
            svc_count = len(SERVICE_CACHE)

        payload = {
            "service_count": svc_count,
            # TODO: später cpu_pct, mem_pct, iface_stats, ...
        }
        msg = {
            "type": "sat.telemetry",
            "sat_id": self.cfg["sat_id"],
            "payload": payload,
        }
        return json.dumps(msg)

    def _build_services_message(self) -> Optional[str]:
        # reuse deiner bestehenden build_service_snapshot(cfg)
        from mdns_utils import build_service_snapshot
        services = build_service_snapshot(self.cfg)
        msg = {
            "type": "sat.services.snapshot",
            "sat_id": self.cfg["sat_id"],
            "payload": {
                "services": services,
            },
        }
        return json.dumps(msg)
