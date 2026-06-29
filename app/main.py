# main.py — capturer la boucle AVANT de lancer les threads
import asyncio
import threading as th
import time
import sys
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.sniffer import Sniffer
from core.analyser import Analyser
from core.forencic import Forensic
from api.routes.include import router
from core.yara_engine import start_auto_update
from core.monitoring.agent import Agent, MongoBackend

class IDSEngine:

    origins = ["http://localhost:5173"]
    PREFIX = "/api"

    def __init__(self):
        self.app = FastAPI(title="Lenyx IDS API")
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=self.origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        self.app.include_router(router, prefix=self.PREFIX)

        self.analyser = Analyser()
        self.sniffer  = Sniffer(self.analyser)

        self.is_running = True

    def monitor_background(self):
        while self.is_running:
            if self.ids_thread and not self.ids_thread.is_alive():
                print("[!] Alerte : Le thread du sniffer s'est arrêté !")
                break
            time.sleep(1)

    def start(self):
        print("[DEBUG] Lenyx IDS is starting...")

        #  Démarrerage du sniffer
        self.ids_thread = th.Thread(
            target=self.sniffer.start_sniffing,
            name="CyberForensic-Sniffer",
            daemon=True
        )
        self.ids_thread.start()

        Forensic.init_pcap_file()
        Forensic.start_buffer_flusher()

        self.monitor_thread = th.Thread(
            target=self.monitor_background,
            name="CyberForensic-Monitor",
            daemon=True
        )
        self.monitor_thread.start()

        print(f"[*] Moteur de détection activé sur : {self.ids_thread.name}")

        # ─── Startup event — capturer la boucle uvicorn ───────
        @self.app.on_event("startup")
        async def on_startup():
            """Stocke la boucle asyncio uvicorn pour les broadcasts threads"""
            loop = asyncio.get_event_loop()
            from api.utils import loop_holder
            loop_holder.LOOP = loop
            print(f"[*] Boucle asyncio capturée : {loop}")

            th.Thread(target=start_auto_update, daemon=True).start()

          
            backend = MongoBackend(uri="mongodb://database-mongo:27017/")
            agent   = Agent(backend=backend, interval=10, verbose=True)
            th.Thread(target=agent.start, name="MonitorAgent-backend", daemon=True).start()
            print("[*] Agent monitoring démarré sur le backend")

        try:
            uvicorn.run(self.app, host="0.0.0.0", port=8000, log_level="info")
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        print("\n[!] Arrêt...")
        self.is_running = False
        sys.exit(0)

if __name__ == "__main__":
    engine = IDSEngine()
    engine.start()