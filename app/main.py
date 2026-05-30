import threading as th
import time
import sys
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.sniffer import Sniffer
from core.analyser import Analyser
from core.forencic import Forensic
from api.routes.stream import router as stream_router

class IDSEngine:

    origins = [
        'http://localhost:5173'
    ]
    def __init__(self):
        self.app = FastAPI(title="Lenyx IDS API")
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=self.origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        self.app.include_router(stream_router, prefix="/api")
        
        self.analyser = Analyser()
        self.sniffer = Sniffer(self.analyser)
        
        self.is_running = True
        self.ids_thread = None
        self.api_thread = None

    def start_api(self):
        """Démarre le serveur Uvicorn (exécuté dans un thread dédié)"""
        uvicorn.run(self.app, host="0.0.0.0", port=8000, log_level="info")

    def start(self):       
        print("[DEBUG] Lenyx IDS is starting...")
        
        self.ids_thread = th.Thread(
            target=self.sniffer.start_sniffing, 
            name="CyberForensic-Sniffer",
            daemon=True
        )
        self.api_thread = th.Thread(
            target=self.start_api,
            name="CyberForensic-API",
            daemon=True
        )

        # Démarrage des deux threads
        self.ids_thread.start()
        self.api_thread.start()
        
        # Initialisation de la forensic (PCAP & Buffer)
        Forensic.init_pcap_file()
        Forensic.start_buffer_flusher()
        
        print(f"[*] Moteur de détection activé sur le thread : {self.ids_thread.name}")
        print(f"[*] API de streaming activée sur le thread : {self.api_thread.name}")
        
        # Lancement de la boucle de surveillance du thread principal
        self.monitor()

    def monitor(self):
        try:
            while self.is_running:
                if not self.ids_thread.is_alive():
                    print("[!] Alerte : Le thread du sniffer s'est arrêté !")
                    break
                if not self.api_thread.is_alive():
                    print("[!] Alerte : Le thread de l'API s'est arrêté !")
                    break
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        print("\n[!] Signal d'arrêt reçu...")
        self.is_running = False
        print("[*] Nettoyage des ressources et sauvegarde des logs...")
        print("[+] Système arrêté avec succès. À bientôt, Lenyx Dev.")
        sys.exit(0)

if __name__ == "__main__":
    engine = IDSEngine()
    engine.start()