import threading as th
import time
import sys
from core.sniffer import Sniffer
from core.analyser import Analyser

class IDSEngine:
    def __init__(self):
        self.analyser = Analyser()
        self.sniffer = Sniffer(self.analyser)
        self.is_running = True
        self.ids_thread = None

    def start(self):       
        print("[DEBUG] Lenyx IDS is starting...")
        # Initialisation du thread
        self.ids_thread = th.Thread(
            target=self.sniffer.start_sniffing, 
            name="CyberForensic",
            daemon=True
        )
        
        self.ids_thread.start()
        print(f"[*] Moteur de détection activé sur le thread : {self.ids_thread.name}")
        self.monitor()

    def monitor(self):
        try:
            while self.is_running:
                if not self.ids_thread.is_alive():
                    print("[!] Alerte : Le thread du sniffer s'est arrêté !")
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
    app = IDSEngine()
    app.start()