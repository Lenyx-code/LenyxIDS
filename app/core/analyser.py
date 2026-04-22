from utils.datetime_utils import DatetimeUtils as dt
import time
import os
connection_history = {}
TRUSTED_IPS = []

class Analyser:

    @staticmethod
    def _write_evidence_to_file(evidence):
        path = "storage/captures/evidence-port-scan.txt"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'a') as f:
            try:
                f.write(evidence)
            except Exception as e:
                print(f"Erreur d\'ecriture : {e}")


    def detect_port_scan(self,ip_src, port_dst, ip_dst, flags):
        global connection_history
        detection_datetime = dt.get_format_now()
        now = time.time()
        if ip_src in TRUSTED_IPS and flags != "S": 
            return False

        if ip_src not in connection_history:
            connection_history[ip_src] = {"port":{port_dst}, "first_seen": now}
        else:
            connection_history[ip_src]["port"].add(port_dst)
            duration = now - connection_history[ip_src]['first_seen']
            unique_ports_count= len(connection_history[ip_src]["port"])

            if unique_ports_count> 10 and duration < 5:
                msg = (
                    f"\n[!!!] DETECTION IDS : Tentative de scan par {ip_src}\n"
                    f"[i] Preuve : {unique_ports_count} ports scannés en {duration:.2f}s\n"
                )
                print(msg)

                evidence = (
                    f"========== CAPTURES SCAN DE PORTS ==========\n"
                    f"[!!!] Alerte générée à : {detection_datetime}\n"
                    f"Source suspecte : {ip_src}\n"
                    f"Victime : {ip_dst}\n"
                    f"Dernier port ciblé : {port_dst}\n"
                    f"Statistiques : {unique_ports_count} ports en {duration:.2f}s\n"
                    f"=============================================\n\n"
                )
                
                self._write_evidence_to_file(evidence)
                    

                connection_history[ip_src] = {"port" : set(), "first_seen": now}
                return True
            
        return False
    
