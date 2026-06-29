from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class Alert(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    detection_time: datetime = Field(default_factory=datetime.now)
    attack_type: str
    severity: str
    ip_src: str
    ip_dst: str
    iface: str
    status: str = "open"
    integrity_hash: Optional[str] = None

    class Config:
        populate_by_name = True


class AlertPortScan(Alert):
    attack_type: str = "PORT_SCAN"
    severity: str    = "HIGH"
    ports_scanned: list[int]
    unique_ports: int
    duration: float


class AlertSynFlood(Alert):
    attack_type: str = "SYN_FLOOD"
    severity: str    = "CRITICAL"
    port_dst: int
    syn_packets: int
    duration: float


class AlertBruteForce(Alert):
    attack_type: str = "BRUTE_FORCE"
    severity: str    = "HIGH"
    port_dst: int
    service: str
    attempts: int


class AlertOsFingerprinting(Alert):
    attack_type: str = "OS_FINGERPRINTING"
    severity: str    = "MEDIUM"
    port_dst: int
    packets_count: int
    duration: float
    scan_types: list[str]


class AlertArpSpoofing(Alert):
    attack_type: str = "ARP_SPOOFING"
    severity: str    = "CRITICAL"
    ip_spoofed: str
    mac_legitimate: str
    mac_fraudulent: str
    target_ip: str


class AlertPingFlood(Alert):
    attack_type: str = "PING_FLOOD"        # underscore — cohérent avec les autres
    severity: str    = "CRITICAL"
    icmp_packets: int                       # nb de paquets ICMP echo-request
    duration: float


class AlertHttpFlood(Alert):
    attack_type: str = "HTTP_FLOOD"
    severity: str    = "CRITICAL"
    port_dst: int
    http_requests: int                      # nb de requêtes HTTP en rafale
    duration: float
    target_path: Optional[str] = None       # ex: "/" ou "/login" si identifiable

class AlertWebAttack(Alert):
    attack_type: str = "WEB_ATTACK"
    severity: str    = "CRITICAL"
    port_dst: int
    web_attack_type: str   
    payload: str            