from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

class AlertMonitor(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    status: str = "open"
    severity: str
    attack_type: str
    hostname: str
    os_type: str
    process_name: Optional[str]
    integrity_hash : str

    class Config:
        populate_by_name = True

class AlertFileChange(AlertMonitor):
    attack_type: str = "FILE_INTEGRITY"
    severity: str    = "HIGH"
    file_path: str
    change_type: str 
    os_type: str


class AlertSuspiciousProcess(AlertMonitor):
    attack_type: str = "SUSPICIOUS_PROCESS"
    severity: str    = "HIGH"
    pid: int
    cmdline: str


class AlertResourceAbuse(AlertMonitor):
    attack_type: str = "RESOURCE_ABUSE"
    severity: str    = "MEDIUM"
    metric: str 
    value: float


class AlertSuspiciousConnection(AlertMonitor):
    attack_type: str = "SUSPICIOUS_CONNECTION"
    severity: str    = "HIGH"
    local_port: int
    remote_ip: str
    remote_port: int
