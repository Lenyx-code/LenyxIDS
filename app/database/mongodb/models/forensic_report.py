from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class AttackEvent(BaseModel):
    time: datetime
    attack_type: str
    description: str
    ip_src: str
    ip_dst: str


class ForensicReport(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")

    incident_id:  str
    generated_at: datetime = Field(default_factory=datetime.now)
    start_date: datetime
    end_date:   datetime

    attacker_ip: str        
    victim_ip:   str

    title:        str
    severity:     str
    attack_types: list[str]
    total_alerts: int

    timeline:   list[AttackEvent]
    alerts_ids: list[str]

    pcap_file:       Optional[str] = None
    integrity_hash:  Optional[str] = None

    conclusion:      str
    recommendations: list[str]

    class Config:
        populate_by_name = True