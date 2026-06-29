from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class Packet(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    timestamp: datetime
    protocol: str
    ip_src: str
    ip_dst: str
    port_src: Optional[int] = None
    port_dst: Optional[int] = None
    iface: str
    pcap_file: Optional[str] = None

    class Config:
        populate_by_name = True