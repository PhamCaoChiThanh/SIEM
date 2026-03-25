from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional, Dict, Any

@dataclass
class NormalizedEvent:
    timestamp: str          # ISO8601
    event_id: str           # Unique ID (e.g., ES _id or UUID)
    category: str           # web, system, network, auth
    src_ip: str
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    user: str = "unknown"
    action: str = "allowed" # allowed, blocked, detected
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    signature: str = ""     # Rule name or signature ID
    message: str = ""       # Human readable summary
    raw_log: str = ""       # Original log snippet
    metadata: Dict[str, Any] = None

    def to_dict(self):
        d = asdict(self)
        if self.metadata is None:
            d['metadata'] = {}
        return d
