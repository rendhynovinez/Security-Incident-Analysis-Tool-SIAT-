from datetime import datetime
from typing import Optional, Dict, List, Any
from enum import Enum


class Severity(Enum):
    """Incident severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentType(Enum):
    """Known incident categories"""
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    MALWARE = "malware"
    DDoS = "ddos"
    DATA_EXFILTRATION = "data_exfiltration"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    UNKNOWN = "unknown"


class Incident:
    """
    Normalized incident schema.
    
    Design rationale:
    - timestamp: ISO format for consistency across timezones
    - source_ip/dest_ip: key for tracking lateral movement
    - user: for behavioral analysis
    - event_type: normalized action (login, request, file_access, etc)
    - severity: allows quick triage
    - raw_log: preserve original for forensics
    """
    
    def __init__(
        self,
        timestamp: datetime,
        source_ip: str,
        event_type: str,
        severity: Severity = Severity.INFO,
        dest_ip: Optional[str] = None,
        dest_port: Optional[int] = None,
        user: Optional[str] = None,
        url: Optional[str] = None,
        user_agent: Optional[str] = None,
        status_code: Optional[int] = None,
        response_size: Optional[int] = None,
        method: Optional[str] = None,
        message: Optional[str] = None,
        incident_type: Optional[IncidentType] = None,
        raw_log: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.user = user
        self.event_type = event_type
        self.url = url
        self.user_agent = user_agent
        self.status_code = status_code
        self.response_size = response_size
        self.method = method
        self.message = message
        self.severity = severity
        self.incident_type = incident_type
        self.raw_log = raw_log
        self.metadata = metadata or {}
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'dest_port': self.dest_port,
            'user': self.user,
            'event_type': self.event_type,
            'url': self.url,
            'user_agent': self.user_agent,
            'status_code': self.status_code,
            'response_size': self.response_size,
            'method': self.method,
            'message': self.message,
            'severity': self.severity.value if self.severity else None,
            'incident_type': self.incident_type.value if self.incident_type else None,
            'raw_log': self.raw_log,
            'metadata': self.metadata
        }
    
    def __repr__(self):
        return f"<Incident {self.timestamp} {self.source_ip} {self.event_type}>"

