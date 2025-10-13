from typing import List, Dict, Tuple
from collections import defaultdict, Counter
from datetime import timedelta

from src.models.incident import Incident, IncidentType, Severity


class RuleBasedDetector:
    """
    Rule-based threat detection without ML dependencies.
    
    Implements common security rules based on known attack patterns:
    - Brute force detection
    - SQL injection patterns
    - XSS attempts
    - Suspicious user agents
    - Port scanning
    - Geographic anomalies
    """
    
    def __init__(self):
        # Known malicious patterns
        self.sql_patterns = [
            "' or '1'='1",
            "'; drop table",
            "union select",
            "' or 1=1",
            "--",
            "xp_cmdshell",
            "exec(",
            "execute("
        ]
        
        self.xss_patterns = [
            "<script",
            "javascript:",
            "onerror=",
            "onload=",
            "eval(",
            "document.cookie"
        ]
        
        self.suspicious_agents = [
            "sqlmap",
            "nikto",
            "nmap",
            "masscan",
            "metasploit",
            "burp",
            "acunetix"
        ]
        
        # Thresholds
        self.brute_force_threshold = 5  # failed attempts
        self.brute_force_window = 300  # 5 minutes in seconds
        self.port_scan_threshold = 10  # unique ports
        self.port_scan_window = 60  # 1 minute
    
    def detect(self, incidents: List[Incident]) -> List[Tuple[Incident, str, IncidentType]]:
        """
        Analyze incidents and flag suspicious ones.
        
        Returns:
            List of (incident, reason, incident_type) tuples
        """
        
        detections = []
        
        # Check each incident individually first
        for incident in incidents:
            
            # Check for SQL injection
            if self._check_sql_injection(incident):
                detections.append((
                    incident,
                    "Potential SQL injection detected in request",
                    IncidentType.SQL_INJECTION
                ))
                incident.incident_type = IncidentType.SQL_INJECTION
                incident.severity = Severity.CRITICAL
            
            # Check for XSS
            elif self._check_xss(incident):
                detections.append((
                    incident,
                    "Potential XSS attack detected",
                    IncidentType.XSS
                ))
                incident.incident_type = IncidentType.XSS
                incident.severity = Severity.HIGH
            
            # Check for suspicious user agent
            elif self._check_suspicious_agent(incident):
                detections.append((
                    incident,
                    f"Attack tool detected: {incident.user_agent}",
                    IncidentType.SUSPICIOUS_ACTIVITY
                ))
                incident.incident_type = IncidentType.SUSPICIOUS_ACTIVITY
                incident.severity = Severity.HIGH
        
        # Behavioral analysis (requires multiple incidents)
        brute_force = self._detect_brute_force(incidents)
        detections.extend(brute_force)
        
        port_scans = self._detect_port_scanning(incidents)
        detections.extend(port_scans)
        
        return detections
    
    def _check_sql_injection(self, incident: Incident) -> bool:
        """Check if incident contains SQL injection patterns"""
        
        if not incident.url:
            return False
        
        url_lower = incident.url.lower()
        
        for pattern in self.sql_patterns:
            if pattern in url_lower:
                return True
        
        return False
    
    def _check_xss(self, incident: Incident) -> bool:
        """Check for XSS attack patterns"""
        
        if not incident.url:
            return False
        
        url_lower = incident.url.lower()
        
        for pattern in self.xss_patterns:
            if pattern in url_lower:
                return True
        
        return False
    
    def _check_suspicious_agent(self, incident: Incident) -> bool:
        """Check for known attack tools in user agent"""
        
        if not incident.user_agent:
            return False
        
        agent_lower = incident.user_agent.lower()
        
        for tool in self.suspicious_agents:
            if tool in agent_lower:
                return True
        
        return False
    
    def _detect_brute_force(self, incidents: List[Incident]) -> List[Tuple[Incident, str, IncidentType]]:
        """
        Detect brute force attacks.
        Logic: Multiple failed login attempts from same IP in short time window
        """
        
        detections = []
        
        # Group by source IP and check for failed attempts
        ip_attempts = defaultdict(list)
        
        for incident in incidents:
            # Look for failed login events
            if incident.event_type in ['login', 'auth', 'authentication']:
                if incident.status_code in [401, 403] or 'fail' in str(incident.message).lower():
                    ip_attempts[incident.source_ip].append(incident)
        
        # Check each IP
        for ip, attempts in ip_attempts.items():
            if len(attempts) < self.brute_force_threshold:
                continue
            
            # Sort by time
            attempts.sort(key=lambda x: x.timestamp)
            
            # Check if attempts are within time window
            for i in range(len(attempts) - self.brute_force_threshold + 1):
                window_attempts = attempts[i:i + self.brute_force_threshold]
                time_diff = (window_attempts[-1].timestamp - window_attempts[0].timestamp).total_seconds()
                
                if time_diff <= self.brute_force_window:
                    # Found brute force pattern
                    for attempt in window_attempts:
                        attempt.incident_type = IncidentType.BRUTE_FORCE
                        attempt.severity = Severity.CRITICAL
                        
                    detections.append((
                        window_attempts[0],
                        f"Brute force attack: {len(window_attempts)} failed attempts from {ip} in {int(time_diff)} seconds",
                        IncidentType.BRUTE_FORCE
                    ))
                    break
        
        return detections
    
    def _detect_port_scanning(self, incidents: List[Incident]) -> List[Tuple[Incident, str, IncidentType]]:
        """
        Detect port scanning activity.
        Logic: Same source IP accessing many different ports in short time
        """
        
        detections = []
        
        # Group by source IP
        ip_ports = defaultdict(lambda: {'ports': set(), 'incidents': []})
        
        for incident in incidents:
            if incident.dest_port:
                ip_ports[incident.source_ip]['ports'].add(incident.dest_port)
                ip_ports[incident.source_ip]['incidents'].append(incident)
        
        # Check for port scanning pattern
        for ip, data in ip_ports.items():
            if len(data['ports']) >= self.port_scan_threshold:
                # Check time window
                incidents_list = sorted(data['incidents'], key=lambda x: x.timestamp)
                time_diff = (incidents_list[-1].timestamp - incidents_list[0].timestamp).total_seconds()
                
                if time_diff <= self.port_scan_window:
                    for inc in incidents_list:
                        inc.incident_type = IncidentType.SUSPICIOUS_ACTIVITY
                        inc.severity = Severity.HIGH
                    
                    detections.append((
                        incidents_list[0],
                        f"Port scan detected: {ip} accessed {len(data['ports'])} different ports in {int(time_diff)} seconds",
                        IncidentType.SUSPICIOUS_ACTIVITY
                    ))
        
        return detections

