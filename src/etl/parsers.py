import re
import json
import csv
from datetime import datetime
import pytz
from typing import List, Dict, Any, Optional
from dateutil import parser as date_parser

from src.models.incident import Incident, Severity


class BaseParser:
    """Base class for log parsers"""
    
    def parse(self, data: Any) -> List[Incident]:
        raise NotImplementedError
        
    def _parse_timestamp(self, ts_string: str) -> datetime:
        """Try to parse various timestamp formats and ensure timezone awareness"""
        try:
            dt = date_parser.parse(ts_string)
            # Make timezone-aware if naive
            if dt.tzinfo is None:
                dt = pytz.UTC.localize(dt)
            return dt
        except:
            # Fallback: try common formats
            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%d/%b/%Y:%H:%M:%S',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S.%f',
            ]
            for fmt in formats:
                try:
                    dt = datetime.strptime(ts_string.split()[0], fmt)
                    # Make timezone-aware
                    return pytz.UTC.localize(dt)
                except:
                    continue
            # Give up, use current time (timezone-aware)
            return datetime.now(pytz.UTC)


class ApacheLogParser(BaseParser):
    """
    Parser for Apache/Nginx access logs
    Format: IP - - [timestamp] "METHOD URL HTTP/1.1" status size "referer" "user-agent"
    """
    
    def __init__(self):
        # Regex pattern for common log format
        self.pattern = re.compile(
            r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<url>[^\s]+) HTTP/[^"]*" '
            r'(?P<status>\d+) (?P<size>\d+|-) '
            r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
        )
    
    def parse(self, file_path: str) -> List[Incident]:
        incidents = []
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                match = self.pattern.match(line.strip())
                if match:
                    data = match.groupdict()
                    
                    # Parse timestamp (format: 10/Oct/2023:13:55:36 +0000)
                    ts_str = data['timestamp'].split()[0]
                    timestamp = datetime.strptime(ts_str, '%d/%b/%Y:%H:%M:%S')
                    timestamp = pytz.UTC.localize(timestamp)
                    
                    # Determine severity based on status code
                    status = int(data['status'])
                    if status >= 500:
                        severity = Severity.HIGH
                    elif status >= 400:
                        severity = Severity.MEDIUM
                    else:
                        severity = Severity.INFO
                    
                    incident = Incident(
                        timestamp=timestamp,
                        source_ip=data['ip'],
                        event_type='http_request',
                        method=data['method'],
                        url=data['url'],
                        status_code=status,
                        response_size=int(data['size']) if data['size'] != '-' else 0,
                        user_agent=data['user_agent'],
                        severity=severity,
                        raw_log=line.strip()
                    )
                    incidents.append(incident)
        
        return incidents


class JSONLogParser(BaseParser):
    """Parser for JSON-formatted logs (e.g., from modern apps, cloud services)"""
    
    def parse(self, file_path: str) -> List[Incident]:
        incidents = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    data = json.loads(line)
                    incident = self._json_to_incident(data, line)
                    if incident:
                        incidents.append(incident)
                except json.JSONDecodeError:
                    # Skip malformed JSON
                    continue
        
        return incidents
    
    def _json_to_incident(self, data: Dict[str, Any], raw: str) -> Optional[Incident]:
        """Convert JSON log entry to Incident"""
        
        # Extract timestamp (try common field names)
        timestamp = None
        for ts_field in ['timestamp', 'time', '@timestamp', 'datetime', 'ts']:
            if ts_field in data:
                timestamp = self._parse_timestamp(str(data[ts_field]))
                break
        if not timestamp:
            timestamp = datetime.now()
        
        # Extract IP (try common field names)
        source_ip = None
        for ip_field in ['source_ip', 'src_ip', 'ip', 'client_ip', 'remote_addr']:
            if ip_field in data:
                source_ip = data[ip_field]
                break
        if not source_ip:
            source_ip = 'unknown'
        
        # Extract event type
        event_type = data.get('event_type', data.get('event', data.get('action', 'unknown')))
        
        # Map severity
        severity_str = data.get('severity', data.get('level', 'info')).lower()
        severity_map = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO,
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
            'debug': Severity.LOW
        }
        severity = severity_map.get(severity_str, Severity.INFO)
        
        return Incident(
            timestamp=timestamp,
            source_ip=source_ip,
            dest_ip=data.get('dest_ip', data.get('dst_ip')),
            dest_port=data.get('dest_port', data.get('dst_port')),
            user=data.get('user', data.get('username')),
            event_type=event_type,
            url=data.get('url', data.get('uri')),
            method=data.get('method'),
            status_code=data.get('status_code', data.get('status')),
            message=data.get('message', data.get('msg')),
            severity=severity,
            raw_log=raw,
            metadata=data
        )


class CSVLogParser(BaseParser):
    """Parser for CSV-formatted logs"""
    
    def parse(self, file_path: str) -> List[Incident]:
        incidents = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                incident = self._row_to_incident(row)
                if incident:
                    incidents.append(incident)
        
        return incidents
    
    def _row_to_incident(self, row: Dict[str, str]) -> Optional[Incident]:
        """Convert CSV row to Incident"""
        
        # Parse timestamp
        timestamp = None
        for ts_field in ['timestamp', 'time', 'datetime', 'date']:
            if ts_field in row and row[ts_field]:
                timestamp = self._parse_timestamp(row[ts_field])
                break
        if not timestamp:
            timestamp = datetime.now()
        
        # Get source IP
        source_ip = row.get('source_ip', row.get('src_ip', row.get('ip', 'unknown')))
        
        # Get event type
        event_type = row.get('event_type', row.get('event', row.get('action', 'unknown')))
        
        # Parse severity
        severity_str = row.get('severity', row.get('level', 'info')).lower()
        severity_map = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO
        }
        severity = severity_map.get(severity_str, Severity.INFO)
        
        return Incident(
            timestamp=timestamp,
            source_ip=source_ip,
            dest_ip=row.get('dest_ip', row.get('dst_ip')),
            dest_port=int(row['dest_port']) if row.get('dest_port') else None,
            user=row.get('user', row.get('username')),
            event_type=event_type,
            url=row.get('url'),
            method=row.get('method'),
            status_code=int(row['status_code']) if row.get('status_code') else None,
            message=row.get('message'),
            severity=severity,
            raw_log=str(row)
        )


class FirewallLogParser(BaseParser):
    """
    Parser for firewall logs
    Typically: timestamp action src_ip:src_port -> dst_ip:dst_port protocol
    """
    
    def __init__(self):
        # Pattern for firewall logs
        self.pattern = re.compile(
            r'(?P<timestamp>[\d\-: ]+) (?P<action>\w+) '
            r'(?P<src_ip>[\d\.]+):(?P<src_port>\d+) -> '
            r'(?P<dst_ip>[\d\.]+):(?P<dst_port>\d+) '
            r'(?P<protocol>\w+)'
        )
    
    def parse(self, file_path: str) -> List[Incident]:
        incidents = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                match = self.pattern.match(line.strip())
                if match:
                    data = match.groupdict()
                    
                    timestamp = self._parse_timestamp(data['timestamp'])
                    
                    # Blocked connections are more important
                    severity = Severity.MEDIUM if data['action'].lower() in ['block', 'deny', 'drop'] else Severity.LOW
                    
                    incident = Incident(
                        timestamp=timestamp,
                        source_ip=data['src_ip'],
                        dest_ip=data['dst_ip'],
                        dest_port=int(data['dst_port']),
                        event_type=f"firewall_{data['action'].lower()}",
                        severity=severity,
                        message=f"{data['action']} connection from {data['src_ip']} to {data['dst_ip']}:{data['dst_port']}",
                        raw_log=line.strip(),
                        metadata={'protocol': data['protocol'], 'src_port': data['src_port']}
                    )
                    incidents.append(incident)
        
        return incidents

