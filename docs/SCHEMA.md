# Canonical Incident Schema

## Design Principles

The incident schema was designed with these priorities:

1. **Universality**: Support logs from web, network, and application layers
2. **Forensics**: Preserve enough context for investigation
3. **Correlation**: Enable linking related events
4. **Simplicity**: Easy to understand and work with
5. **Extensibility**: Support future log sources via metadata field

## Schema Definition

### Core Fields

#### timestamp (datetime, required)
- ISO 8601 format
- Timezone-aware for global deployments
- Enables temporal analysis and sequencing
- **Rationale**: Time is critical for correlation and timeline reconstruction

#### source_ip (string, required)
- IPv4 or IPv6 address
- Primary key for behavioral analysis
- Tracks attacker origin
- **Rationale**: Most security analysis pivots on source IP

#### event_type (string, required)
- Normalized action: `login`, `http_request`, `file_access`, `firewall_block`, etc.
- Consistent across log sources
- **Rationale**: Enables cross-platform correlation

### Network Fields

#### dest_ip (string, optional)
- Target IP address
- Used for firewall logs, network traffic
- **Rationale**: Identifies attack targets and lateral movement

#### dest_port (int, optional)
- Target port number
- Critical for identifying services under attack
- **Rationale**: Port scanning, service enumeration detection

### Application Fields

#### url (string, optional)
- Request URL or path
- Contains attack payloads (SQL injection, XSS)
- **Rationale**: Web attacks embed payloads in URLs

#### method (string, optional)
- HTTP method: GET, POST, PUT, DELETE
- Different methods have different risk profiles
- **Rationale**: POST/PUT more likely for exploitation

#### status_code (int, optional)
- HTTP status code or event result code
- 4xx/5xx indicate errors
- **Rationale**: Failed attempts are security-relevant

#### response_size (int, optional)
- Bytes transferred
- Anomalously large = potential data exfiltration
- **Rationale**: Statistical anomaly detection

#### user_agent (string, optional)
- Client user agent string
- Identifies attack tools (sqlmap, nikto, etc.)
- **Rationale**: Known attack tool detection

### Identity Fields

#### user (string, optional)
- Username or account
- Enables per-user behavioral analysis
- **Rationale**: Compromised account detection

### Classification Fields

#### severity (Severity enum, required)
- CRITICAL, HIGH, MEDIUM, LOW, INFO
- Enables triage prioritization
- **Rationale**: SOC teams need severity-based queuing

#### incident_type (IncidentType enum, optional)
- Classification: SQL_INJECTION, BRUTE_FORCE, XSS, etc.
- Set by detection engines
- **Rationale**: Groups incidents for analysis

### Forensics Fields

#### message (string, optional)
- Human-readable description
- Additional context from original log
- **Rationale**: Provides context without parsing raw log

#### raw_log (string, optional)
- Original log line
- Preserves forensic evidence
- **Rationale**: May need original format for investigation

#### metadata (dict, optional)
- Key-value pairs for format-specific fields
- Extensibility mechanism
- **Rationale**: Accommodates diverse log sources without schema changes

## Normalization Examples

### From Apache Log
```
192.168.1.100 - - [15/Sep/2023:10:15:23 +0000] "GET /index.html HTTP/1.1" 200 2048
```

Normalized:
```python
Incident(
    timestamp=datetime(2023, 9, 15, 10, 15, 23),
    source_ip="192.168.1.100",
    event_type="http_request",
    method="GET",
    url="/index.html",
    status_code=200,
    response_size=2048,
    severity=Severity.INFO
)
```

### From JSON Application Log
```json
{
  "time": "2023-09-15T10:16:00Z",
  "client_ip": "10.0.0.45",
  "action": "login",
  "username": "admin",
  "result": "failed",
  "level": "warning"
}
```

Normalized:
```python
Incident(
    timestamp=datetime(2023, 9, 15, 10, 16, 0),
    source_ip="10.0.0.45",
    event_type="login",
    user="admin",
    message="failed",
    severity=Severity.MEDIUM
)
```

### From Firewall Log
```
2023-09-15 10:16:00 BLOCK 88.99.77.66:12345 -> 10.0.0.10:22 TCP
```

Normalized:
```python
Incident(
    timestamp=datetime(2023, 9, 15, 10, 16, 0),
    source_ip="88.99.77.66",
    dest_ip="10.0.0.10",
    dest_port=22,
    event_type="firewall_block",
    severity=Severity.MEDIUM,
    metadata={"protocol": "TCP", "src_port": "12345"}
)
```

## Field Mappings

| Source Format | Canonical Field | Variations Handled |
|---------------|----------------|-------------------|
| Timestamp | timestamp | @timestamp, time, datetime, ts, date |
| Source IP | source_ip | src_ip, client_ip, remote_addr, ip |
| Event Type | event_type | event, action, activity, type |
| User | user | username, account, uid, login |
| Severity | severity | level, priority, criticality |

## Evolution Strategy

When new log sources need fields not in the schema:

1. **Check metadata**: Can it fit in metadata dict?
2. **Consider reuse**: Does an existing field cover it semantically?
3. **Add field**: If truly universal, extend the schema
4. **Document**: Update parser and schema docs

## Trade-offs

### What We Include
- Fields common across multiple log sources
- Fields critical for security analysis
- Fields enabling correlation

### What We Exclude
- Format-specific details (goes in metadata)
- Non-security data (performance metrics, business data)
- Redundant fields (multiple representations of same data)

### Flexibility vs. Structure
- Strict schema for common fields (easier to query)
- Loose metadata field (handles edge cases)
- Balance: 80% of logs fit cleanly, 20% use metadata

## Validation

The schema is validated through:
- Type hints in Python code
- Parsers handle missing optional fields gracefully
- Required fields enforced at Incident creation
- Unit tests verify normalization correctness

