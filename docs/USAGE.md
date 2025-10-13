# Usage Guide

## Installation

1. Clone or extract the project
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Quick Start

Place your log files in the `sample_data/` directory and run:

```bash
python main.py
```

The tool will:
1. Auto-detect log formats
2. Parse and normalize incidents
3. Run detection engines
4. Generate a report in `output/`

## Supported Log Formats

### Apache/Nginx Access Logs
```
192.168.1.100 - - [15/Sep/2023:10:15:23 +0000] "GET /index.html HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
```

### JSON Logs (one per line)
```json
{"timestamp": "2023-09-15T10:15:00Z", "source_ip": "192.168.1.100", "event_type": "login", "user": "admin"}
```

### CSV Logs
```csv
timestamp,source_ip,event_type,user,status_code,message,severity
2023-09-15 10:15:00,192.168.1.100,login,admin,200,Success,info
```

### Firewall Logs
```
2023-09-15 10:15:00 ALLOW 192.168.1.100:54321 -> 10.0.0.10:443 TCP
```

## Running Tests

Run all tests:
```bash
pytest tests/ -v
```

Run with coverage:
```bash
pytest tests/ -v --cov=src --cov-report=html
```

Run specific test modules:
```bash
pytest tests/test_etl.py -v
pytest tests/test_detection.py -v
pytest tests/test_reporting.py -v
```

## Programmatic Usage

### Basic ETL

```python
from src.etl.pipeline import ETLPipeline

etl = ETLPipeline()
incidents = etl.process_file("logs/apache.log", format_hint="apache")
```

### Detection

```python
from src.detection.rule_based import RuleBasedDetector
from src.detection.statistical import StatisticalDetector

# Rule-based detection
rule_detector = RuleBasedDetector()
rule_detections = rule_detector.detect(incidents)

# Statistical detection
stat_detector = StatisticalDetector(zscore_threshold=2.5)
stat_detections = stat_detector.detect(incidents)
```

### Reporting

```python
from src.reporting.report_generator import ReportGenerator

reporter = ReportGenerator()
report = reporter.generate_report(
    detections,
    all_incidents,
    output_file="report.txt"
)
```

## Configuration

### Detection Thresholds

Edit `src/detection/rule_based.py`:
```python
self.brute_force_threshold = 5  # failed attempts
self.brute_force_window = 300   # seconds
self.port_scan_threshold = 10   # unique ports
```

Edit `src/detection/statistical.py`:
```python
detector = StatisticalDetector(zscore_threshold=3.0)  # sensitivity
```

### Custom Parsers

Create a new parser:

```python
from src.etl.parsers import BaseParser
from src.models.incident import Incident

class CustomParser(BaseParser):
    def parse(self, file_path):
        incidents = []
        # Your parsing logic here
        return incidents
```

Register in pipeline:
```python
etl = ETLPipeline()
etl.parsers['custom'] = CustomParser()
```

## Output

### Console Output
Shows progress and summary:
```
[1/4] Processing log files...
      Loaded 152 incidents
[2/4] Running rule-based detection...
      Found 3 threats
[3/4] Running statistical analysis...
      Found 2 anomalies
[4/4] Generating report...
```

### Report File
Located in `output/security_report_YYYYMMDD_HHMMSS.txt`

Contains:
- Executive summary with statistics
- Detailed findings for each threat
- Root cause timelines
- Actionable recommendations

## Troubleshooting

### No incidents found
- Check that log files exist in `sample_data/`
- Verify log format matches supported formats
- Check file encoding (UTF-8 expected)

### Parse errors
- Review log file format
- Check for malformed lines (parser skips them)
- Try specifying format_hint explicitly

### No detections
- Verify sample data contains actual threats
- Lower detection thresholds for testing
- Check that incidents have required fields

### Import errors
- Ensure you're in project root directory
- Check that all dependencies are installed
- Verify Python version (3.7+ required)

## Best Practices

1. **Log Rotation**: Process daily batches, archive analyzed logs
2. **Threshold Tuning**: Start conservative, adjust based on false positive rate
3. **Regular Updates**: Update attack signatures in rule-based detector
4. **Forensics**: Always preserve raw logs for investigation
5. **Validation**: Review detections manually until comfortable with accuracy

