# Security Incident Analysis Tool

A practical incident analysis system for SOC teams to process, analyze, and triage security events from multiple log sources.

## Quick Start

```bash
pip install -r requirements.txt
python main.py
```

## Project Structure

```
incident-analysis/
├── src/
│   ├── etl/           # Log parsing and normalization
│   ├── detection/     # Threat detection engines
│   ├── reporting/     # Incident reports and analysis
│   └── models/        # Data models and schema
├── tests/
├── sample_data/       # Sample log files
└── docs/
```

## What It Does

1. **ETL Pipeline**: Ingests logs from various sources (web servers, firewalls, apps) and normalizes them into a common schema
2. **Detection**: Identifies suspicious patterns using rule-based and statistical methods
3. **Reporting**: Generates detailed incident reports with root cause analysis

## Running Tests

```bash
pytest tests/ -v --cov=src
```

## Documentation

See `docs/` folder for:
- Architecture overview
- Schema design rationale
- Detection algorithms
- Usage examples

---
Built for SOC workflow optimization

