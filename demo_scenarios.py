#!/usr/bin/env python3
"""
Demo berbagai skenario penggunaan tool
"""

from datetime import datetime, timedelta
import pytz
from src.models.incident import Incident, Severity
from src.etl.pipeline import ETLPipeline
from src.detection.rule_based import RuleBasedDetector
from src.detection.statistical import StatisticalDetector
from src.reporting.report_generator import ReportGenerator


def demo_1_basic_usage():
    """Demo 1: Penggunaan dasar - process semua log"""
    print("\n" + "="*60)
    print("DEMO 1: Basic Usage - Process All Logs")
    print("="*60)
    
    etl = ETLPipeline()
    rule_detector = RuleBasedDetector()
    stat_detector = StatisticalDetector()
    
    # Process all logs
    incidents = etl.process_directory("sample_data")
    print(f"✓ Loaded {len(incidents)} incidents from all log files")
    
    # Detect threats
    rule_threats = rule_detector.detect(incidents)
    stat_threats = stat_detector.detect(incidents)
    
    print(f"✓ Rule-based detection: {len(rule_threats)} threats")
    print(f"✓ Statistical detection: {len(stat_threats)} threats")
    
    # Show sample
    if rule_threats:
        inc, reason, itype = rule_threats[0]
        print(f"\nSample threat:")
        print(f"  Type: {itype.value}")
        print(f"  IP: {inc.source_ip}")
        print(f"  Reason: {reason}")


def demo_2_investigate_ip():
    """Demo 2: Investigate specific IP address"""
    print("\n" + "="*60)
    print("DEMO 2: Investigate Specific IP")
    print("="*60)
    
    suspicious_ip = "45.33.32.156"
    print(f"Investigating IP: {suspicious_ip}")
    
    etl = ETLPipeline()
    all_incidents = etl.process_directory("sample_data")
    
    # Filter by IP
    ip_incidents = [inc for inc in all_incidents if inc.source_ip == suspicious_ip]
    print(f"\n✓ Found {len(ip_incidents)} events from {suspicious_ip}:")
    
    for inc in ip_incidents[:5]:  # Show first 5
        print(f"  [{inc.timestamp.strftime('%H:%M:%S')}] {inc.event_type}")
        if inc.url:
            print(f"    URL: {inc.url[:60]}...")
    
    # Detect threats from this IP
    detector = RuleBasedDetector()
    threats = detector.detect(ip_incidents)
    
    print(f"\n✓ Threats detected: {len(threats)}")
    for inc, reason, itype in threats:
        print(f"  ⚠️  {itype.value}: {reason}")


def demo_3_test_detection():
    """Demo 3: Test detection with custom incident"""
    print("\n" + "="*60)
    print("DEMO 3: Test Detection Rules")
    print("="*60)
    
    # Create test incidents
    test_cases = [
        {
            "name": "SQL Injection",
            "incident": Incident(
                timestamp=datetime.now(pytz.UTC),
                source_ip="10.0.0.99",
                event_type="http_request",
                url="/admin?id=1' OR '1'='1--"
            )
        },
        {
            "name": "XSS Attack",
            "incident": Incident(
                timestamp=datetime.now(pytz.UTC),
                source_ip="10.0.0.88",
                event_type="http_request",
                url="/search?q=<script>alert('XSS')</script>"
            )
        },
        {
            "name": "Attack Tool",
            "incident": Incident(
                timestamp=datetime.now(pytz.UTC),
                source_ip="10.0.0.77",
                event_type="http_request",
                user_agent="sqlmap/1.5.2"
            )
        }
    ]
    
    detector = RuleBasedDetector()
    
    for test in test_cases:
        print(f"\nTesting: {test['name']}")
        detections = detector.detect([test['incident']])
        
        if detections:
            print(f"  ✓ DETECTED!")
            for inc, reason, itype in detections:
                print(f"    Type: {itype.value}")
                print(f"    Reason: {reason}")
        else:
            print(f"  ✗ Not detected")


def demo_4_brute_force():
    """Demo 4: Simulate and detect brute force"""
    print("\n" + "="*60)
    print("DEMO 4: Brute Force Detection")
    print("="*60)
    
    # Simulate brute force: 10 failed logins in 2 minutes
    base_time = datetime.now(pytz.UTC)
    attacker_ip = "203.0.113.99"
    
    incidents = []
    for i in range(10):
        inc = Incident(
            timestamp=base_time + timedelta(seconds=i*10),
            source_ip=attacker_ip,
            event_type="login",
            status_code=401,
            user=f"admin",
            message="Login failed"
        )
        incidents.append(inc)
    
    print(f"Simulated: 10 failed login attempts from {attacker_ip}")
    print(f"Time span: {(incidents[-1].timestamp - incidents[0].timestamp).total_seconds()} seconds")
    
    # Detect
    detector = RuleBasedDetector()
    detections = detector.detect(incidents)
    
    if detections:
        print(f"\n✓ BRUTE FORCE DETECTED!")
        for inc, reason, itype in detections:
            print(f"  {reason}")
    else:
        print(f"\n✗ Not detected (threshold not reached)")


def demo_5_statistical():
    """Demo 5: Statistical anomaly detection"""
    print("\n" + "="*60)
    print("DEMO 5: Statistical Anomaly Detection")
    print("="*60)
    
    base_time = datetime.now(pytz.UTC)
    incidents = []
    
    # Normal traffic: 5 requests per minute for 10 minutes
    print("Simulating normal traffic: 5 req/min...")
    for minute in range(10):
        for req in range(5):
            inc = Incident(
                timestamp=base_time + timedelta(minutes=minute, seconds=req*10),
                source_ip=f"192.168.1.{minute}",
                event_type="http_request"
            )
            incidents.append(inc)
    
    # Sudden spike: 100 requests in 1 minute
    print("Simulating traffic spike: 100 req/min from single IP...")
    spike_time = base_time + timedelta(minutes=10)
    for req in range(100):
        inc = Incident(
            timestamp=spike_time + timedelta(seconds=req/2),
            source_ip="10.0.0.100",
            event_type="http_request"
        )
        incidents.append(inc)
    
    # Detect
    detector = StatisticalDetector(zscore_threshold=2.0)
    detections = detector.detect(incidents)
    
    print(f"\n✓ Total incidents: {len(incidents)}")
    print(f"✓ Anomalies detected: {len(detections)}")
    
    for inc, reason, itype in detections[:3]:  # Show first 3
        print(f"\n  ⚠️  {itype.value}")
        print(f"    {reason}")


def demo_6_timeline_tracing():
    """Demo 6: Root cause timeline tracing"""
    print("\n" + "="*60)
    print("DEMO 6: Root Cause Timeline Tracing")
    print("="*60)
    
    # Simulate attack progression
    attacker_ip = "198.51.100.99"
    base_time = datetime.now(pytz.UTC)
    
    attack_sequence = [
        ("10:00:00", "port_scan", "Scanning for open ports", None, None),
        ("10:00:30", "http_request", "Probing web server", "/admin", None),
        ("10:01:00", "http_request", "Testing SQL injection", "/login?user=admin' OR '1'='1", None),
        ("10:01:30", "http_request", "Exploiting vulnerability", "/api/data?id=1 UNION SELECT", None),
        ("10:02:00", "data_download", "Exfiltrating data", None, 50000000),
    ]
    
    incidents = []
    print(f"\nAttack sequence from {attacker_ip}:")
    
    for time_str, event, desc, url, size in attack_sequence:
        hour, minute, second = map(int, time_str.split(':'))
        timestamp = base_time.replace(hour=hour, minute=minute, second=second, microsecond=0)
        
        inc = Incident(
            timestamp=timestamp,
            source_ip=attacker_ip,
            event_type=event,
            url=url,
            response_size=size,
            message=desc
        )
        incidents.append(inc)
        print(f"  [{time_str}] {event}: {desc}")
    
    # Detect threats
    detector = RuleBasedDetector()
    detections = detector.detect(incidents)
    
    # Generate report with timeline
    reporter = ReportGenerator()
    
    if detections:
        print(f"\n✓ Detected {len(detections)} threats")
        print("\nTimeline analysis:")
        
        # Trace timeline for last incident
        timeline = reporter._trace_timeline(incidents[-1], incidents)
        for i, inc in enumerate(timeline, 1):
            print(f"  {i}. [{inc.timestamp.strftime('%H:%M:%S')}] {inc.event_type}")
            if inc.message:
                print(f"     {inc.message}")


def demo_7_report_generation():
    """Demo 7: Generate comprehensive report"""
    print("\n" + "="*60)
    print("DEMO 7: Generate Comprehensive Report")
    print("="*60)
    
    # Use real sample data
    etl = ETLPipeline()
    incidents = etl.process_directory("sample_data")
    
    # Detect
    rule_detector = RuleBasedDetector()
    stat_detector = StatisticalDetector()
    
    rule_threats = rule_detector.detect(incidents)
    stat_threats = stat_detector.detect(incidents)
    
    all_threats = rule_threats + stat_threats
    
    # Remove duplicates
    unique_threats = []
    seen = set()
    for threat in all_threats:
        inc, reason, itype = threat
        key = (inc.timestamp, inc.source_ip, inc.event_type)
        if key not in seen:
            seen.add(key)
            unique_threats.append(threat)
    
    print(f"✓ Analyzed {len(incidents)} incidents")
    print(f"✓ Detected {len(unique_threats)} unique threats")
    
    # Generate report
    reporter = ReportGenerator()
    output_file = "output/demo_report.txt"
    report = reporter.generate_report(unique_threats, incidents, output_file)
    
    print(f"✓ Report saved to: {output_file}")
    
    # Show snippet
    print("\n--- Report Preview (first 30 lines) ---")
    lines = report.split('\n')
    for line in lines[:30]:
        print(line)
    print("...")


def main():
    """Run all demos"""
    print("\n" + "="*60)
    print("SECURITY INCIDENT ANALYSIS TOOL - DEMO SCENARIOS")
    print("="*60)
    
    demos = [
        ("Basic Usage", demo_1_basic_usage),
        ("Investigate IP", demo_2_investigate_ip),
        ("Test Detection", demo_3_test_detection),
        ("Brute Force", demo_4_brute_force),
        ("Statistical Anomaly", demo_5_statistical),
        ("Timeline Tracing", demo_6_timeline_tracing),
        ("Report Generation", demo_7_report_generation),
    ]
    
    print("\nAvailable demos:")
    for i, (name, _) in enumerate(demos, 1):
        print(f"  {i}. {name}")
    
    print("\nRunning all demos...")
    
    for name, demo_func in demos:
        try:
            demo_func()
            print(f"\n✓ {name} demo completed")
        except Exception as e:
            print(f"\n✗ {name} demo failed: {e}")
        
        input("\nPress Enter to continue to next demo...")
    
    print("\n" + "="*60)
    print("All demos completed!")
    print("="*60)


if __name__ == "__main__":
    main()

