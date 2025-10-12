#!/usr/bin/env python3
"""
Main entry point for Security Incident Analysis Tool
"""

import os
import sys
from datetime import datetime

from src.etl.pipeline import ETLPipeline
from src.detection.rule_based import RuleBasedDetector
from src.detection.statistical import StatisticalDetector
from src.reporting.report_generator import ReportGenerator


def main():
    print("=" * 60)
    print("Security Incident Analysis Tool")
    print("=" * 60)
    print()
    
    # Initialize components
    etl = ETLPipeline()
    rule_detector = RuleBasedDetector()
    stat_detector = StatisticalDetector(zscore_threshold=2.5)
    reporter = ReportGenerator()
    
    # Process sample data
    sample_dir = "sample_data"
    
    if not os.path.exists(sample_dir):
        print(f"Error: {sample_dir} directory not found")
        print("Please create sample log files in the sample_data directory")
        return
    
    print(f"[1/4] Processing log files from {sample_dir}/...")
    all_incidents = etl.process_directory(sample_dir)
    
    if not all_incidents:
        print("No incidents found. Make sure log files exist in sample_data/")
        return
    
    print(f"      Loaded {len(all_incidents)} incidents")
    print()
    
    # Run detection engines
    print("[2/4] Running rule-based detection...")
    rule_detections = rule_detector.detect(all_incidents)
    print(f"      Found {len(rule_detections)} threats")
    
    print("[3/4] Running statistical analysis...")
    stat_detections = stat_detector.detect(all_incidents)
    print(f"      Found {len(stat_detections)} anomalies")
    print()
    
    # Combine detections (remove duplicates)
    all_detections = rule_detections + stat_detections
    unique_detections = []
    seen = set()
    
    for detection in all_detections:
        incident, reason, itype = detection
        key = (incident.timestamp, incident.source_ip, incident.event_type)
        if key not in seen:
            seen.add(key)
            unique_detections.append(detection)
    
    print(f"Total unique threats detected: {len(unique_detections)}")
    print()
    
    # Generate report
    print("[4/4] Generating security report...")
    
    # Create output directory
    os.makedirs("output", exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"output/security_report_{timestamp}.txt"
    
    report = reporter.generate_report(
        unique_detections,
        all_incidents,
        output_file
    )
    
    print()
    print("=" * 60)
    print("Analysis complete!")
    print(f"Report saved to: {output_file}")
    print("=" * 60)
    
    # Print summary to console
    print("\nQUICK SUMMARY:")
    print("-" * 60)
    summary_lines = report.split("EXECUTIVE SUMMARY")[1].split("DETAILED FINDINGS")[0]
    print(summary_lines.strip())
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

