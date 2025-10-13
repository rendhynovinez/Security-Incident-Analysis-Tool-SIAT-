import unittest
import os
from datetime import datetime
import pytz
from src.models.incident import Incident, IncidentType, Severity
from src.reporting.report_generator import ReportGenerator


class TestReportGenerator(unittest.TestCase):
    
    def setUp(self):
        self.reporter = ReportGenerator()
        
        # Create sample incidents
        self.incidents = [
            Incident(
                timestamp=datetime.now(pytz.UTC),
                source_ip="10.0.0.1",
                event_type="http_request",
                url="/api/user?id=1' OR '1'='1",
                severity=Severity.CRITICAL,
                incident_type=IncidentType.SQL_INJECTION
            ),
            Incident(
                timestamp=datetime.now(pytz.UTC),
                source_ip="10.0.0.2",
                event_type="login",
                status_code=401,
                severity=Severity.CRITICAL,
                incident_type=IncidentType.BRUTE_FORCE
            )
        ]
        
        self.detections = [
            (self.incidents[0], "SQL injection detected", IncidentType.SQL_INJECTION),
            (self.incidents[1], "Brute force attack", IncidentType.BRUTE_FORCE)
        ]
    
    def test_report_generation(self):
        """Test basic report generation"""
        
        report = self.reporter.generate_report(
            self.detections,
            self.incidents
        )
        
        self.assertIsInstance(report, str)
        self.assertIn("SECURITY INCIDENT ANALYSIS REPORT", report)
        self.assertIn("EXECUTIVE SUMMARY", report)
        self.assertIn("DETAILED FINDINGS", report)
        self.assertIn("RECOMMENDATIONS", report)
    
    def test_report_contains_detections(self):
        """Test that report includes all detections"""
        
        report = self.reporter.generate_report(
            self.detections,
            self.incidents
        )
        
        # Check for incident types
        self.assertIn("SQL", report.upper())
        self.assertIn("BRUTE", report.upper())
    
    def test_report_file_output(self):
        """Test saving report to file"""
        
        output_file = "test_report.txt"
        
        try:
            report = self.reporter.generate_report(
                self.detections,
                self.incidents,
                output_file
            )
            
            self.assertTrue(os.path.exists(output_file))
            
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read()
                self.assertEqual(content, report)
        
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)
    
    def test_timeline_tracing(self):
        """Test root cause timeline tracing"""
        
        # Create multiple related incidents
        related_incidents = [
            Incident(
                timestamp=datetime.now(pytz.UTC),
                source_ip="10.0.0.1",
                event_type="scan",
                severity=Severity.LOW
            ),
            Incident(
                timestamp=datetime.now(pytz.UTC),
                source_ip="10.0.0.1",
                event_type="probe",
                severity=Severity.MEDIUM
            ),
            Incident(
                timestamp=datetime.now(pytz.UTC),
                source_ip="10.0.0.1",
                event_type="exploit",
                severity=Severity.CRITICAL,
                incident_type=IncidentType.SQL_INJECTION
            )
        ]
        
        timeline = self.reporter._trace_timeline(
            related_incidents[2],
            related_incidents
        )
        
        # Should find all 3 related events
        self.assertEqual(len(timeline), 3)
    
    def test_recommendations_generation(self):
        """Test security recommendations"""
        
        report = self.reporter.generate_report(
            self.detections,
            self.incidents
        )
        
        # Should contain actionable recommendations
        self.assertIn("Block", report)
        self.assertIn("Review", report)


if __name__ == '__main__':
    unittest.main()

