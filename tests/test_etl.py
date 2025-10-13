import unittest
import os
from datetime import datetime
from src.etl.parsers import ApacheLogParser, JSONLogParser, CSVLogParser, FirewallLogParser
from src.etl.pipeline import ETLPipeline
from src.models.incident import Incident, Severity


class TestParsers(unittest.TestCase):
    
    def setUp(self):
        self.sample_dir = "sample_data"
    
    def test_apache_parser(self):
        """Test Apache log parsing"""
        parser = ApacheLogParser()
        log_file = os.path.join(self.sample_dir, "apache_access.log")
        
        if os.path.exists(log_file):
            incidents = parser.parse(log_file)
            
            self.assertGreater(len(incidents), 0)
            
            # Check first incident
            inc = incidents[0]
            self.assertIsInstance(inc, Incident)
            self.assertIsInstance(inc.timestamp, datetime)
            self.assertIsNotNone(inc.source_ip)
            self.assertEqual(inc.event_type, 'http_request')
    
    def test_json_parser(self):
        """Test JSON log parsing"""
        parser = JSONLogParser()
        log_file = os.path.join(self.sample_dir, "app_logs.json")
        
        if os.path.exists(log_file):
            incidents = parser.parse(log_file)
            
            self.assertGreater(len(incidents), 0)
            
            inc = incidents[0]
            self.assertIsInstance(inc, Incident)
            self.assertIsNotNone(inc.source_ip)
    
    def test_csv_parser(self):
        """Test CSV log parsing"""
        parser = CSVLogParser()
        log_file = os.path.join(self.sample_dir, "system_events.csv")
        
        if os.path.exists(log_file):
            incidents = parser.parse(log_file)
            
            self.assertGreater(len(incidents), 0)
            
            inc = incidents[0]
            self.assertIsInstance(inc, Incident)
    
    def test_firewall_parser(self):
        """Test firewall log parsing"""
        parser = FirewallLogParser()
        log_file = os.path.join(self.sample_dir, "firewall.log")
        
        if os.path.exists(log_file):
            incidents = parser.parse(log_file)
            
            self.assertGreater(len(incidents), 0)
            
            inc = incidents[0]
            self.assertIsInstance(inc, Incident)
            self.assertIsNotNone(inc.dest_ip)
            self.assertIsNotNone(inc.dest_port)


class TestETLPipeline(unittest.TestCase):
    
    def setUp(self):
        self.pipeline = ETLPipeline()
        self.sample_dir = "sample_data"
    
    def test_format_detection(self):
        """Test automatic format detection"""
        
        # JSON file
        format_hint = self.pipeline._detect_format(
            os.path.join(self.sample_dir, "app_logs.json")
        )
        self.assertEqual(format_hint, 'json')
        
        # CSV file
        format_hint = self.pipeline._detect_format(
            os.path.join(self.sample_dir, "system_events.csv")
        )
        self.assertEqual(format_hint, 'csv')
    
    def test_process_directory(self):
        """Test processing entire directory"""
        
        if os.path.exists(self.sample_dir):
            incidents = self.pipeline.process_directory(self.sample_dir)
            
            self.assertGreater(len(incidents), 0)
            
            # All should be Incident objects
            for inc in incidents:
                self.assertIsInstance(inc, Incident)


if __name__ == '__main__':
    unittest.main()

