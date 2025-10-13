import unittest
from datetime import datetime, timedelta
import pytz
from src.models.incident import Incident, IncidentType, Severity
from src.detection.rule_based import RuleBasedDetector
from src.detection.statistical import StatisticalDetector


class TestRuleBasedDetector(unittest.TestCase):
    
    def setUp(self):
        self.detector = RuleBasedDetector()
    
    def test_sql_injection_detection(self):
        """Test SQL injection pattern detection"""
        
        incidents = [
            Incident(
                timestamp=datetime.now(pytz.UTC),
                source_ip="10.0.0.1",
                event_type="http_request",
                url="/api/user?id=1' OR '1'='1"
            )
        ]
        
        detections = self.detector.detect(incidents)
        
        self.assertGreater(len(detections), 0)
        self.assertEqual(detections[0][2], IncidentType.SQL_INJECTION)
    
    def test_xss_detection(self):
        """Test XSS attack detection"""
        
        incidents = [
            Incident(
                timestamp=datetime.now(pytz.UTC),
                source_ip="10.0.0.2",
                event_type="http_request",
                url="/search?q=<script>alert(1)</script>"
            )
        ]
        
        detections = self.detector.detect(incidents)
        
        self.assertGreater(len(detections), 0)
        self.assertEqual(detections[0][2], IncidentType.XSS)
    
    def test_brute_force_detection(self):
        """Test brute force attack detection"""
        
        base_time = datetime.now(pytz.UTC)
        incidents = []
        
        # Create 6 failed login attempts in short time window
        for i in range(6):
            inc = Incident(
                timestamp=base_time + timedelta(seconds=i*10),
                source_ip="10.0.0.3",
                event_type="login",
                status_code=401,
                message="Login failed"
            )
            incidents.append(inc)
        
        detections = self.detector.detect(incidents)
        
        # Should detect brute force
        brute_force_found = any(d[2] == IncidentType.BRUTE_FORCE for d in detections)
        self.assertTrue(brute_force_found)
    
    def test_suspicious_user_agent(self):
        """Test detection of attack tools"""
        
        incidents = [
            Incident(
                timestamp=datetime.now(pytz.UTC),
                source_ip="10.0.0.4",
                event_type="http_request",
                user_agent="sqlmap/1.4.7"
            )
        ]
        
        detections = self.detector.detect(incidents)
        
        self.assertGreater(len(detections), 0)
        self.assertEqual(detections[0][2], IncidentType.SUSPICIOUS_ACTIVITY)
    
    def test_port_scanning_detection(self):
        """Test port scan detection"""
        
        base_time = datetime.now(pytz.UTC)
        incidents = []
        
        # Simulate scanning multiple ports
        for port in range(20, 35):
            inc = Incident(
                timestamp=base_time + timedelta(seconds=(port-20)),
                source_ip="10.0.0.5",
                event_type="firewall_block",
                dest_ip="192.168.1.1",
                dest_port=port
            )
            incidents.append(inc)
        
        detections = self.detector.detect(incidents)
        
        # Should detect port scan
        scan_found = any("scan" in d[1].lower() for d in detections)
        self.assertTrue(scan_found)


class TestStatisticalDetector(unittest.TestCase):
    
    def setUp(self):
        self.detector = StatisticalDetector(zscore_threshold=2.0)
    
    def test_volume_anomaly_detection(self):
        """Test traffic spike detection"""
        
        base_time = datetime.now(pytz.UTC)
        incidents = []
        
        # Normal traffic: 5 requests per minute
        for minute in range(10):
            for req in range(5):
                inc = Incident(
                    timestamp=base_time + timedelta(minutes=minute, seconds=req*10),
                    source_ip="192.168.1.1",
                    event_type="http_request"
                )
                incidents.append(inc)
        
        # Spike: 50 requests in one minute
        spike_time = base_time + timedelta(minutes=10)
        for req in range(50):
            inc = Incident(
                timestamp=spike_time + timedelta(seconds=req),
                source_ip="10.0.0.10",
                event_type="http_request"
            )
            incidents.append(inc)
        
        detections = self.detector.detect(incidents)
        
        # Should detect the spike
        spike_detected = any("spike" in d[1].lower() or "ddos" in str(d[2]).lower() for d in detections)
        self.assertTrue(spike_detected)
    
    def test_rate_anomaly_detection(self):
        """Test excessive request rate detection"""
        
        base_time = datetime.now(pytz.UTC)
        incidents = []
        
        # Normal users: 10 requests spread over time
        for user_id in range(5):
            for req in range(10):
                inc = Incident(
                    timestamp=base_time + timedelta(minutes=req),
                    source_ip=f"192.168.1.{user_id}",
                    event_type="api_call"
                )
                incidents.append(inc)
        
        # Abusive user: 100 requests in 1 minute
        for req in range(100):
            inc = Incident(
                timestamp=base_time + timedelta(seconds=req),
                source_ip="10.0.0.99",
                event_type="api_call"
            )
            incidents.append(inc)
        
        detections = self.detector.detect(incidents)
        
        # Should detect excessive rate
        rate_detected = any("rate" in d[1].lower() for d in detections)
        self.assertTrue(rate_detected)
    
    def test_size_anomaly_detection(self):
        """Test large response detection"""
        
        base_time = datetime.now(pytz.UTC)
        incidents = []
        
        # Normal responses: ~1KB
        for i in range(20):
            inc = Incident(
                timestamp=base_time + timedelta(seconds=i),
                source_ip=f"192.168.1.{i}",
                event_type="http_request",
                response_size=1024 + (i * 100)
            )
            incidents.append(inc)
        
        # Abnormally large response: 50MB
        large_inc = Incident(
            timestamp=base_time + timedelta(seconds=30),
            source_ip="10.0.0.50",
            event_type="http_request",
            response_size=50 * 1024 * 1024
        )
        incidents.append(large_inc)
        
        detections = self.detector.detect(incidents)
        
        # Should detect large response
        size_detected = any("large" in d[1].lower() or "size" in d[1].lower() for d in detections)
        self.assertTrue(size_detected)


if __name__ == '__main__':
    unittest.main()

