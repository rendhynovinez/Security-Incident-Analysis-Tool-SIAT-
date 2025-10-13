import unittest
import os
from src.etl.pipeline import ETLPipeline
from src.detection.rule_based import RuleBasedDetector
from src.detection.statistical import StatisticalDetector
from src.reporting.report_generator import ReportGenerator


class TestEndToEnd(unittest.TestCase):
    """Integration tests for the complete analysis pipeline"""
    
    def setUp(self):
        self.etl = ETLPipeline()
        self.rule_detector = RuleBasedDetector()
        self.stat_detector = StatisticalDetector()
        self.reporter = ReportGenerator()
        self.sample_dir = "sample_data"
    
    def test_full_pipeline(self):
        """Test complete ETL -> Detection -> Reporting pipeline"""
        
        if not os.path.exists(self.sample_dir):
            self.skipTest(f"{self.sample_dir} not found")
        
        # Step 1: ETL
        incidents = self.etl.process_directory(self.sample_dir)
        self.assertGreater(len(incidents), 0, "ETL should produce incidents")
        
        # Step 2: Detection
        rule_detections = self.rule_detector.detect(incidents)
        stat_detections = self.stat_detector.detect(incidents)
        
        all_detections = rule_detections + stat_detections
        
        # We expect some threats in sample data
        self.assertGreater(
            len(all_detections), 0,
            "Detection should find threats in sample data"
        )
        
        # Step 3: Reporting
        report = self.reporter.generate_report(
            all_detections,
            incidents
        )
        
        self.assertIsInstance(report, str)
        self.assertGreater(len(report), 100)
    
    def test_multi_format_processing(self):
        """Test that we can handle multiple log formats"""
        
        if not os.path.exists(self.sample_dir):
            self.skipTest(f"{self.sample_dir} not found")
        
        formats_found = set()
        
        for filename in os.listdir(self.sample_dir):
            file_path = os.path.join(self.sample_dir, filename)
            if os.path.isfile(file_path):
                try:
                    incidents = self.etl.process_file(file_path)
                    if incidents:
                        formats_found.add(filename.split('.')[-1])
                except Exception as e:
                    self.fail(f"Failed to process {filename}: {e}")
        
        # Should handle at least 2 different formats
        self.assertGreaterEqual(len(formats_found), 2)


if __name__ == '__main__':
    unittest.main()

