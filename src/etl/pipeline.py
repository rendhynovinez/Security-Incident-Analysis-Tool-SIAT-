import os
from typing import List
from src.models.incident import Incident
from src.etl.parsers import (
    ApacheLogParser, 
    JSONLogParser, 
    CSVLogParser, 
    FirewallLogParser
)


class ETLPipeline:
    """
    Main ETL pipeline for ingesting and normalizing security logs.
    
    Supports multiple log formats and automatically selects appropriate parser.
    """
    
    def __init__(self):
        self.parsers = {
            'apache': ApacheLogParser(),
            'json': JSONLogParser(),
            'csv': CSVLogParser(),
            'firewall': FirewallLogParser()
        }
    
    def process_file(self, file_path: str, format_hint: str = None) -> List[Incident]:
        """
        Process a log file and return normalized incidents.
        
        Args:
            file_path: Path to log file
            format_hint: Optional hint about log format ('apache', 'json', 'csv', 'firewall')
        
        Returns:
            List of normalized Incident objects
        """
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")
        
        # Auto-detect format if not provided
        if not format_hint:
            format_hint = self._detect_format(file_path)
        
        parser = self.parsers.get(format_hint)
        if not parser:
            raise ValueError(f"Unknown format: {format_hint}")
        
        print(f"Processing {file_path} as {format_hint} format...")
        incidents = parser.parse(file_path)
        print(f"Extracted {len(incidents)} incidents")
        
        return incidents
    
    def _detect_format(self, file_path: str) -> str:
        """Auto-detect log format based on file extension and content"""
        
        # Check extension first
        ext = os.path.splitext(file_path)[1].lower()
        if ext == '.json':
            return 'json'
        elif ext == '.csv':
            return 'csv'
        
        # Peek at first line
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                first_line = f.readline().strip()
                
                if first_line.startswith('{'):
                    return 'json'
                elif ',' in first_line and 'timestamp' in first_line.lower():
                    return 'csv'
                elif '->' in first_line:
                    return 'firewall'
                else:
                    return 'apache'  # default
        except:
            return 'apache'
    
    def process_directory(self, directory: str) -> List[Incident]:
        """Process all log files in a directory"""
        
        all_incidents = []
        
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            if os.path.isfile(file_path):
                try:
                    incidents = self.process_file(file_path)
                    all_incidents.extend(incidents)
                except Exception as e:
                    print(f"Error processing {filename}: {e}")
        
        return all_incidents

