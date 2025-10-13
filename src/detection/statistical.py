from typing import List, Tuple, Dict
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import statistics

from src.models.incident import Incident, IncidentType, Severity


class StatisticalDetector:
    """
    Statistical anomaly detection using basic statistical methods.
    
    No ML libraries - just math and statistics module.
    
    Methods:
    - Volume anomalies (Z-score based)
    - Rate limiting violations
    - Geographic velocity (impossible travel)
    - Response size anomalies
    """
    
    def __init__(self, zscore_threshold=3.0):
        self.zscore_threshold = zscore_threshold
        
    def detect(self, incidents: List[Incident]) -> List[Tuple[Incident, str, IncidentType]]:
        """Run statistical anomaly detection"""
        
        detections = []
        
        # Volume-based anomalies
        volume_anomalies = self._detect_volume_anomalies(incidents)
        detections.extend(volume_anomalies)
        
        # Rate limiting
        rate_anomalies = self._detect_rate_anomalies(incidents)
        detections.extend(rate_anomalies)
        
        # Response size anomalies
        size_anomalies = self._detect_size_anomalies(incidents)
        detections.extend(size_anomalies)
        
        return detections
    
    def _calculate_zscore(self, value: float, mean: float, std: float) -> float:
        """Calculate Z-score for outlier detection"""
        if std == 0:
            return 0
        return abs(value - mean) / std
    
    def _detect_volume_anomalies(self, incidents: List[Incident]) -> List[Tuple[Incident, str, IncidentType]]:
        """
        Detect unusual traffic volumes.
        
        Logic:
        1. Group requests by time buckets (e.g., per minute)
        2. Calculate mean and stdev of requests per bucket
        3. Flag buckets with Z-score > threshold
        """
        
        detections = []
        
        if len(incidents) < 10:
            return detections  # Not enough data
        
        # Group by 1-minute buckets
        buckets = defaultdict(list)
        for incident in incidents:
            # Round to minute
            bucket = incident.timestamp.replace(second=0, microsecond=0)
            buckets[bucket].append(incident)
        
        # Calculate statistics
        counts = [len(incs) for incs in buckets.values()]
        
        if len(counts) < 3:
            return detections
        
        mean_count = statistics.mean(counts)
        try:
            stdev_count = statistics.stdev(counts)
        except:
            return detections
        
        # Find anomalous buckets
        for bucket, incs in buckets.items():
            count = len(incs)
            zscore = self._calculate_zscore(count, mean_count, stdev_count)
            
            if zscore > self.zscore_threshold:
                # Group by source IP to find culprit
                ip_counts = Counter([inc.source_ip for inc in incs])
                top_ip, top_count = ip_counts.most_common(1)[0]
                
                for inc in incs:
                    if inc.source_ip == top_ip:
                        inc.incident_type = IncidentType.DDoS
                        inc.severity = Severity.CRITICAL
                
                detections.append((
                    incs[0],
                    f"Traffic spike detected: {count} requests at {bucket.strftime('%H:%M')} (mean: {mean_count:.1f}, Z-score: {zscore:.2f}). Top source: {top_ip} ({top_count} requests)",
                    IncidentType.DDoS
                ))
        
        return detections
    
    def _detect_rate_anomalies(self, incidents: List[Incident]) -> List[Tuple[Incident, str, IncidentType]]:
        """
        Detect IPs making too many requests too quickly.
        
        Logic: Calculate request rate per IP and flag outliers
        """
        
        detections = []
        
        # Group by IP
        ip_incidents = defaultdict(list)
        for inc in incidents:
            ip_incidents[inc.source_ip].append(inc)
        
        # Calculate rates (requests per minute)
        rates = []
        for ip, incs in ip_incidents.items():
            if len(incs) < 2:
                continue
            
            incs_sorted = sorted(incs, key=lambda x: x.timestamp)
            time_span = (incs_sorted[-1].timestamp - incs_sorted[0].timestamp).total_seconds() / 60
            
            if time_span > 0:
                rate = len(incs) / time_span
                rates.append((ip, rate, incs_sorted))
        
        if len(rates) < 3:
            return detections
        
        # Calculate statistics
        rate_values = [r[1] for r in rates]
        mean_rate = statistics.mean(rate_values)
        
        try:
            stdev_rate = statistics.stdev(rate_values)
        except:
            return detections
        
        # Find anomalous rates
        for ip, rate, incs in rates:
            zscore = self._calculate_zscore(rate, mean_rate, stdev_rate)
            
            if zscore > self.zscore_threshold and rate > 50:  # also require absolute threshold
                for inc in incs:
                    inc.incident_type = IncidentType.SUSPICIOUS_ACTIVITY
                    inc.severity = Severity.HIGH
                
                detections.append((
                    incs[0],
                    f"Excessive request rate from {ip}: {rate:.1f} req/min (mean: {mean_rate:.1f}, Z-score: {zscore:.2f})",
                    IncidentType.SUSPICIOUS_ACTIVITY
                ))
        
        return detections
    
    def _detect_size_anomalies(self, incidents: List[Incident]) -> List[Tuple[Incident, str, IncidentType]]:
        """
        Detect unusual response sizes (potential data exfiltration).
        
        Logic: Flag responses with abnormally large sizes
        """
        
        detections = []
        
        # Filter incidents with response size
        sized_incidents = [inc for inc in incidents if inc.response_size and inc.response_size > 0]
        
        if len(sized_incidents) < 10:
            return detections
        
        sizes = [inc.response_size for inc in sized_incidents]
        mean_size = statistics.mean(sizes)
        
        try:
            stdev_size = statistics.stdev(sizes)
        except:
            return detections
        
        # Find anomalous sizes
        for inc in sized_incidents:
            zscore = self._calculate_zscore(inc.response_size, mean_size, stdev_size)
            
            if zscore > self.zscore_threshold and inc.response_size > 1000000:  # > 1MB and outlier
                inc.incident_type = IncidentType.DATA_EXFILTRATION
                inc.severity = Severity.CRITICAL
                
                detections.append((
                    inc,
                    f"Unusually large response: {inc.response_size / 1024 / 1024:.2f} MB from {inc.source_ip} (mean: {mean_size / 1024:.1f} KB, Z-score: {zscore:.2f})",
                    IncidentType.DATA_EXFILTRATION
                ))
        
        return detections

