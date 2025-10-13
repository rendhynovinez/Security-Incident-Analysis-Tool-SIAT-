from typing import List, Tuple, Dict
from datetime import datetime
from collections import defaultdict

from src.models.incident import Incident, IncidentType, Severity


class ReportGenerator:
    """
    Generate human-readable incident reports with root cause analysis.
    
    Supports multiple output formats and can trace incidents across multiple log entries.
    """
    
    def generate_report(
        self, 
        detections: List[Tuple[Incident, str, IncidentType]], 
        all_incidents: List[Incident],
        output_file: str = None
    ) -> str:
        """
        Generate comprehensive security report.
        
        Args:
            detections: List of (incident, reason, type) tuples from detection engines
            all_incidents: Complete list of incidents for context
            output_file: Optional file path to save report
        
        Returns:
            Report as string
        """
        
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("SECURITY INCIDENT ANALYSIS REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Total incidents analyzed: {len(all_incidents)}")
        report_lines.append(f"Threats detected: {len(detections)}")
        report_lines.append("")
        
        # Executive summary
        report_lines.append("EXECUTIVE SUMMARY")
        report_lines.append("-" * 80)
        summary = self._generate_summary(detections)
        report_lines.append(summary)
        report_lines.append("")
        
        # Detailed findings
        report_lines.append("DETAILED FINDINGS")
        report_lines.append("-" * 80)
        
        # Group detections by type
        grouped = defaultdict(list)
        for detection in detections:
            incident, reason, itype = detection
            grouped[itype].append((incident, reason))
        
        for itype, items in grouped.items():
            report_lines.append(f"\n{itype.value.upper().replace('_', ' ')}")
            report_lines.append("~" * 40)
            
            for idx, (incident, reason) in enumerate(items, 1):
                incident_report = self._generate_incident_report(
                    incident, reason, idx, all_incidents
                )
                report_lines.append(incident_report)
                report_lines.append("")
        
        # Recommendations
        report_lines.append("\nRECOMMENDATIONS")
        report_lines.append("-" * 80)
        recommendations = self._generate_recommendations(grouped)
        report_lines.append(recommendations)
        
        report_lines.append("\n" + "=" * 80)
        report_lines.append("END OF REPORT")
        report_lines.append("=" * 80)
        
        report_text = "\n".join(report_lines)
        
        # Save to file if specified
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"Report saved to: {output_file}")
        
        return report_text
    
    def _generate_summary(self, detections: List[Tuple[Incident, str, IncidentType]]) -> str:
        """Generate executive summary"""
        
        # Count by type
        type_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        
        for incident, reason, itype in detections:
            type_counts[itype] += 1
            severity_counts[incident.severity] += 1
        
        lines = []
        lines.append(f"Detected {len(detections)} security incidents:")
        
        for itype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  - {itype.value.replace('_', ' ').title()}: {count}")
        
        lines.append("\nSeverity breakdown:")
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                lines.append(f"  - {severity.value.upper()}: {count}")
        
        return "\n".join(lines)
    
    def _generate_incident_report(
        self, 
        incident: Incident, 
        reason: str, 
        index: int,
        all_incidents: List[Incident]
    ) -> str:
        """Generate detailed report for a single incident"""
        
        lines = []
        lines.append(f"Finding #{index}")
        lines.append(f"Timestamp: {incident.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Severity: {incident.severity.value.upper()}")
        lines.append(f"Source IP: {incident.source_ip}")
        
        if incident.dest_ip:
            lines.append(f"Destination: {incident.dest_ip}:{incident.dest_port or 'N/A'}")
        
        if incident.user:
            lines.append(f"User: {incident.user}")
        
        if incident.url:
            lines.append(f"URL: {incident.url}")
        
        if incident.user_agent:
            lines.append(f"User-Agent: {incident.user_agent[:100]}")
        
        lines.append(f"\nDetection Logic:")
        lines.append(f"  {reason}")
        
        # Root cause analysis - trace related events
        timeline = self._trace_timeline(incident, all_incidents)
        if len(timeline) > 1:
            lines.append(f"\nRelated Events Timeline ({len(timeline)} events):")
            for i, event in enumerate(timeline, 1):
                lines.append(f"  {i}. [{event.timestamp.strftime('%H:%M:%S')}] {event.event_type}: {event.source_ip}")
                if event.message:
                    lines.append(f"     {event.message[:80]}")
        
        # Recommendations
        lines.append(f"\nNext Steps:")
        next_steps = self._suggest_next_steps(incident)
        for step in next_steps:
            lines.append(f"  - {step}")
        
        return "\n".join(lines)
    
    def _trace_timeline(self, incident: Incident, all_incidents: List[Incident]) -> List[Incident]:
        """
        Trace related incidents to provide context.
        
        Builds a timeline of events from the same source IP around the incident time.
        """
        
        # Get incidents from same IP within +/- 5 minutes
        time_window = 300  # seconds
        
        related = []
        for inc in all_incidents:
            if inc.source_ip == incident.source_ip:
                time_diff = abs((inc.timestamp - incident.timestamp).total_seconds())
                if time_diff <= time_window:
                    related.append(inc)
        
        # Sort by timestamp
        related.sort(key=lambda x: x.timestamp)
        
        return related
    
    def _suggest_next_steps(self, incident: Incident) -> List[str]:
        """Suggest investigation and mitigation steps"""
        
        steps = []
        
        if incident.incident_type == IncidentType.BRUTE_FORCE:
            steps.append(f"Block IP {incident.source_ip} temporarily")
            steps.append("Review authentication logs for compromised accounts")
            steps.append("Enable rate limiting on login endpoints")
            steps.append("Consider implementing CAPTCHA or MFA")
        
        elif incident.incident_type == IncidentType.SQL_INJECTION:
            steps.append(f"Block IP {incident.source_ip} immediately")
            steps.append("Review application code for SQL injection vulnerabilities")
            steps.append("Check database logs for unauthorized access")
            steps.append("Use parameterized queries and input validation")
        
        elif incident.incident_type == IncidentType.XSS:
            steps.append(f"Investigate request from {incident.source_ip}")
            steps.append("Review application for XSS vulnerabilities")
            steps.append("Implement Content Security Policy (CSP)")
            steps.append("Use proper output encoding")
        
        elif incident.incident_type == IncidentType.DDoS:
            steps.append("Enable DDoS protection mechanisms")
            steps.append("Consider using CDN or DDoS mitigation service")
            steps.append("Analyze traffic patterns for botnet signatures")
            steps.append("Implement rate limiting")
        
        elif incident.incident_type == IncidentType.DATA_EXFILTRATION:
            steps.append(f"Investigate {incident.source_ip} for unauthorized access")
            steps.append("Review data access logs")
            steps.append("Check for compromised credentials")
            steps.append("Implement DLP (Data Loss Prevention) controls")
        
        else:
            steps.append(f"Investigate IP {incident.source_ip}")
            steps.append("Review full logs for additional context")
            steps.append("Check for lateral movement attempts")
        
        return steps
    
    def _generate_recommendations(self, grouped_detections: Dict) -> str:
        """Generate overall recommendations"""
        
        lines = []
        
        if IncidentType.BRUTE_FORCE in grouped_detections:
            lines.append("• Implement account lockout policies after failed login attempts")
            lines.append("• Deploy Multi-Factor Authentication (MFA)")
        
        if IncidentType.SQL_INJECTION in grouped_detections or IncidentType.XSS in grouped_detections:
            lines.append("• Conduct security code review of web applications")
            lines.append("• Implement Web Application Firewall (WAF)")
            lines.append("• Use input validation and output encoding")
        
        if IncidentType.DDoS in grouped_detections:
            lines.append("• Deploy DDoS mitigation solution")
            lines.append("• Implement rate limiting at application and network layers")
        
        if IncidentType.DATA_EXFILTRATION in grouped_detections:
            lines.append("• Review data access controls and permissions")
            lines.append("• Implement Data Loss Prevention (DLP) solutions")
        
        lines.append("\nGeneral Recommendations:")
        lines.append("• Enable detailed logging for all critical systems")
        lines.append("• Set up real-time alerting for high-severity incidents")
        lines.append("• Conduct regular security training for development teams")
        lines.append("• Perform periodic penetration testing")
        lines.append("• Keep all systems patched and up-to-date")
        
        return "\n".join(lines)

