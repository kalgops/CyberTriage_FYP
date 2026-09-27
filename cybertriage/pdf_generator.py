"""PDF Report Generator for CyberTriage.

Generates professional PDF reports with charts, tables, and analysis.
"""

from __future__ import annotations

from fpdf import FPDF
from datetime import datetime
from typing import Dict, List
import pandas as pd
import io


class CyberTriagePDF(FPDF):
    """Custom PDF class for CyberTriage reports."""
    
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        
    def header(self):
        """Add header to each page."""
        self.set_font('Arial', 'B', 12)
        self.set_text_color(102, 126, 234)
        self.cell(0, 10, 'CyberTriage Security Report', 0, 1, 'C')
        self.set_text_color(0, 0, 0)
        self.ln(5)
        
    def footer(self):
        """Add footer to each page."""
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')
        
    def chapter_title(self, title: str):
        """Add a chapter title."""
        self.set_font('Arial', 'B', 14)
        self.set_fill_color(102, 126, 234)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, title, 0, 1, 'L', 1)
        self.ln(4)
        self.set_text_color(0, 0, 0)
        
    def section_title(self, title: str):
        """Add a section title."""
        self.set_font('Arial', 'B', 12)
        self.set_text_color(102, 126, 234)
        self.cell(0, 8, title, 0, 1, 'L')
        self.ln(2)
        self.set_text_color(0, 0, 0)
        
    def add_key_value(self, key: str, value: str, bold_key: bool = True):
        """Add a key-value pair."""
        if bold_key:
            self.set_font('Arial', 'B', 10)
        else:
            self.set_font('Arial', '', 10)
        self.cell(60, 6, f"{key}:", 0, 0)
        self.set_font('Arial', '', 10)
        self.cell(0, 6, str(value), 0, 1)
        
    def add_alert_box(self, text: str, severity: str = 'info'):
        """Add a colored alert box."""
        colors = {
            'critical': (239, 68, 68),
            'warning': (245, 158, 11),
            'success': (16, 185, 129),
            'info': (59, 130, 246)
        }
        
        color = colors.get(severity, colors['info'])
        
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font('Arial', 'B', 11)
        
        # Multi-cell for wrapping
        self.multi_cell(0, 8, text, 0, 'L', 1)
        self.ln(2)
        self.set_text_color(0, 0, 0)


def generate_pdf_report(report_obj: Dict, detection: Dict, df: pd.DataFrame, 
                       comparison: pd.DataFrame = None) -> bytes:
    """Generate a comprehensive PDF report.
    
    Args:
        report_obj: Report object from report.build_report()
        detection: Detection results from detector.detect()
        df: Parsed log DataFrame
        comparison: Model comparison DataFrame (optional)
        
    Returns:
        PDF file as bytes
    """
    pdf = CyberTriagePDF()
    pdf.add_page()
    
    # Title Page
    pdf.set_font('Arial', 'B', 24)
    pdf.set_text_color(102, 126, 234)
    pdf.cell(0, 20, 'CyberTriage', 0, 1, 'C')
    
    pdf.set_font('Arial', '', 16)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, 'Security Incident Analysis Report', 0, 1, 'C')
    
    pdf.ln(10)
    
    # Report metadata
    pdf.set_font('Arial', 'I', 10)
    pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, 'C')
    pdf.cell(0, 6, "AI-Assisted Log Triage System", 0, 1, 'C')
    
    pdf.ln(20)
    
    # Executive Summary
    pdf.chapter_title('Executive Summary')
    
    incident_type = report_obj.get('incident_type', 'Unknown')
    severity = report_obj.get('severity', 'Unknown')
    
    # Severity alert box
    severity_map = {
        'High': 'critical',
        'Medium': 'warning',
        'Low': 'info',
        'Informational': 'success'
    }
    
    pdf.add_alert_box(
        f"Incident Type: {incident_type} | Severity: {severity}",
        severity_map.get(severity, 'info')
    )
    
    pdf.ln(5)
    
    # Key Metrics
    pdf.section_title('Key Metrics')
    pdf.add_key_value('Total Events Analyzed', detection.get('total_events', 0))
    pdf.add_key_value('Failed Login Attempts', detection.get('total_failed', 0))
    pdf.add_key_value('Flagged IP Addresses', len(detection.get('flagged_ips', [])))
    pdf.add_key_value('Unique Source IPs', df['source_ip'].nunique() if not df.empty and 'source_ip' in df.columns else 0)
    
    pdf.ln(5)
    
    # Incident Explanation
    pdf.section_title('Incident Explanation')
    pdf.set_font('Arial', '', 10)
    summary = report_obj.get('summary', 'No summary available')
    pdf.multi_cell(0, 6, summary)
    
    pdf.ln(5)
    
    # Evidence Summary
    pdf.chapter_title('Evidence Summary')
    
    evidence = report_obj.get('evidence', {})
    for key, value in evidence.items():
        pdf.add_key_value(key, value)
    
    pdf.ln(5)
    
    # Top Offender Details
    top = report_obj.get('top_offender')
    if top:
        pdf.section_title('Primary Threat Source')
        pdf.add_key_value('Source IP Address', top.get('source_ip', 'N/A'))
        pdf.add_key_value('Failed Attempts', top.get('failed_count', 0))
        pdf.add_key_value('Unique Usernames Targeted', top.get('username_count', 0))
        pdf.add_key_value('First Seen', top.get('first_seen', 'N/A'))
        pdf.add_key_value('Last Seen', top.get('last_seen', 'N/A'))
        pdf.add_key_value('Severity Level', top.get('severity', 'N/A'))
        
        if top.get('unique_usernames'):
            pdf.ln(3)
            pdf.set_font('Arial', 'B', 10)
            pdf.cell(0, 6, 'Targeted Usernames:', 0, 1)
            pdf.set_font('Arial', '', 9)
            usernames = ', '.join(top['unique_usernames'][:10])
            if len(top['unique_usernames']) > 10:
                usernames += f" ... and {len(top['unique_usernames']) - 10} more"
            pdf.multi_cell(0, 5, usernames)
    
    pdf.ln(5)
    
    # Model Comparison
    if comparison is not None and not comparison.empty:
        pdf.add_page()
        pdf.chapter_title('AI Model Analysis')
        
        pdf.section_title('Detection Model Comparison')
        pdf.set_font('Arial', '', 10)
        pdf.multi_cell(0, 6, 
            "The system employs both rule-based detection and machine learning (Isolation Forest) "
            "for comprehensive threat analysis. Below is a comparison of both approaches.")
        
        pdf.ln(3)
        
        # Model agreement statistics
        if 'rule_flagged' in comparison.columns and 'isolation_forest_anomaly' in comparison.columns:
            agreement = (comparison['rule_flagged'] == comparison['isolation_forest_anomaly']).sum()
            total = len(comparison)
            agreement_pct = (agreement / total * 100) if total > 0 else 0
            
            pdf.add_key_value('Total IPs Analyzed', total)
            pdf.add_key_value('Model Agreement Rate', f"{agreement_pct:.1f}%")
            pdf.add_key_value('Rule-Based Detections', comparison['rule_flagged'].sum())
            pdf.add_key_value('ML Anomalies Detected', comparison['isolation_forest_anomaly'].sum())
    
    pdf.ln(5)
    
    # Recommended Actions
    pdf.add_page()
    pdf.chapter_title('Recommended Actions')
    
    steps = report_obj.get('recommended_steps', [])
    for idx, step in enumerate(steps, 1):
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(10, 6, f"{idx}.", 0, 0)
        pdf.set_font('Arial', '', 10)
        pdf.multi_cell(0, 6, step)
        pdf.ln(2)
    
    pdf.ln(5)
    
    # Per-IP Breakdown
    if detection.get('ip_summaries'):
        pdf.add_page()
        pdf.chapter_title('Detailed IP Analysis')
        
        for idx, ip_summary in enumerate(detection['ip_summaries'][:10], 1):
            pdf.section_title(f"{idx}. {ip_summary['source_ip']}")
            
            pdf.add_key_value('Failed Attempts', ip_summary['failed_count'])
            pdf.add_key_value('Unique Usernames', ip_summary['username_count'])
            pdf.add_key_value('Severity', ip_summary['severity'])
            pdf.add_key_value('Status', 'Flagged' if ip_summary['flagged'] else 'Normal')
            pdf.add_key_value('Time Window', 
                            f"{ip_summary.get('first_seen', 'N/A')} to {ip_summary.get('last_seen', 'N/A')}")
            
            pdf.ln(3)
    
    # Technical Details
    pdf.add_page()
    pdf.chapter_title('Technical Details')
    
    pdf.section_title('Detection Thresholds')
    pdf.set_font('Arial', '', 10)
    pdf.multi_cell(0, 6, 
        "Low Severity: 3-4 failed attempts\n"
        "Medium Severity: 5-9 failed attempts\n"
        "High Severity: 10+ failed attempts\n\n"
        "Note: Severity is escalated by one level when multiple usernames are targeted, "
        "indicating potential password spraying behavior.")
    
    pdf.ln(5)
    
    pdf.section_title('Machine Learning Model')
    pdf.set_font('Arial', '', 10)
    pdf.multi_cell(0, 6,
        "Model: Isolation Forest (Unsupervised Anomaly Detection)\n"
        "Features: Failed count, successful count, unique usernames, events per minute, "
        "duration, failure ratio\n"
        "Purpose: Provides supplementary anomaly detection to complement rule-based analysis")
    
    pdf.ln(10)
    
    # Footer note
    pdf.set_font('Arial', 'I', 8)
    pdf.set_text_color(128, 128, 128)
    pdf.multi_cell(0, 5,
        "This report was generated by CyberTriage, an AI-assisted cybersecurity log triage system. "
        "This is a defensive education prototype. All analysis should be verified by qualified "
        "security personnel before taking action.")
    
    # Return PDF as bytes
    # fpdf2 returns a bytearray; normalise it to immutable download bytes.
    return bytes(pdf.output())
