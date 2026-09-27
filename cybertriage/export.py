"""Enhanced export capabilities for CyberTriage reports.

Provides multiple export formats including JSON, MITRE ATT&CK mapping,
and structured incident data for integration with other security tools.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Dict, List, Optional

import pandas as pd


def export_to_json(report_obj: Dict, detection: Dict, df: pd.DataFrame) -> str:
    """Export analysis results as structured JSON.
    
    Args:
        report_obj: Report object from build_report()
        detection: Detection results from detect()
        df: Parsed log DataFrame
    
    Returns:
        JSON string with complete analysis results
    """
    # Convert DataFrame to records for JSON serialization
    log_records = df.to_dict('records') if not df.empty else []
    
    export_data = {
        "metadata": {
            "export_timestamp": datetime.now().isoformat(),
            "tool": "CyberTriage",
            "version": "2.0.0",
            "analysis_type": "SSH Authentication Log Triage"
        },
        "incident": {
            "type": report_obj.get("incident_type"),
            "severity": report_obj.get("severity"),
            "summary": report_obj.get("summary"),
            "confidence": "high" if report_obj.get("severity") in ["High", "Medium"] else "low"
        },
        "evidence": report_obj.get("evidence", {}),
        "detection": {
            "total_events": detection.get("total_events", 0),
            "total_failed": detection.get("total_failed", 0),
            "overall_severity": detection.get("overall_severity"),
            "flagged_ip_count": len(detection.get("flagged_ips", []))
        },
        "top_offender": report_obj.get("top_offender"),
        "ip_summaries": detection.get("ip_summaries", []),
        "recommended_actions": report_obj.get("recommended_steps", []),
        "raw_logs": log_records[:100]  # Limit to first 100 for size
    }
    
    return json.dumps(export_data, indent=2, default=str)


def map_to_mitre_attack(report_obj: Dict) -> Dict[str, object]:
    """Map detected incident to MITRE ATT&CK framework.
    
    Args:
        report_obj: Report object from build_report()
    
    Returns:
        Dictionary with MITRE ATT&CK technique mappings
    """
    incident_type = report_obj.get("incident_type", "")
    severity = report_obj.get("severity", "")
    
    # Base mapping for SSH brute force attacks
    if "Brute Force" in incident_type:
        return {
            "tactics": ["TA0006"],  # Credential Access
            "techniques": [
                {
                    "id": "T1110",
                    "name": "Brute Force",
                    "sub_techniques": [
                        {
                            "id": "T1110.001",
                            "name": "Password Guessing",
                            "confidence": "high" if severity == "High" else "medium"
                        }
                    ]
                },
                {
                    "id": "T1078",
                    "name": "Valid Accounts",
                    "sub_techniques": [
                        {
                            "id": "T1078.003",
                            "name": "Local Accounts",
                            "confidence": "medium"
                        }
                    ]
                }
            ],
            "detection_methods": [
                "Authentication logs analysis",
                "Failed login threshold detection",
                "Anomaly-based detection"
            ],
            "data_sources": [
                "DS0028: Logon Session",
                "DS0002: User Account"
            ]
        }
    
    elif "Suspicious" in incident_type:
        return {
            "tactics": ["TA0006"],  # Credential Access
            "techniques": [
                {
                    "id": "T1110",
                    "name": "Brute Force",
                    "sub_techniques": [],
                    "confidence": "low"
                }
            ],
            "detection_methods": ["Authentication logs analysis"],
            "data_sources": ["DS0028: Logon Session"]
        }
    
    else:
        return {
            "tactics": [],
            "techniques": [],
            "detection_methods": ["Authentication logs analysis"],
            "data_sources": ["DS0028: Logon Session"],
            "notes": "No malicious activity detected"
        }


def export_stix_bundle(report_obj: Dict, detection: Dict) -> str:
    """Export as STIX 2.1 bundle for threat intelligence sharing.
    
    Args:
        report_obj: Report object from build_report()
        detection: Detection results from detect()
    
    Returns:
        JSON string with STIX 2.1 bundle
    """
    timestamp = datetime.now().isoformat() + "Z"
    top = report_obj.get("top_offender")
    
    # Create indicator object for suspicious IP
    objects = []
    
    if top and report_obj.get("severity") in ["High", "Medium"]:
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "created": timestamp,
            "modified": timestamp,
            "name": f"SSH Brute Force from {top['source_ip']}",
            "description": report_obj.get("summary", ""),
            "pattern": f"[ipv4-addr:value = '{top['source_ip']}']",
            "pattern_type": "stix",
            "valid_from": timestamp,
            "indicator_types": ["malicious-activity"],
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "credential-access"
                }
            ]
        }
        objects.append(indicator)
    
    bundle = {
        "type": "bundle",
        "id": f"bundle--{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "objects": objects
    }
    
    return json.dumps(bundle, indent=2)


def export_csv_summary(detection: Dict) -> str:
    """Export IP summary as CSV for spreadsheet analysis.
    
    Args:
        detection: Detection results from detect()
    
    Returns:
        CSV string with IP summaries
    """
    ip_summaries = detection.get("ip_summaries", [])
    
    if not ip_summaries:
        return "source_ip,failed_count,username_count,severity,flagged,verdict\n"
    
    df = pd.DataFrame([
        {
            "source_ip": s["source_ip"],
            "failed_count": s["failed_count"],
            "username_count": s["username_count"],
            "unique_usernames": ";".join(s["unique_usernames"]),
            "first_seen": s["first_seen"],
            "last_seen": s["last_seen"],
            "severity": s["severity"],
            "flagged": s["flagged"],
            "verdict": s["verdict"]
        }
        for s in ip_summaries
    ])
    
    return df.to_csv(index=False)


def export_siem_format(report_obj: Dict, detection: Dict, df: pd.DataFrame) -> str:
    """Export in Common Event Format (CEF) for SIEM ingestion.
    
    Args:
        report_obj: Report object from build_report()
        detection: Detection results from detect()
        df: Parsed log DataFrame
    
    Returns:
        CEF formatted string
    """
    top = report_obj.get("top_offender")
    severity_map = {"High": 10, "Medium": 7, "Low": 4, "Informational": 1}
    cef_severity = severity_map.get(report_obj.get("severity", "Informational"), 1)
    
    if top:
        cef_line = (
            f"CEF:0|CyberTriage|SSH Log Analyzer|2.0|100|{report_obj.get('incident_type')}|{cef_severity}|"
            f"src={top['source_ip']} "
            f"suser={';'.join(top['unique_usernames'][:5])} "
            f"cnt={top['failed_count']} "
            f"cs1Label=Severity cs1={report_obj.get('severity')} "
            f"cs2Label=TimeWindow cs2={top.get('first_seen', '')} to {top.get('last_seen', '')} "
            f"msg={report_obj.get('summary', '')}"
        )
    else:
        cef_line = (
            f"CEF:0|CyberTriage|SSH Log Analyzer|2.0|100|{report_obj.get('incident_type')}|{cef_severity}|"
            f"msg={report_obj.get('summary', '')}"
        )
    
    return cef_line
