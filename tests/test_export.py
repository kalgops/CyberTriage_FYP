"""Tests for export module."""

import json
from cybertriage import export, parser, detector, report


def test_export_to_json_produces_valid_json():
    """Test that JSON export produces valid JSON."""
    log_text = """Jun 10 10:01:22 server sshd[1122]: Failed password for root from 192.168.1.45 port 53422 ssh2
Jun 10 10:01:25 server sshd[1123]: Failed password for admin from 192.168.1.45 port 53423 ssh2"""
    
    df = parser.parse_log_text(log_text)
    detection = detector.detect(df)
    report_obj = report.build_report(df, detection)
    
    json_output = export.export_to_json(report_obj, detection, df)
    
    # Should be valid JSON
    data = json.loads(json_output)
    
    assert "metadata" in data
    assert "incident" in data
    assert "evidence" in data
    assert data["metadata"]["tool"] == "CyberTriage"


def test_mitre_attack_mapping_for_brute_force():
    """Test MITRE ATT&CK mapping for brute force incidents."""
    log_text = """Jun 10 10:01:22 server sshd[1122]: Failed password for root from 192.168.1.45 port 53422 ssh2
Jun 10 10:01:25 server sshd[1123]: Failed password for admin from 192.168.1.45 port 53423 ssh2
Jun 10 10:01:28 server sshd[1124]: Failed password for test from 192.168.1.45 port 53424 ssh2
Jun 10 10:01:31 server sshd[1125]: Failed password for ubuntu from 192.168.1.45 port 53425 ssh2
Jun 10 10:01:34 server sshd[1126]: Failed password for user from 192.168.1.45 port 53426 ssh2
Jun 10 10:01:37 server sshd[1127]: Failed password for guest from 192.168.1.45 port 53427 ssh2
Jun 10 10:01:40 server sshd[1128]: Failed password for oracle from 192.168.1.45 port 53428 ssh2
Jun 10 10:01:43 server sshd[1129]: Failed password for mysql from 192.168.1.45 port 53429 ssh2
Jun 10 10:01:46 server sshd[1130]: Failed password for postgres from 192.168.1.45 port 53430 ssh2
Jun 10 10:01:49 server sshd[1131]: Failed password for jenkins from 192.168.1.45 port 53431 ssh2"""
    
    df = parser.parse_log_text(log_text)
    detection = detector.detect(df)
    report_obj = report.build_report(df, detection)
    
    mitre_mapping = export.map_to_mitre_attack(report_obj)
    
    assert "tactics" in mitre_mapping
    assert "techniques" in mitre_mapping
    assert "TA0006" in mitre_mapping["tactics"]  # Credential Access
    assert any(t["id"] == "T1110" for t in mitre_mapping["techniques"])  # Brute Force


def test_mitre_attack_mapping_for_normal():
    """Test MITRE ATT&CK mapping for normal activity."""
    log_text = """Jun 10 10:01:22 server sshd[1122]: Accepted password for alice from 192.168.1.10 port 53422 ssh2"""
    
    df = parser.parse_log_text(log_text)
    detection = detector.detect(df)
    report_obj = report.build_report(df, detection)
    
    mitre_mapping = export.map_to_mitre_attack(report_obj)
    
    assert len(mitre_mapping["tactics"]) == 0
    assert len(mitre_mapping["techniques"]) == 0
    assert "notes" in mitre_mapping


def test_export_stix_bundle_produces_valid_json():
    """Test that STIX bundle export produces valid JSON."""
    log_text = """Jun 10 10:01:22 server sshd[1122]: Failed password for root from 192.168.1.45 port 53422 ssh2
Jun 10 10:01:25 server sshd[1123]: Failed password for admin from 192.168.1.45 port 53423 ssh2
Jun 10 10:01:28 server sshd[1124]: Failed password for test from 192.168.1.45 port 53424 ssh2
Jun 10 10:01:31 server sshd[1125]: Failed password for ubuntu from 192.168.1.45 port 53425 ssh2
Jun 10 10:01:34 server sshd[1126]: Failed password for user from 192.168.1.45 port 53426 ssh2
Jun 10 10:01:37 server sshd[1127]: Failed password for guest from 192.168.1.45 port 53427 ssh2
Jun 10 10:01:40 server sshd[1128]: Failed password for oracle from 192.168.1.45 port 53428 ssh2
Jun 10 10:01:43 server sshd[1129]: Failed password for mysql from 192.168.1.45 port 53429 ssh2
Jun 10 10:01:46 server sshd[1130]: Failed password for postgres from 192.168.1.45 port 53430 ssh2
Jun 10 10:01:49 server sshd[1131]: Failed password for jenkins from 192.168.1.45 port 53431 ssh2"""
    
    df = parser.parse_log_text(log_text)
    detection = detector.detect(df)
    report_obj = report.build_report(df, detection)
    
    stix_output = export.export_stix_bundle(report_obj, detection)
    
    # Should be valid JSON
    data = json.loads(stix_output)
    
    assert data["type"] == "bundle"
    assert "objects" in data
    assert len(data["objects"]) > 0


def test_export_csv_summary():
    """Test CSV summary export."""
    log_text = """Jun 10 10:01:22 server sshd[1122]: Failed password for root from 192.168.1.45 port 53422 ssh2
Jun 10 10:01:25 server sshd[1123]: Failed password for admin from 192.168.1.45 port 53423 ssh2"""
    
    df = parser.parse_log_text(log_text)
    detection = detector.detect(df)
    
    csv_output = export.export_csv_summary(detection)
    
    assert "source_ip" in csv_output
    assert "failed_count" in csv_output
    assert "192.168.1.45" in csv_output


def test_export_siem_format():
    """Test CEF format export for SIEM."""
    log_text = """Jun 10 10:01:22 server sshd[1122]: Failed password for root from 192.168.1.45 port 53422 ssh2
Jun 10 10:01:25 server sshd[1123]: Failed password for admin from 192.168.1.45 port 53423 ssh2
Jun 10 10:01:28 server sshd[1124]: Failed password for test from 192.168.1.45 port 53424 ssh2
Jun 10 10:01:31 server sshd[1125]: Failed password for ubuntu from 192.168.1.45 port 53425 ssh2
Jun 10 10:01:34 server sshd[1126]: Failed password for user from 192.168.1.45 port 53426 ssh2
Jun 10 10:01:37 server sshd[1127]: Failed password for guest from 192.168.1.45 port 53427 ssh2
Jun 10 10:01:40 server sshd[1128]: Failed password for oracle from 192.168.1.45 port 53428 ssh2
Jun 10 10:01:43 server sshd[1129]: Failed password for mysql from 192.168.1.45 port 53429 ssh2
Jun 10 10:01:46 server sshd[1130]: Failed password for postgres from 192.168.1.45 port 53430 ssh2
Jun 10 10:01:49 server sshd[1131]: Failed password for jenkins from 192.168.1.45 port 53431 ssh2"""
    
    df = parser.parse_log_text(log_text)
    detection = detector.detect(df)
    report_obj = report.build_report(df, detection)
    
    cef_output = export.export_siem_format(report_obj, detection, df)
    
    assert cef_output.startswith("CEF:0|CyberTriage|")
    assert "192.168.1.45" in cef_output
    assert "src=" in cef_output
