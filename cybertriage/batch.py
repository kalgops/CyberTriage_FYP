"""Batch processing capabilities for CyberTriage.

Enables processing multiple log files and generating comparative reports.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd

from . import parser, detector, classifier, report, anomaly


@dataclass
class BatchResult:
    """Results from processing a single log file."""
    
    filename: str
    success: bool
    error_message: Optional[str] = None
    total_lines: int = 0
    parsed_lines: int = 0
    incident_type: Optional[str] = None
    severity: Optional[str] = None
    flagged_ips: int = 0
    total_failed: int = 0
    top_offender_ip: Optional[str] = None
    processing_time_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, object]:
        """Convert to dictionary for export."""
        return {
            "filename": self.filename,
            "success": self.success,
            "error_message": self.error_message,
            "total_lines": self.total_lines,
            "parsed_lines": self.parsed_lines,
            "incident_type": self.incident_type,
            "severity": self.severity,
            "flagged_ips": self.flagged_ips,
            "total_failed": self.total_failed,
            "top_offender_ip": self.top_offender_ip,
            "processing_time_ms": round(self.processing_time_ms, 2),
        }


class BatchProcessor:
    """Process multiple log files in batch mode."""
    
    def __init__(self, model: Optional[anomaly.IsolationForestBaseline] = None):
        """Initialize batch processor.
        
        Args:
            model: Optional pre-trained anomaly detection model
        """
        self.model = model
        self.results: List[BatchResult] = []
    
    def process_file(self, file_path: str) -> Tuple[BatchResult, Optional[Dict]]:
        """Process a single log file.
        
        Args:
            file_path: Path to log file
        
        Returns:
            Tuple of (BatchResult, full_report_dict or None)
        """
        import time
        start_time = time.perf_counter()
        
        filename = os.path.basename(file_path)
        
        try:
            # Read and parse file
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                log_text = f.read()
            
            total_lines = len(log_text.splitlines())
            df = parser.parse_log_text(log_text)
            parsed_lines = len(df)
            
            # Run detection
            detection = detector.detect(df)
            incident_type = classifier.classify(df, detection)
            report_obj = report.build_report(df, detection)
            
            # Extract key metrics
            top = report_obj.get("top_offender")
            
            processing_time = (time.perf_counter() - start_time) * 1000
            
            result = BatchResult(
                filename=filename,
                success=True,
                total_lines=total_lines,
                parsed_lines=parsed_lines,
                incident_type=incident_type,
                severity=report_obj.get("severity"),
                flagged_ips=len(detection.get("flagged_ips", [])),
                total_failed=detection.get("total_failed", 0),
                top_offender_ip=top["source_ip"] if top else None,
                processing_time_ms=processing_time,
            )
            
            return result, report_obj
        
        except Exception as e:
            processing_time = (time.perf_counter() - start_time) * 1000
            result = BatchResult(
                filename=filename,
                success=False,
                error_message=str(e),
                processing_time_ms=processing_time,
            )
            return result, None
    
    def process_directory(self, directory: str, pattern: str = "*.log") -> List[BatchResult]:
        """Process all log files in a directory.
        
        Args:
            directory: Directory path
            pattern: File pattern (e.g., "*.log", "*.txt")
        
        Returns:
            List of BatchResult objects
        """
        self.results.clear()
        
        dir_path = Path(directory)
        if not dir_path.exists() or not dir_path.is_dir():
            raise ValueError(f"Directory not found: {directory}")
        
        log_files = sorted(dir_path.glob(pattern))
        
        if not log_files:
            raise ValueError(f"No files matching pattern '{pattern}' found in {directory}")
        
        for log_file in log_files:
            result, _ = self.process_file(str(log_file))
            self.results.append(result)
        
        return self.results
    
    def process_files(self, file_paths: List[str]) -> List[BatchResult]:
        """Process a list of log files.
        
        Args:
            file_paths: List of file paths
        
        Returns:
            List of BatchResult objects
        """
        self.results.clear()
        
        for file_path in file_paths:
            result, _ = self.process_file(file_path)
            self.results.append(result)
        
        return self.results
    
    def get_summary(self) -> Dict[str, object]:
        """Get summary statistics across all processed files.
        
        Returns:
            Dictionary with summary statistics
        """
        if not self.results:
            return {
                "total_files": 0,
                "successful": 0,
                "failed": 0,
                "total_lines_processed": 0,
                "total_incidents": 0,
            }
        
        successful = [r for r in self.results if r.success]
        failed = [r for r in self.results if not r.success]
        
        high_severity = sum(1 for r in successful if r.severity == "High")
        medium_severity = sum(1 for r in successful if r.severity == "Medium")
        low_severity = sum(1 for r in successful if r.severity == "Low")
        
        return {
            "total_files": len(self.results),
            "successful": len(successful),
            "failed": len(failed),
            "total_lines_processed": sum(r.total_lines for r in successful),
            "total_parsed_lines": sum(r.parsed_lines for r in successful),
            "total_incidents": sum(1 for r in successful if r.incident_type and "Brute Force" in r.incident_type),
            "severity_breakdown": {
                "high": high_severity,
                "medium": medium_severity,
                "low": low_severity,
            },
            "total_flagged_ips": sum(r.flagged_ips for r in successful),
            "avg_processing_time_ms": sum(r.processing_time_ms for r in self.results) / len(self.results),
        }
    
    def export_results_csv(self) -> str:
        """Export batch results as CSV.
        
        Returns:
            CSV string
        """
        if not self.results:
            return "filename,success,incident_type,severity,flagged_ips,total_failed,top_offender_ip\n"
        
        df = pd.DataFrame([r.to_dict() for r in self.results])
        return df.to_csv(index=False)
    
    def export_results_json(self) -> str:
        """Export batch results as JSON.
        
        Returns:
            JSON string
        """
        import json
        
        export_data = {
            "summary": self.get_summary(),
            "results": [r.to_dict() for r in self.results]
        }
        
        return json.dumps(export_data, indent=2)


def compare_logs(file_paths: List[str], model: Optional[anomaly.IsolationForestBaseline] = None) -> pd.DataFrame:
    """Compare multiple log files side-by-side.
    
    Args:
        file_paths: List of log file paths
        model: Optional pre-trained anomaly detection model
    
    Returns:
        DataFrame with comparative analysis
    """
    processor = BatchProcessor(model=model)
    results = processor.process_files(file_paths)
    
    comparison_data = []
    for result in results:
        comparison_data.append({
            "Filename": result.filename,
            "Status": "✅ Success" if result.success else "❌ Failed",
            "Lines": result.total_lines,
            "Parsed": result.parsed_lines,
            "Incident": result.incident_type or "N/A",
            "Severity": result.severity or "N/A",
            "Flagged IPs": result.flagged_ips,
            "Failed Logins": result.total_failed,
            "Top Offender": result.top_offender_ip or "None",
        })
    
    return pd.DataFrame(comparison_data)
