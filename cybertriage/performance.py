"""Performance monitoring and analytics for CyberTriage.

Tracks analysis performance metrics and provides insights into system behavior.
This module is for monitoring only - no offensive capability.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class AnalysisMetrics:
    """Performance metrics for a single analysis run."""
    
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    total_lines: int = 0
    parsed_lines: int = 0
    unique_ips: int = 0
    parsing_time_ms: float = 0.0
    detection_time_ms: float = 0.0
    ml_time_ms: float = 0.0
    total_time_ms: float = 0.0
    llm_used: bool = False
    llm_time_ms: float = 0.0
    
    @property
    def parse_rate(self) -> float:
        """Lines parsed per second."""
        if self.parsing_time_ms > 0:
            return (self.parsed_lines / self.parsing_time_ms) * 1000
        return 0.0
    
    @property
    def success_rate(self) -> float:
        """Percentage of lines successfully parsed."""
        if self.total_lines > 0:
            return (self.parsed_lines / self.total_lines) * 100
        return 0.0
    
    def to_dict(self) -> Dict[str, object]:
        """Convert metrics to dictionary for display."""
        return {
            "timestamp": self.timestamp,
            "total_lines": self.total_lines,
            "parsed_lines": self.parsed_lines,
            "unique_ips": self.unique_ips,
            "parsing_time_ms": round(self.parsing_time_ms, 2),
            "detection_time_ms": round(self.detection_time_ms, 2),
            "ml_time_ms": round(self.ml_time_ms, 2),
            "total_time_ms": round(self.total_time_ms, 2),
            "parse_rate_per_sec": round(self.parse_rate, 2),
            "success_rate_pct": round(self.success_rate, 2),
            "llm_used": self.llm_used,
            "llm_time_ms": round(self.llm_time_ms, 2) if self.llm_used else 0.0,
        }


class PerformanceMonitor:
    """Context manager for tracking analysis performance."""
    
    def __init__(self):
        self.metrics = AnalysisMetrics()
        self._start_time: Optional[float] = None
        self._section_start: Optional[float] = None
    
    def __enter__(self) -> "PerformanceMonitor":
        """Start overall timing."""
        self._start_time = time.perf_counter()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Calculate total time."""
        if self._start_time:
            self.metrics.total_time_ms = (time.perf_counter() - self._start_time) * 1000
    
    def start_section(self, section: str) -> None:
        """Start timing a specific section."""
        self._section_start = time.perf_counter()
    
    def end_section(self, section: str) -> None:
        """End timing and record duration."""
        if self._section_start:
            duration_ms = (time.perf_counter() - self._section_start) * 1000
            
            if section == "parsing":
                self.metrics.parsing_time_ms = duration_ms
            elif section == "detection":
                self.metrics.detection_time_ms = duration_ms
            elif section == "ml":
                self.metrics.ml_time_ms = duration_ms
            elif section == "llm":
                self.metrics.llm_time_ms = duration_ms
                self.metrics.llm_used = True
            
            self._section_start = None
    
    def set_input_stats(self, total_lines: int, parsed_lines: int, unique_ips: int) -> None:
        """Record input statistics."""
        self.metrics.total_lines = total_lines
        self.metrics.parsed_lines = parsed_lines
        self.metrics.unique_ips = unique_ips
    
    def get_metrics(self) -> AnalysisMetrics:
        """Get the collected metrics."""
        return self.metrics


class AnalysisHistory:
    """Maintains history of analysis runs for session analytics."""
    
    def __init__(self, max_history: int = 100):
        self.max_history = max_history
        self.history: List[AnalysisMetrics] = []
    
    def add(self, metrics: AnalysisMetrics) -> None:
        """Add metrics to history."""
        self.history.append(metrics)
        if len(self.history) > self.max_history:
            self.history.pop(0)
    
    def get_summary(self) -> Dict[str, object]:
        """Get summary statistics across all runs."""
        if not self.history:
            return {
                "total_runs": 0,
                "total_lines_processed": 0,
                "avg_parse_time_ms": 0.0,
                "avg_total_time_ms": 0.0,
            }
        
        return {
            "total_runs": len(self.history),
            "total_lines_processed": sum(m.total_lines for m in self.history),
            "total_parsed_lines": sum(m.parsed_lines for m in self.history),
            "avg_parse_time_ms": sum(m.parsing_time_ms for m in self.history) / len(self.history),
            "avg_detection_time_ms": sum(m.detection_time_ms for m in self.history) / len(self.history),
            "avg_ml_time_ms": sum(m.ml_time_ms for m in self.history) / len(self.history),
            "avg_total_time_ms": sum(m.total_time_ms for m in self.history) / len(self.history),
            "llm_usage_count": sum(1 for m in self.history if m.llm_used),
        }
    
    def clear(self) -> None:
        """Clear history."""
        self.history.clear()
