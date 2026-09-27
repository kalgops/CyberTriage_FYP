"""Tests for performance monitoring module."""

import time
from cybertriage import performance


def test_performance_monitor_tracks_sections():
    """Test that performance monitor tracks section timing."""
    monitor = performance.PerformanceMonitor()
    
    with monitor:
        monitor.start_section("parsing")
        time.sleep(0.01)  # Simulate work
        monitor.end_section("parsing")
        
        monitor.start_section("detection")
        time.sleep(0.01)  # Simulate work
        monitor.end_section("detection")
    
    metrics = monitor.get_metrics()
    
    assert metrics.parsing_time_ms > 0
    assert metrics.detection_time_ms > 0
    assert metrics.total_time_ms > 0
    assert metrics.total_time_ms >= metrics.parsing_time_ms + metrics.detection_time_ms


def test_performance_monitor_calculates_parse_rate():
    """Test that parse rate is calculated correctly."""
    monitor = performance.PerformanceMonitor()
    
    with monitor:
        monitor.set_input_stats(total_lines=100, parsed_lines=95, unique_ips=5)
        monitor.start_section("parsing")
        time.sleep(0.01)
        monitor.end_section("parsing")
    
    metrics = monitor.get_metrics()
    
    assert metrics.parse_rate > 0
    assert metrics.success_rate == 95.0


def test_analysis_history_maintains_summary():
    """Test that analysis history maintains summary statistics."""
    history = performance.AnalysisHistory(max_history=10)
    
    # Add some metrics
    for i in range(5):
        metrics = performance.AnalysisMetrics()
        metrics.total_lines = 100 + i
        metrics.parsed_lines = 90 + i
        metrics.parsing_time_ms = 10.0 + i
        history.add(metrics)
    
    summary = history.get_summary()
    
    assert summary["total_runs"] == 5
    assert summary["total_lines_processed"] == 100 + 101 + 102 + 103 + 104
    assert summary["avg_parse_time_ms"] == (10 + 11 + 12 + 13 + 14) / 5


def test_analysis_history_respects_max_size():
    """Test that history respects maximum size."""
    history = performance.AnalysisHistory(max_history=3)
    
    for i in range(5):
        metrics = performance.AnalysisMetrics()
        history.add(metrics)
    
    assert len(history.history) == 3


def test_metrics_to_dict_includes_all_fields():
    """Test that metrics can be converted to dictionary."""
    metrics = performance.AnalysisMetrics()
    metrics.total_lines = 100
    metrics.parsed_lines = 95
    metrics.parsing_time_ms = 10.5
    
    data = metrics.to_dict()
    
    assert "total_lines" in data
    assert "parsed_lines" in data
    assert "parsing_time_ms" in data
    assert "parse_rate_per_sec" in data
    assert "success_rate_pct" in data
    assert data["total_lines"] == 100
    assert data["parsed_lines"] == 95
