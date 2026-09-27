# Quick Start Guide - New Features

## 🚀 Using CyberTriage v2.0 Enhanced Features

This guide shows you how to use the new features added to CyberTriage.

---

## **1. Performance Monitoring** ⚡

### Basic Usage

```python
from cybertriage import parser, detector, performance

# Create performance monitor
monitor = performance.PerformanceMonitor()

with monitor:
    # Track parsing
    monitor.start_section("parsing")
    df = parser.parse_log_text(log_text)
    monitor.end_section("parsing")
    
    # Track detection
    monitor.start_section("detection")
    detection = detector.detect(df)
    monitor.end_section("detection")
    
    # Set input stats
    monitor.set_input_stats(
        total_lines=100,
        parsed_lines=95,
        unique_ips=5
    )

# Get metrics
metrics = monitor.get_metrics()
print(f"Total time: {metrics.total_time_ms:.2f}ms")
print(f"Parse rate: {metrics.parse_rate:.2f} lines/sec")
print(f"Success rate: {metrics.success_rate:.1f}%")
```

### Session History

```python
from cybertriage import performance

# Track multiple analyses
history = performance.AnalysisHistory()

for log_file in log_files:
    monitor = performance.PerformanceMonitor()
    with monitor:
        # ... process log ...
        pass
    history.add(monitor.get_metrics())

# Get summary
summary = history.get_summary()
print(f"Total runs: {summary['total_runs']}")
print(f"Avg time: {summary['avg_total_time_ms']:.2f}ms")
```

---

## **2. Enhanced Export Formats** 📤

### JSON Export

```python
from cybertriage import export, parser, detector, report

# Analyze logs
df = parser.parse_log_text(log_text)
detection = detector.detect(df)
report_obj = report.build_report(df, detection)

# Export as JSON
json_data = export.export_to_json(report_obj, detection, df)

# Save to file
with open("analysis_results.json", "w") as f:
    f.write(json_data)
```

### MITRE ATT&CK Mapping

```python
from cybertriage import export

# Map to MITRE framework
mitre_mapping = export.map_to_mitre_attack(report_obj)

print("Tactics:", mitre_mapping['tactics'])
print("Techniques:")
for technique in mitre_mapping['techniques']:
    print(f"  - {technique['id']}: {technique['name']}")
    if 'sub_techniques' in technique:
        for sub in technique['sub_techniques']:
            print(f"    - {sub['id']}: {sub['name']} (confidence: {sub['confidence']})")
```

### STIX 2.1 Bundle

```python
# Export as STIX for threat intelligence sharing
stix_bundle = export.export_stix_bundle(report_obj, detection)

# Save for TIP integration
with open("threat_intel.json", "w") as f:
    f.write(stix_bundle)
```

### CEF for SIEM

```python
# Export in Common Event Format
cef_line = export.export_siem_format(report_obj, detection, df)

# Send to SIEM or save to log
print(cef_line)
# Output: CEF:0|CyberTriage|SSH Log Analyzer|2.0|100|Possible SSH Brute Force Attempt|10|src=192.168.1.45 ...
```

### CSV Summary

```python
# Export IP summaries as CSV
csv_data = export.export_csv_summary(detection)

# Save for spreadsheet analysis
with open("ip_summary.csv", "w") as f:
    f.write(csv_data)
```

---

## **3. Configuration Management** ⚙️

### Using Default Configuration

```python
from cybertriage import config

# Get global config
cfg = config.get_config()

# Access settings
print(f"Low threshold: {cfg.detection.low_threshold}")
print(f"Medium threshold: {cfg.detection.medium_threshold}")
print(f"High threshold: {cfg.detection.high_threshold}")
```

### Custom Configuration

```python
from cybertriage import config

# Create custom config
custom_cfg = config.CyberTriageConfig()

# Modify detection thresholds
custom_cfg.detection.low_threshold = 5
custom_cfg.detection.medium_threshold = 10
custom_cfg.detection.high_threshold = 20

# Modify anomaly settings
custom_cfg.anomaly.contamination = 0.15
custom_cfg.anomaly.n_estimators = 300

# Validate and set
custom_cfg.validate()
config.set_config(custom_cfg)
```

### Environment Variables

```bash
# Set via environment variables
export CYBERTRIAGE_LOW_THRESHOLD=5
export CYBERTRIAGE_MEDIUM_THRESHOLD=10
export CYBERTRIAGE_HIGH_THRESHOLD=15
export OLLAMA_MODEL=llama3.1
export CYBERTRIAGE_ENABLE_LLM=true
```

```python
# Load from environment
cfg = config.CyberTriageConfig.from_env()
```

### Configuration Sections

```python
# Detection configuration
cfg.detection.low_threshold = 3
cfg.detection.medium_threshold = 5
cfg.detection.high_threshold = 10
cfg.detection.enable_severity_escalation = True

# Anomaly detection configuration
cfg.anomaly.contamination = 0.1
cfg.anomaly.random_state = 3070
cfg.anomaly.n_estimators = 200
cfg.anomaly.min_training_rows = 20

# LLM configuration
cfg.llm.enabled = True
cfg.llm.host = "http://localhost:11434"
cfg.llm.model = "llama3"
cfg.llm.timeout_seconds = 30
cfg.llm.validate_output = True

# UI configuration
cfg.ui.show_performance_metrics = True
cfg.ui.max_log_display_lines = 1000

# Export configuration
cfg.export.enable_json = True
cfg.export.enable_mitre_mapping = True
cfg.export.enable_stix = True
cfg.export.enable_cef = True
```

---

## **4. Batch Processing** 📊

### Process Directory

```python
from cybertriage import batch

# Initialize processor
processor = batch.BatchProcessor()

# Process all .log files in directory
results = processor.process_directory(
    directory="/var/log/auth/",
    pattern="*.log"
)

# Check results
for result in results:
    if result.success:
        print(f"✅ {result.filename}: {result.incident_type} ({result.severity})")
    else:
        print(f"❌ {result.filename}: {result.error_message}")
```

### Process Specific Files

```python
# Process list of files
file_paths = [
    "server1_auth.log",
    "server2_auth.log",
    "server3_auth.log"
]

results = processor.process_files(file_paths)
```

### Get Summary Statistics

```python
# Get batch summary
summary = processor.get_summary()

print(f"Total files: {summary['total_files']}")
print(f"Successful: {summary['successful']}")
print(f"Failed: {summary['failed']}")
print(f"Total incidents: {summary['total_incidents']}")
print(f"High severity: {summary['severity_breakdown']['high']}")
print(f"Medium severity: {summary['severity_breakdown']['medium']}")
print(f"Low severity: {summary['severity_breakdown']['low']}")
print(f"Avg processing time: {summary['avg_processing_time_ms']:.2f}ms")
```

### Export Batch Results

```python
# Export as CSV
csv_output = processor.export_results_csv()
with open("batch_results.csv", "w") as f:
    f.write(csv_output)

# Export as JSON
json_output = processor.export_results_json()
with open("batch_results.json", "w") as f:
    f.write(json_output)
```

### Compare Multiple Logs

```python
# Side-by-side comparison
comparison_df = batch.compare_logs([
    "monday.log",
    "tuesday.log",
    "wednesday.log"
])

print(comparison_df)
# Output: DataFrame with columns: Filename, Status, Lines, Parsed, Incident, Severity, etc.
```

### With Pre-trained Model

```python
from cybertriage import anomaly, batch

# Load or train model
model = anomaly.IsolationForestBaseline(contamination=0.1, random_state=3070)
# ... train model ...

# Use model in batch processing
processor = batch.BatchProcessor(model=model)
results = processor.process_directory("/logs/")
```

---

## **5. Complete Example** 🎯

### Full Analysis with All Features

```python
from cybertriage import (
    parser, detector, classifier, report, anomaly,
    performance, export, config, batch
)

# 1. Configure system
cfg = config.CyberTriageConfig.from_env()
cfg.detection.low_threshold = 5
config.set_config(cfg)

# 2. Monitor performance
monitor = performance.PerformanceMonitor()
history = performance.AnalysisHistory()

with monitor:
    # 3. Parse logs
    monitor.start_section("parsing")
    df = parser.parse_log_text(log_text)
    monitor.end_section("parsing")
    
    # 4. Detect threats
    monitor.start_section("detection")
    detection = detector.detect(df)
    monitor.end_section("detection")
    
    # 5. Classify incident
    incident_type = classifier.classify(df, detection)
    
    # 6. Generate report
    report_obj = report.build_report(df, detection)
    
    # 7. Set metrics
    monitor.set_input_stats(
        total_lines=len(log_text.splitlines()),
        parsed_lines=len(df),
        unique_ips=df['source_ip'].nunique() if not df.empty else 0
    )

# 8. Get performance metrics
metrics = monitor.get_metrics()
history.add(metrics)

# 9. Export in multiple formats
json_data = export.export_to_json(report_obj, detection, df)
mitre_mapping = export.map_to_mitre_attack(report_obj)
stix_bundle = export.export_stix_bundle(report_obj, detection)
cef_line = export.export_siem_format(report_obj, detection, df)

# 10. Save results
with open("results.json", "w") as f:
    f.write(json_data)

print(f"Analysis completed in {metrics.total_time_ms:.2f}ms")
print(f"Incident: {incident_type} ({report_obj['severity']})")
print(f"MITRE Tactics: {mitre_mapping['tactics']}")
```

---

## **6. Testing New Features** ✅

### Run New Tests

```bash
# Test performance monitoring
pytest tests/test_performance.py -v

# Test export functionality
pytest tests/test_export.py -v

# Test configuration
pytest tests/test_config.py -v

# Run all tests
pytest -v
```

### Expected Output

```
tests/test_performance.py::test_performance_monitor_tracks_sections PASSED
tests/test_performance.py::test_performance_monitor_calculates_parse_rate PASSED
tests/test_performance.py::test_analysis_history_maintains_summary PASSED
tests/test_performance.py::test_analysis_history_respects_max_size PASSED
tests/test_performance.py::test_metrics_to_dict_includes_all_fields PASSED

tests/test_export.py::test_export_to_json_produces_valid_json PASSED
tests/test_export.py::test_mitre_attack_mapping_for_brute_force PASSED
tests/test_export.py::test_mitre_attack_mapping_for_normal PASSED
tests/test_export.py::test_export_stix_bundle_produces_valid_json PASSED
tests/test_export.py::test_export_csv_summary PASSED
tests/test_export.py::test_export_siem_format PASSED

tests/test_config.py::test_default_config_is_valid PASSED
tests/test_config.py::test_detection_config_validation PASSED
tests/test_config.py::test_anomaly_config_validation PASSED
tests/test_config.py::test_llm_config_validation PASSED
tests/test_config.py::test_config_from_env PASSED
tests/test_config.py::test_config_to_dict PASSED
tests/test_config.py::test_global_config_management PASSED
tests/test_config.py::test_ui_config_validation PASSED
tests/test_config.py::test_export_config_validation PASSED

======================== 83 passed in 1.72s =========================
```

---

## **7. Integration with Streamlit App** 🖥️

The new features can be easily integrated into the Streamlit dashboard:

```python
import streamlit as st
from cybertriage import performance, export, config

# Show performance metrics
if config.get_config().ui.show_performance_metrics:
    with st.expander("⚡ Performance Metrics"):
        st.json(metrics.to_dict())

# Enhanced export options
st.markdown("### 📥 Export Options")
col1, col2, col3, col4 = st.columns(4)

with col1:
    json_data = export.export_to_json(report_obj, detection, df)
    st.download_button("📄 JSON", json_data, "analysis.json")

with col2:
    mitre_data = json.dumps(export.map_to_mitre_attack(report_obj), indent=2)
    st.download_button("🎯 MITRE", mitre_data, "mitre_mapping.json")

with col3:
    stix_data = export.export_stix_bundle(report_obj, detection)
    st.download_button("🔒 STIX", stix_data, "threat_intel.json")

with col4:
    cef_data = export.export_siem_format(report_obj, detection, df)
    st.download_button("📊 CEF", cef_data, "siem_event.cef")
```

---

## **Need Help?** 💡

- **Documentation**: See `ENHANCEMENTS.md` for detailed information
- **Tests**: Check `tests/test_*.py` for usage examples
- **Source Code**: All modules have comprehensive docstrings

---

**CyberTriage v2.0** - Enhanced for Excellence 🛡️
