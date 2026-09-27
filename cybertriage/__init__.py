"""CyberTriage Prototype package.

AI-Assisted Cybersecurity Log Triage and Incident Explanation System.

This is a defensive cybersecurity education prototype only. It parses, analyses
and explains synthetic SSH authentication logs. It contains no offensive
capabilities.

New in v2.0:
    - Performance monitoring and analytics
    - Enhanced export formats (JSON, MITRE ATT&CK, STIX, CEF)
    - Configuration management system
    - Batch processing for multiple log files
"""

from . import (
    anomaly, 
    parser, 
    detector, 
    classifier, 
    report, 
    sample_data, 
    synthetic_dataset,
    advanced_viz,
    pdf_generator,
    performance,
    export,
    config,
    batch
)

__all__ = [
    "anomaly", 
    "parser", 
    "detector", 
    "classifier", 
    "report", 
    "sample_data", 
    "synthetic_dataset",
    "advanced_viz",
    "pdf_generator",
    "performance",
    "export",
    "config",
    "batch"
]
__version__ = "2.0.0"
