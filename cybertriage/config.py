"""Configuration management for CyberTriage.

Centralized configuration with validation and environment variable support.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class DetectionConfig:
    """Configuration for detection thresholds and rules."""
    
    low_threshold: int = 3
    medium_threshold: int = 5
    high_threshold: int = 10
    enable_severity_escalation: bool = True
    min_usernames_for_escalation: int = 2
    
    def validate(self) -> None:
        """Validate configuration values."""
        if not (0 < self.low_threshold <= self.medium_threshold <= self.high_threshold):
            raise ValueError("Thresholds must be: 0 < low <= medium <= high")
        if self.min_usernames_for_escalation < 1:
            raise ValueError("min_usernames_for_escalation must be >= 1")


@dataclass
class AnomalyConfig:
    """Configuration for anomaly detection model."""
    
    contamination: float = 0.1
    random_state: int = 3070
    n_estimators: int = 200
    min_training_rows: int = 20
    
    def validate(self) -> None:
        """Validate configuration values."""
        if not (0.0 < self.contamination < 0.5):
            raise ValueError("contamination must be between 0.0 and 0.5")
        if self.n_estimators < 10:
            raise ValueError("n_estimators must be >= 10")
        if self.min_training_rows < 10:
            raise ValueError("min_training_rows must be >= 10")


@dataclass
class LLMConfig:
    """Configuration for LLM integration."""
    
    enabled: bool = False
    host: str = "http://localhost:11434"
    model: str = "llama3"
    timeout_seconds: int = 30
    max_retries: int = 2
    validate_output: bool = True
    
    def validate(self) -> None:
        """Validate configuration values."""
        if self.timeout_seconds < 1:
            raise ValueError("timeout_seconds must be >= 1")
        if self.max_retries < 0:
            raise ValueError("max_retries must be >= 0")


@dataclass
class UIConfig:
    """Configuration for user interface."""
    
    page_title: str = "CyberTriage - AI Security Analytics"
    page_icon: str = "🛡️"
    layout: str = "wide"
    theme_primary_color: str = "#667eea"
    show_performance_metrics: bool = True
    max_log_display_lines: int = 1000
    
    def validate(self) -> None:
        """Validate configuration values."""
        if self.layout not in ["centered", "wide"]:
            raise ValueError("layout must be 'centered' or 'wide'")
        if self.max_log_display_lines < 10:
            raise ValueError("max_log_display_lines must be >= 10")


@dataclass
class ExportConfig:
    """Configuration for export functionality."""
    
    enable_json: bool = True
    enable_csv: bool = True
    enable_pdf: bool = True
    enable_mitre_mapping: bool = True
    enable_stix: bool = True
    enable_cef: bool = True
    include_raw_logs_in_json: bool = True
    max_raw_logs_in_export: int = 100
    
    def validate(self) -> None:
        """Validate configuration values."""
        if self.max_raw_logs_in_export < 0:
            raise ValueError("max_raw_logs_in_export must be >= 0")


@dataclass
class CyberTriageConfig:
    """Main configuration container for CyberTriage."""
    
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    anomaly: AnomalyConfig = field(default_factory=AnomalyConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    ui: UIConfig = field(default_factory=UIConfig)
    export: ExportConfig = field(default_factory=ExportConfig)
    
    def validate(self) -> None:
        """Validate all configuration sections."""
        self.detection.validate()
        self.anomaly.validate()
        self.llm.validate()
        self.ui.validate()
        self.export.validate()
    
    @classmethod
    def from_env(cls) -> "CyberTriageConfig":
        """Create configuration from environment variables.
        
        Supported environment variables:
            - CYBERTRIAGE_LOW_THRESHOLD
            - CYBERTRIAGE_MEDIUM_THRESHOLD
            - CYBERTRIAGE_HIGH_THRESHOLD
            - OLLAMA_HOST
            - OLLAMA_MODEL
            - CYBERTRIAGE_ENABLE_LLM
            - CYBERTRIAGE_SHOW_METRICS
        """
        config = cls()
        
        # Detection config
        if val := os.getenv("CYBERTRIAGE_LOW_THRESHOLD"):
            config.detection.low_threshold = int(val)
        if val := os.getenv("CYBERTRIAGE_MEDIUM_THRESHOLD"):
            config.detection.medium_threshold = int(val)
        if val := os.getenv("CYBERTRIAGE_HIGH_THRESHOLD"):
            config.detection.high_threshold = int(val)
        
        # Anomaly config
        if val := os.getenv("CYBERTRIAGE_CONTAMINATION"):
            config.anomaly.contamination = float(val)
        if val := os.getenv("CYBERTRIAGE_RANDOM_STATE"):
            config.anomaly.random_state = int(val)
        
        # LLM config
        if val := os.getenv("OLLAMA_HOST"):
            config.llm.host = val
        if val := os.getenv("OLLAMA_MODEL"):
            config.llm.model = val
        if val := os.getenv("CYBERTRIAGE_ENABLE_LLM"):
            config.llm.enabled = val.lower() in ("true", "1", "yes")
        
        # UI config
        if val := os.getenv("CYBERTRIAGE_SHOW_METRICS"):
            config.ui.show_performance_metrics = val.lower() in ("true", "1", "yes")
        
        config.validate()
        return config
    
    def to_dict(self) -> Dict[str, object]:
        """Convert configuration to dictionary."""
        return {
            "detection": {
                "low_threshold": self.detection.low_threshold,
                "medium_threshold": self.detection.medium_threshold,
                "high_threshold": self.detection.high_threshold,
                "enable_severity_escalation": self.detection.enable_severity_escalation,
            },
            "anomaly": {
                "contamination": self.anomaly.contamination,
                "random_state": self.anomaly.random_state,
                "n_estimators": self.anomaly.n_estimators,
                "min_training_rows": self.anomaly.min_training_rows,
            },
            "llm": {
                "enabled": self.llm.enabled,
                "host": self.llm.host,
                "model": self.llm.model,
                "validate_output": self.llm.validate_output,
            },
            "ui": {
                "show_performance_metrics": self.ui.show_performance_metrics,
                "max_log_display_lines": self.ui.max_log_display_lines,
            },
            "export": {
                "enable_json": self.export.enable_json,
                "enable_csv": self.export.enable_csv,
                "enable_pdf": self.export.enable_pdf,
                "enable_mitre_mapping": self.export.enable_mitre_mapping,
            }
        }


# Global configuration instance
_config: Optional[CyberTriageConfig] = None


def get_config() -> CyberTriageConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = CyberTriageConfig.from_env()
    return _config


def set_config(config: CyberTriageConfig) -> None:
    """Set the global configuration instance."""
    global _config
    config.validate()
    _config = config


def reset_config() -> None:
    """Reset configuration to defaults."""
    global _config
    _config = None
