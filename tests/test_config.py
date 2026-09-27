"""Tests for configuration management module."""

import os
import pytest
from cybertriage import config


def test_default_config_is_valid():
    """Test that default configuration is valid."""
    cfg = config.CyberTriageConfig()
    cfg.validate()  # Should not raise


def test_detection_config_validation():
    """Test detection configuration validation."""
    cfg = config.DetectionConfig()
    cfg.low_threshold = 3
    cfg.medium_threshold = 5
    cfg.high_threshold = 10
    cfg.validate()  # Should not raise
    
    # Invalid thresholds
    cfg.low_threshold = 10
    cfg.medium_threshold = 5
    cfg.high_threshold = 3
    with pytest.raises(ValueError):
        cfg.validate()


def test_anomaly_config_validation():
    """Test anomaly configuration validation."""
    cfg = config.AnomalyConfig()
    cfg.contamination = 0.1
    cfg.validate()  # Should not raise
    
    # Invalid contamination
    cfg.contamination = 0.6
    with pytest.raises(ValueError):
        cfg.validate()


def test_llm_config_validation():
    """Test LLM configuration validation."""
    cfg = config.LLMConfig()
    cfg.timeout_seconds = 30
    cfg.validate()  # Should not raise
    
    # Invalid timeout
    cfg.timeout_seconds = 0
    with pytest.raises(ValueError):
        cfg.validate()


def test_config_from_env(monkeypatch):
    """Test configuration loading from environment variables."""
    monkeypatch.setenv("CYBERTRIAGE_LOW_THRESHOLD", "5")
    monkeypatch.setenv("CYBERTRIAGE_MEDIUM_THRESHOLD", "10")
    monkeypatch.setenv("CYBERTRIAGE_HIGH_THRESHOLD", "15")
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.1")
    monkeypatch.setenv("CYBERTRIAGE_ENABLE_LLM", "true")
    
    cfg = config.CyberTriageConfig.from_env()
    
    assert cfg.detection.low_threshold == 5
    assert cfg.detection.medium_threshold == 10
    assert cfg.detection.high_threshold == 15
    assert cfg.llm.model == "llama3.1"
    assert cfg.llm.enabled is True


def test_config_to_dict():
    """Test configuration serialization to dictionary."""
    cfg = config.CyberTriageConfig()
    data = cfg.to_dict()
    
    assert "detection" in data
    assert "anomaly" in data
    assert "llm" in data
    assert "ui" in data
    assert "export" in data


def test_global_config_management():
    """Test global configuration instance management."""
    config.reset_config()
    
    cfg1 = config.get_config()
    cfg2 = config.get_config()
    
    # Should return same instance
    assert cfg1 is cfg2
    
    # Set new config
    new_cfg = config.CyberTriageConfig()
    new_cfg.detection.low_threshold = 5
    config.set_config(new_cfg)
    
    cfg3 = config.get_config()
    assert cfg3.detection.low_threshold == 5


def test_ui_config_validation():
    """Test UI configuration validation."""
    cfg = config.UIConfig()
    cfg.layout = "wide"
    cfg.validate()  # Should not raise
    
    # Invalid layout
    cfg.layout = "invalid"
    with pytest.raises(ValueError):
        cfg.validate()


def test_export_config_validation():
    """Test export configuration validation."""
    cfg = config.ExportConfig()
    cfg.max_raw_logs_in_export = 100
    cfg.validate()  # Should not raise
    
    # Invalid max
    cfg.max_raw_logs_in_export = -1
    with pytest.raises(ValueError):
        cfg.validate()
