"""Unit tests for configuration management."""

from pathlib import Path
import pytest
import tempfile

from safe_mcp_scanner.config import Config, load_config, merge_configs


class TestConfig:
    """Test configuration loading and validation."""
    
    def test_default_config_creation(self):
        """Test creating a config with default values."""
        config = Config()
        
        assert config.scan.max_file_size == 10 * 1024 * 1024
        assert config.scan.follow_symlinks is False
        assert "**/*.py" in config.scan.include_patterns
        assert "**/.git/**" in config.scan.exclude_patterns
        assert config.output.format == "json"
    
    def test_technique_enabling_disabling(self):
        """Test technique enable/disable logic."""
        # When enabled_techniques is set, ONLY those are enabled
        config = Config(enabled_techniques=["SAFE-T1001"])
        assert config.is_technique_enabled("SAFE-T1001") is True
        assert config.is_technique_enabled("SAFE-T1101") is False
        assert config.is_technique_enabled("SAFE-T1999") is False
        
        # When only disabled_techniques is set, all others are enabled
        config2 = Config(disabled_techniques=["SAFE-T1101"])
        assert config2.is_technique_enabled("SAFE-T1001") is True
        assert config2.is_technique_enabled("SAFE-T1101") is False
        assert config2.is_technique_enabled("SAFE-T1999") is True
    
    def test_file_filtering(self):
        """Test file filtering based on patterns."""
        config = Config()
        
        # Should scan Python files
        assert config.should_scan_file(Path("test.py")) is True
        assert config.should_scan_file(Path("src/module.py")) is True
        
        # Should skip git files
        assert config.should_scan_file(Path(".git/config")) is False
        assert config.should_scan_file(Path("project/.git/HEAD")) is False
        
        # Should skip node_modules
        assert config.should_scan_file(Path("node_modules/package/index.js")) is False
    
    def test_invalid_technique_id_validation(self):
        """Test validation of technique ID format."""
        with pytest.raises(ValueError, match="Invalid technique ID format"):
            Config(enabled_techniques=["INVALID-ID"])
    
    def test_severity_validation(self):
        """Test severity level validation."""
        with pytest.raises(ValueError):
            Config(fail_on_severity="invalid")


class TestConfigLoading:
    """Test configuration file loading."""
    
    def test_merge_configs(self):
        """Test configuration merging."""
        config1 = {"scan": {"max_file_size": 1000}, "output": {"format": "json"}}
        config2 = {"scan": {"max_file_size": 2000}, "new_option": "value"}
        
        merged = merge_configs(config1, config2)
        
        assert merged["scan"]["max_file_size"] == 2000  # Later config wins
        assert merged["output"]["format"] == "json"    # Preserved from first
        assert merged["new_option"] == "value"         # Added from second
    
    def test_load_config_with_file(self):
        """Test loading configuration from a YAML file."""
        config_content = """
scan:
  max_file_size: 5242880
  follow_symlinks: true
output:
  format: sarif
disabled_techniques:
  - SAFE-T1001
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            config_path = Path(f.name)
        
        try:
            config = load_config(config_path)
            
            assert config.scan.max_file_size == 5242880
            assert config.scan.follow_symlinks is True
            assert config.output.format == "sarif"
            assert "SAFE-T1001" in config.disabled_techniques
        finally:
            config_path.unlink()  # Clean up