"""Integration tests for the CLI interface."""

import json
from pathlib import Path
import pytest
from click.testing import CliRunner

from safe_mcp_scanner.cli import cli


class TestCLI:
    """Test CLI functionality."""
    
    def test_cli_help(self):
        """Test CLI help output."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        
        assert result.exit_code == 0
        assert "SAFE-MCP Scanner" in result.output
        assert "vulnerability scanner" in result.output.lower()
    
    def test_scan_command_help(self):
        """Test scan command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        
        assert result.exit_code == 0
        assert "PATH" in result.output
        assert "format" in result.output.lower()
    
    def test_scan_file(self, vulnerable_python_file):
        """Test scanning a single file."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(vulnerable_python_file)])
        
        assert result.exit_code == 0
        
        # Should output JSON by default
        try:
            output_data = json.loads(result.output)
            assert "scan_info" in output_data
            assert "findings" in output_data
        except json.JSONDecodeError:
            pytest.fail("CLI output is not valid JSON")
    
    def test_scan_with_format_option(self, vulnerable_python_file):
        """Test scanning with different output formats."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(vulnerable_python_file), "--format", "json"])
        
        assert result.exit_code == 0
        assert "findings" in result.output
    
    def test_scan_with_output_file(self, vulnerable_python_file, temp_dir):
        """Test scanning with output to file."""
        output_file = temp_dir / "results.json"
        
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", 
            str(vulnerable_python_file), 
            "--output", 
            str(output_file)
        ])
        
        assert result.exit_code == 0
        assert output_file.exists()
        
        # Check output file content
        output_content = output_file.read_text()
        output_data = json.loads(output_content)
        assert "scan_info" in output_data
    
    def test_info_command(self):
        """Test info command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["info", "--list-techniques"])
        
        assert result.exit_code == 0
        assert "SAFE-T1001" in result.output
        assert "SAFE-T1101" in result.output
    
    def test_init_config_command(self, temp_dir):
        """Test configuration file creation."""
        config_file = temp_dir / "test-config.yaml"
        
        runner = CliRunner()
        result = runner.invoke(cli, ["init-config", str(config_file)])
        
        assert result.exit_code == 0
        assert config_file.exists()
        
        # Should be valid YAML
        import yaml
        config_data = yaml.safe_load(config_file.read_text())
        assert "scan" in config_data
        assert "output" in config_data