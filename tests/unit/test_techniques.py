"""Unit tests for SAFE-MCP techniques."""

import pytest
from pathlib import Path

from safe_mcp_scanner.config import Config
from safe_mcp_scanner.techniques.command_injection import CommandInjectionTechnique
from safe_mcp_scanner.techniques.malicious_tools import MaliciousToolTechnique


class TestCommandInjectionTechnique:
    """Test the command injection technique."""
    
    def test_technique_properties(self, default_config):
        """Test technique metadata."""
        technique = CommandInjectionTechnique(default_config)
        
        assert technique.technique_id == "SAFE-T1101"
        assert technique.name == "Command Injection"
        assert technique.severity == "high"
        assert technique.tactic == "Execution"
        assert technique.mitre_attack_mapping == "T1059"
        assert ".py" in technique.file_types
    
    def test_can_analyze_python_files(self, default_config):
        """Test file type filtering."""
        technique = CommandInjectionTechnique(default_config)
        
        assert technique.can_analyze_file(Path("test.py")) is True
        assert technique.can_analyze_file(Path("test.js")) is True
        assert technique.can_analyze_file(Path("test.txt")) is False
        assert technique.can_analyze_file(Path("test.json")) is False
    
    def test_analyze_vulnerable_file(self, default_config, vulnerable_python_file):
        """Test analyzing a file with command injection."""
        technique = CommandInjectionTechnique(default_config)
        findings = technique.analyze_file(vulnerable_python_file)
        
        assert len(findings) > 0
        
        # Check finding properties
        for finding in findings:
            assert finding.technique_id == "SAFE-T1101"
            assert finding.severity == "high"
            assert finding.file_path == vulnerable_python_file
            assert finding.line_number is not None
            assert "MCP" in finding.recommendation
    
    def test_analyze_clean_file(self, default_config, clean_python_file):
        """Test analyzing a clean file."""
        technique = CommandInjectionTechnique(default_config)
        findings = technique.analyze_file(clean_python_file)
        
        # Should have minimal or no findings
        assert len(findings) == 0


class TestMaliciousToolTechnique:
    """Test the malicious tool description technique."""
    
    def test_technique_properties(self, default_config):
        """Test technique metadata."""
        technique = MaliciousToolTechnique(default_config)
        
        assert technique.technique_id == "SAFE-T1001"
        assert technique.name == "Malicious Tool Descriptions"
        assert technique.severity == "high"
        assert technique.tactic == "Initial Access"
        assert technique.mitre_attack_mapping == "T1566"
        assert ".json" in technique.file_types
    
    def test_can_analyze_config_files(self, default_config):
        """Test file type filtering."""
        technique = MaliciousToolTechnique(default_config)
        
        assert technique.can_analyze_file(Path("config.json")) is True
        assert technique.can_analyze_file(Path("config.yaml")) is True
        assert technique.can_analyze_file(Path("test.py")) is False
    
    def test_analyze_malicious_config(self, default_config, malicious_mcp_config):
        """Test analyzing a malicious MCP config."""
        technique = MaliciousToolTechnique(default_config)
        findings = technique.analyze_file(malicious_mcp_config)
        
        assert len(findings) > 0
        
        # Check finding properties
        for finding in findings:
            assert finding.technique_id == "SAFE-T1001"
            assert finding.severity == "high"
            assert finding.file_path == malicious_mcp_config
            assert "MCP" in finding.recommendation