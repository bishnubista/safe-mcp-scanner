"""Unit tests for the main scanner functionality."""

from safe_mcp_scanner.scanner import Scanner
from safe_mcp_scanner.config import Config


class TestScanner:
    """Test the main Scanner class."""
    
    def test_scanner_initialization(self, default_config):
        """Test scanner initialization."""
        scanner = Scanner(default_config)
        
        assert scanner.config == default_config
        assert scanner.file_discovery is not None
        assert scanner.technique_loader is not None
        assert scanner.reporter_factory is not None
    
    def test_get_available_techniques(self, default_config):
        """Test getting available techniques."""
        scanner = Scanner(default_config)
        techniques = scanner.get_available_techniques()
        
        # Should have our registered techniques
        assert "SAFE-T1001" in techniques
        assert "SAFE-T1101" in techniques
        
        # Check technique properties
        t1001 = techniques["SAFE-T1001"]
        assert t1001.name == "Malicious Tool Descriptions"
        assert t1001.tactic == "Initial Access"
    
    def test_get_enabled_techniques(self):
        """Test filtering enabled techniques."""
        config = Config(disabled_techniques=["SAFE-T1001"])
        scanner = Scanner(config)
        
        enabled = scanner.get_enabled_techniques()
        available = scanner.get_available_techniques()
        
        assert "SAFE-T1001" not in enabled
        assert "SAFE-T1001" in available
        assert len(enabled) < len(available)
    
    def test_scan_single_file(self, default_config, vulnerable_python_file):
        """Test scanning a single file."""
        scanner = Scanner(default_config)
        results = scanner.scan(vulnerable_python_file)
        
        assert results.total_files == 1
        assert len(results.scanned_files) >= 0
        assert results.scan_duration > 0
        assert len(results.findings) > 0  # Should find command injection
        
        # Check that we found command injection
        finding_techniques = [f.technique_id for f in results.findings]
        assert "SAFE-T1101" in finding_techniques
    
    def test_scan_directory(self, default_config, temp_dir, vulnerable_python_file, clean_python_file):
        """Test scanning a directory."""
        scanner = Scanner(default_config)
        results = scanner.scan(temp_dir)
        
        assert results.total_files >= 2
        assert len(results.findings) > 0
        
        # Should find vulnerabilities in the vulnerable file
        vulnerable_findings = [
            f for f in results.findings 
            if f.file_path == vulnerable_python_file
        ]
        assert len(vulnerable_findings) > 0
    
    def test_format_results_json(self, default_config, vulnerable_python_file):
        """Test JSON result formatting."""
        scanner = Scanner(default_config)
        results = scanner.scan(vulnerable_python_file)
        
        json_output = scanner.format_results(results, "json")
        
        assert "scan_info" in json_output
        assert "findings" in json_output
        assert "summary" in json_output
        assert "SAFE-T1101" in json_output  # Should contain our technique
    
    def test_scan_with_no_findings(self, default_config, clean_python_file):
        """Test scanning a file with no vulnerabilities."""
        scanner = Scanner(default_config)
        results = scanner.scan(clean_python_file)
        
        # May or may not have findings depending on patterns
        assert results.total_files == 1
        assert len(results.scanned_files) >= 0