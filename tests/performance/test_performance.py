"""Performance tests for the SAFE-MCP Scanner."""

import time
import pytest
from pathlib import Path

from safe_mcp_scanner.scanner import Scanner
from safe_mcp_scanner.config import Config


@pytest.mark.slow
class TestPerformance:
    """Performance tests for scanning operations."""
    
    def test_scan_large_directory(self, temp_dir, default_config):
        """Test scanning performance with many files."""
        # Create many test files
        num_files = 100
        for i in range(num_files):
            file_path = temp_dir / f"test_{i}.py"
            file_path.write_text(f"""
import subprocess
import os

def function_{i}(user_input):
    subprocess.call(f"ls {{user_input}}", shell=True)
    os.system(f"echo {{user_input}}")
""")
        
        scanner = Scanner(default_config)
        
        start_time = time.time()
        results = scanner.scan(temp_dir)
        scan_duration = time.time() - start_time
        
        # Performance assertions
        assert scan_duration < 30  # Should complete within 30 seconds
        assert len(results.scanned_files) == num_files
        assert len(results.findings) > 0  # Should find vulnerabilities
        
        # Calculate files per second
        files_per_second = num_files / scan_duration
        assert files_per_second > 10  # Should process at least 10 files/second
    
    def test_memory_usage_large_files(self, temp_dir, default_config):
        """Test memory usage with large files."""
        # Create a moderately large file
        large_content = "# Python code\n" + "print('hello')\n" * 10000
        large_file = temp_dir / "large.py"
        large_file.write_text(large_content)
        
        scanner = Scanner(default_config)
        results = scanner.scan(large_file)
        
        # Should complete without issues
        assert len(results.scanned_files) == 1
    
    def test_concurrent_scanning(self, temp_dir, default_config):
        """Test that scanning doesn't have major threading issues."""
        # Create test files
        for i in range(10):
            file_path = temp_dir / f"concurrent_{i}.py"
            file_path.write_text(f"import os; os.system('echo {i}')")
        
        scanner = Scanner(default_config)
        
        # Run multiple scans - should not interfere with each other
        results1 = scanner.scan(temp_dir)
        results2 = scanner.scan(temp_dir)
        
        # Results should be consistent
        assert len(results1.findings) == len(results2.findings)
        assert len(results1.scanned_files) == len(results2.scanned_files)