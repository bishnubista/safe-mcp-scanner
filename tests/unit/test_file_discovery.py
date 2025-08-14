"""Unit tests for file discovery functionality."""

import pytest
from pathlib import Path

from safe_mcp_scanner.file_discovery import FileDiscovery
from safe_mcp_scanner.config import Config


class TestFileDiscovery:
    """Test file discovery and filtering."""
    
    def test_discover_single_file(self, default_config, vulnerable_python_file):
        """Test discovering a single file."""
        discovery = FileDiscovery(default_config)
        files = discovery.discover_files(vulnerable_python_file)
        
        assert len(files) == 1
        assert files[0] == vulnerable_python_file
    
    def test_discover_directory(self, default_config, temp_dir):
        """Test discovering files in a directory."""
        # Create test files
        (temp_dir / "test.py").write_text("print('hello')")
        (temp_dir / "config.json").write_text('{"test": true}')
        (temp_dir / "readme.txt").write_text("readme")
        
        discovery = FileDiscovery(default_config)
        files = discovery.discover_files(temp_dir)
        
        # Should find Python and JSON files, but not txt
        python_files = [f for f in files if f.suffix == ".py"]
        json_files = [f for f in files if f.suffix == ".json"]
        txt_files = [f for f in files if f.suffix == ".txt"]
        
        assert len(python_files) > 0
        assert len(json_files) > 0
        assert len(txt_files) == 0  # Not in default include patterns
    
    def test_exclude_patterns(self, default_config, temp_dir):
        """Test file exclusion patterns."""
        # Create files that should be excluded
        git_dir = temp_dir / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("git config")
        
        node_modules = temp_dir / "node_modules" / "package"
        node_modules.mkdir(parents=True)
        (node_modules / "index.js").write_text("module.exports = {};")
        
        # Create file that should be included
        (temp_dir / "main.py").write_text("print('hello')")
        
        discovery = FileDiscovery(default_config)
        files = discovery.discover_files(temp_dir)
        
        # Should only find main.py
        assert len(files) == 1
        assert files[0].name == "main.py"
    
    def test_mcp_related_files(self, default_config, temp_dir):
        """Test detection of MCP-related files."""
        discovery = FileDiscovery(default_config)
        
        # Create MCP config files
        mcp_config = temp_dir / "claude_desktop_config.json"
        mcp_config.write_text('{"tools": []}')
        
        # Create MCP server file
        mcp_server = temp_dir / "mcp_server.py"
        mcp_server.write_text("# MCP server implementation")
        
        assert discovery._is_mcp_related_file(mcp_config) is True
        assert discovery._is_mcp_related_file(mcp_server) is True
    
    def test_file_categorization(self, default_config, temp_dir):
        """Test file categorization."""
        discovery = FileDiscovery(default_config)
        
        # Create different types of files
        files = {
            "claude_desktop_config.json": "mcp-config",
            "mcp_server.py": "mcp-server", 
            "Dockerfile": "container",
            "main.py": "source",
            "config.yaml": "config",
            "README.md": "other"
        }
        
        for filename, expected_category in files.items():
            file_path = temp_dir / filename
            file_path.write_text("test content")
            
            category = discovery.get_file_category(file_path)
            assert category == expected_category, f"Expected {expected_category} for {filename}, got {category}"
    
    def test_file_size_limits(self, temp_dir):
        """Test file size filtering."""
        config = Config()
        config.scan.max_file_size = 100  # Very small limit
        
        discovery = FileDiscovery(config)
        
        # Create a large file
        large_file = temp_dir / "large.py"
        large_file.write_text("x" * 200)  # Larger than limit
        
        # Create a small file  
        small_file = temp_dir / "small.py"
        small_file.write_text("print('hello')")
        
        files = discovery.discover_files(temp_dir)
        
        # Should only find the small file
        assert len(files) == 1
        assert files[0] == small_file
    
    def test_scan_statistics(self, default_config, temp_dir):
        """Test scan statistics generation."""
        discovery = FileDiscovery(default_config)
        
        # Create test files
        (temp_dir / "server.py").write_text("# MCP server")
        (temp_dir / "config.json").write_text("{}")
        
        files = discovery.discover_files(temp_dir)
        stats = discovery.get_scan_statistics(files)
        
        assert stats["total_files"] == len(files)
        assert stats["total_size_bytes"] > 0
        assert "categories" in stats
        assert stats["average_file_size"] > 0