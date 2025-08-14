"""File discovery and filtering for MCP server scanning."""

import fnmatch
from pathlib import Path
from typing import List, Set, Iterator

from .config import Config


class FileDiscovery:
    """Handles file discovery and filtering for MCP server scanning."""
    
    # MCP-specific file patterns
    MCP_CONFIG_PATTERNS = [
        "**/claude_desktop_config.json",
        "**/mcp_config.json", 
        "**/mcp-config.json",
        "**/.mcp/**",
        "**/mcp.json",
        "**/claude-desktop.json"
    ]
    
    # Common MCP server file patterns
    MCP_SERVER_PATTERNS = [
        "**/mcp_server.py",
        "**/mcp-server.py", 
        "**/mcp_*.py",
        "**/mcp-*.py",
        "**/*mcp*.py",
        "**/server.py",  # When in MCP-related directories
    ]
    
    # Container and deployment files
    CONTAINER_PATTERNS = [
        "**/Dockerfile*",
        "**/docker-compose*.yml",
        "**/docker-compose*.yaml",
        "**/*.dockerfile",
        "**/k8s/**/*.yaml",
        "**/k8s/**/*.yml",
        "**/kubernetes/**/*.yaml",
        "**/kubernetes/**/*.yml",
    ]
    
    def __init__(self, config: Config) -> None:
        self.config = config
    
    def discover_files(self, root_path: Path) -> List[Path]:
        """Discover all files to be scanned in the given directory tree.
        
        Args:
            root_path: Root directory to start discovery from
            
        Returns:
            List of file paths to scan
        """
        if not root_path.exists():
            raise ValueError(f"Path does not exist: {root_path}")
        
        if root_path.is_file():
            return [root_path] if self._should_scan_file(root_path) else []
        
        discovered_files: List[Path] = []
        processed_paths: Set[Path] = set()
        
        for file_path in self._walk_directory(root_path):
            # Resolve symlinks if following them
            resolved_path = file_path.resolve() if self.config.scan.follow_symlinks else file_path
            
            # Skip if we've already processed this file (handles symlink loops)
            if resolved_path in processed_paths:
                continue
            processed_paths.add(resolved_path)
            
            # Check if file should be scanned
            if self._should_scan_file(file_path):
                discovered_files.append(file_path)
                
                # Check file count limit
                if (self.config.scan.max_files is not None and 
                    len(discovered_files) >= self.config.scan.max_files):
                    break
        
        return discovered_files
    
    def _walk_directory(self, root_path: Path) -> Iterator[Path]:
        """Walk directory tree yielding files, respecting symlink settings."""
        try:
            for path in root_path.rglob("*"):
                # Skip directories
                if path.is_dir():
                    continue
                
                # Handle symlinks
                if path.is_symlink() and not self.config.scan.follow_symlinks:
                    continue
                
                # Check if file is readable and within size limits
                try:
                    stat = path.stat()
                    if stat.st_size > self.config.scan.max_file_size:
                        continue
                except (OSError, PermissionError):
                    continue
                
                yield path
                
        except (PermissionError, OSError):
            # Skip directories we can't read
            pass
    
    def _should_scan_file(self, file_path: Path) -> bool:
        """Determine if a file should be scanned based on patterns and rules."""
        # Use config-based filtering first
        if not self.config.should_scan_file(file_path):
            return False
        
        # Additional MCP-specific logic
        if self._is_mcp_related_file(file_path):
            return True
        
        # Check if file is in MCP-related directory
        if self._is_in_mcp_directory(file_path):
            return True
        
        return True  # Default to scanning if it passed config filters
    
    def _is_mcp_related_file(self, file_path: Path) -> bool:
        """Check if file is directly MCP-related."""
        file_path_str = str(file_path).lower()
        file_name = file_path.name.lower()
        
        # Check for MCP config files
        for pattern in self.MCP_CONFIG_PATTERNS:
            if file_path.match(pattern):
                return True
        
        # Check for MCP server files
        for pattern in self.MCP_SERVER_PATTERNS:
            if file_path.match(pattern):
                return True
        
        # Check for MCP in filename or path
        mcp_keywords = ["mcp", "model-context-protocol", "claude"]
        for keyword in mcp_keywords:
            if keyword in file_path_str:
                return True
        
        return False
    
    def _is_in_mcp_directory(self, file_path: Path) -> bool:
        """Check if file is in an MCP-related directory."""
        path_parts = [part.lower() for part in file_path.parts]
        
        mcp_dir_keywords = [
            "mcp", "model-context-protocol", "claude", "claude-desktop",
            "mcp-server", "mcp_server", "anthropic"
        ]
        
        for keyword in mcp_dir_keywords:
            if any(keyword in part for part in path_parts):
                return True
        
        return False
    
    def get_file_category(self, file_path: Path) -> str:
        """Categorize a file based on its type and location.
        
        Returns:
            Category string: 'mcp-config', 'mcp-server', 'container', 'source', 'other'
        """
        file_path_str = str(file_path)
        
        # Check MCP config files
        for pattern in self.MCP_CONFIG_PATTERNS:
            if file_path.match(pattern):
                return "mcp-config"
        
        # Check MCP server files
        for pattern in self.MCP_SERVER_PATTERNS:
            if file_path.match(pattern):
                return "mcp-server"
        
        # Check container files
        for pattern in self.CONTAINER_PATTERNS:
            if file_path.match(pattern):
                return "container"
        
        # Check source code files
        source_extensions = {".py", ".js", ".ts", ".jsx", ".tsx"}
        if file_path.suffix.lower() in source_extensions:
            return "source"
        
        # Check config files
        config_extensions = {".json", ".yaml", ".yml", ".toml", ".ini"}
        if file_path.suffix.lower() in config_extensions:
            return "config"
        
        return "other"
    
    def get_scan_statistics(self, files: List[Path]) -> dict:
        """Get statistics about the files discovered for scanning."""
        categories = {}
        total_size = 0
        
        for file_path in files:
            category = self.get_file_category(file_path)
            categories[category] = categories.get(category, 0) + 1
            
            try:
                total_size += file_path.stat().st_size
            except (OSError, PermissionError):
                pass
        
        return {
            "total_files": len(files),
            "total_size_bytes": total_size,
            "categories": categories,
            "average_file_size": total_size // len(files) if files else 0
        }