"""Base class for detection engines."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Any, Dict

from ..techniques.base import Finding
from ..config import Config


class BaseDetector(ABC):
    """Abstract base class for detection engines."""
    
    def __init__(self, config: Config) -> None:
        self.config = config
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable detector name."""
        pass
    
    @property
    @abstractmethod
    def supported_file_types(self) -> List[str]:
        """File extensions this detector can handle."""
        pass
    
    @abstractmethod
    def can_analyze_file(self, file_path: Path) -> bool:
        """Check if this detector can analyze the given file."""
        pass
    
    @abstractmethod
    def analyze_file(self, file_path: Path, patterns: List[Dict[str, Any]]) -> List[Finding]:
        """Analyze a file using the provided patterns.
        
        Args:
            file_path: Path to the file to analyze
            patterns: Detection patterns to apply
            
        Returns:
            List of security findings
        """
        pass
    
    def read_file_safely(self, file_path: Path) -> str:
        """Safely read a file with size limits and encoding detection."""
        try:
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.config.scan.max_file_size:
                raise ValueError(f"File too large: {file_size} bytes")
            
            # Try to read with UTF-8 first, fall back to other encodings
            encodings = ["utf-8", "utf-8-sig", "latin-1", "cp1252"]
            
            for encoding in encodings:
                try:
                    return file_path.read_text(encoding=encoding)
                except UnicodeDecodeError:
                    continue
            
            raise ValueError("Could not decode file with any supported encoding")
            
        except Exception as e:
            raise ValueError(f"Error reading file {file_path}: {e}")
    
    def extract_source_context(
        self, 
        content: str, 
        line_number: int, 
        context_lines: int = 5
    ) -> str:
        """Extract source code context around a specific line."""
        lines = content.splitlines()
        
        start_line = max(0, line_number - context_lines - 1)
        end_line = min(len(lines), line_number + context_lines)
        
        context_lines_list = []
        for i in range(start_line, end_line):
            marker = ">>> " if i == line_number - 1 else "    "
            context_lines_list.append(f"{marker}{i + 1:4d}: {lines[i]}")
        
        return "\n".join(context_lines_list)