"""Factory for creating result reporters."""

from typing import Dict, Type

from .reporters.base import BaseReporter
from .reporters.json_reporter import JSONReporter


class ReporterFactory:
    """Factory for creating result reporters based on format."""
    
    def __init__(self) -> None:
        self._reporters: Dict[str, Type[BaseReporter]] = {
            "json": JSONReporter,
        }
    
    def register_reporter(self, format_name: str, reporter_class: Type[BaseReporter]) -> None:
        """Register a new reporter format.
        
        Args:
            format_name: Name of the format (e.g., 'json', 'sarif')
            reporter_class: Reporter class to handle this format
        """
        if not issubclass(reporter_class, BaseReporter):
            raise ValueError(f"Reporter {reporter_class} must inherit from BaseReporter")
        
        self._reporters[format_name.lower()] = reporter_class
    
    def get_reporter(self, format_name: str) -> BaseReporter:
        """Get a reporter instance for the specified format.
        
        Args:
            format_name: Output format name
            
        Returns:
            Reporter instance
            
        Raises:
            ValueError: If format is not supported
        """
        format_name = format_name.lower()
        
        if format_name not in self._reporters:
            available_formats = ", ".join(self._reporters.keys())
            raise ValueError(f"Unsupported format '{format_name}'. Available formats: {available_formats}")
        
        reporter_class = self._reporters[format_name]
        return reporter_class()
    
    def get_available_formats(self) -> list[str]:
        """Get list of available output formats.
        
        Returns:
            List of format names
        """
        return list(self._reporters.keys())
    
    def is_format_supported(self, format_name: str) -> bool:
        """Check if a format is supported.
        
        Args:
            format_name: Format name to check
            
        Returns:
            True if format is supported
        """
        return format_name.lower() in self._reporters