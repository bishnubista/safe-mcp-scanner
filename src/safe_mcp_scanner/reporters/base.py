"""Base class for result reporters."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any

from ..techniques.base import Finding


@dataclass
class ScanResults:
    """Container for scan results."""
    
    findings: List[Finding]
    scanned_files: List[Path]
    total_files: int
    scan_duration: float
    scanner_version: str = "0.1.0"
    
    def has_findings_at_severity(self, severity: str) -> bool:
        """Check if there are findings at or above the specified severity."""
        severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_level = severity_levels.get(severity.lower(), 0)
        
        for finding in self.findings:
            finding_level = severity_levels.get(finding.severity.lower(), 0)
            if finding_level >= min_level:
                return True
        
        return False
    
    def get_findings_by_severity(self) -> Dict[str, List[Finding]]:
        """Group findings by severity level."""
        grouped = {"low": [], "medium": [], "high": [], "critical": []}
        
        for finding in self.findings:
            severity = finding.severity.lower()
            if severity in grouped:
                grouped[severity].append(finding)
        
        return grouped
    
    def get_findings_by_technique(self) -> Dict[str, List[Finding]]:
        """Group findings by technique ID."""
        grouped = {}
        
        for finding in self.findings:
            technique_id = finding.technique_id
            if technique_id not in grouped:
                grouped[technique_id] = []
            grouped[technique_id].append(finding)
        
        return grouped


class BaseReporter(ABC):
    """Abstract base class for result reporters."""
    
    @property
    @abstractmethod
    def format_name(self) -> str:
        """Name of the output format."""
        pass
    
    @property
    @abstractmethod
    def file_extension(self) -> str:
        """File extension for this format."""
        pass
    
    @abstractmethod
    def format_results(self, results: ScanResults) -> str:
        """Format scan results into the target format.
        
        Args:
            results: Scan results to format
            
        Returns:
            Formatted output as string
        """
        pass
    
    def should_include_source(self, finding: Finding) -> bool:
        """Determine if source code should be included for a finding."""
        return finding.source_code is not None and len(finding.source_code.strip()) > 0