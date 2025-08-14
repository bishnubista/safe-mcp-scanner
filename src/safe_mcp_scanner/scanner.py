"""Main scanning orchestrator for the SAFE-MCP Scanner."""

import time
from pathlib import Path
from typing import List, Dict, Any

from .config import Config
from .techniques.base import BaseTechnique, Finding
from .detectors.base import BaseDetector
from .reporters.base import BaseReporter, ScanResults
from .file_discovery import FileDiscovery
from .technique_loader import TechniqueLoader
from .reporter_factory import ReporterFactory


class Scanner:
    """Main scanner class that orchestrates the scanning process."""
    
    def __init__(self, config: Config) -> None:
        self.config = config
        self.file_discovery = FileDiscovery(config)
        self.technique_loader = TechniqueLoader(config)
        self.reporter_factory = ReporterFactory()
        
        # Load available techniques
        self._techniques: Dict[str, BaseTechnique] = {}
        self._load_techniques()
    
    def _load_techniques(self) -> None:
        """Load and initialize available techniques."""
        self._techniques = self.technique_loader.load_techniques()
    
    def get_available_techniques(self) -> Dict[str, BaseTechnique]:
        """Get all available techniques."""
        return self._techniques.copy()
    
    def get_enabled_techniques(self) -> Dict[str, BaseTechnique]:
        """Get only enabled techniques."""
        return {
            technique_id: technique 
            for technique_id, technique in self._techniques.items()
            if technique.is_enabled()
        }
    
    def scan(self, target_path: Path) -> ScanResults:
        """Perform a security scan on the target path.
        
        Args:
            target_path: Directory or file to scan
            
        Returns:
            Scan results containing findings and metadata
        """
        start_time = time.time()
        
        # Discover files to scan
        if target_path.is_file():
            files_to_scan = [target_path] if self.config.should_scan_file(target_path) else []
            total_files = 1
        else:
            files_to_scan = self.file_discovery.discover_files(target_path)
            total_files = len(files_to_scan)
        
        # Get enabled techniques
        enabled_techniques = self.get_enabled_techniques()
        
        # Scan files
        all_findings: List[Finding] = []
        scanned_files: List[Path] = []
        
        for file_path in files_to_scan:
            file_findings = self._scan_file(file_path, enabled_techniques)
            all_findings.extend(file_findings)
            
            if file_findings or self._should_track_file(file_path):
                scanned_files.append(file_path)
        
        # Calculate scan duration
        scan_duration = time.time() - start_time
        
        return ScanResults(
            findings=all_findings,
            scanned_files=scanned_files,
            total_files=total_files,
            scan_duration=scan_duration
        )
    
    def _scan_file(self, file_path: Path, techniques: Dict[str, BaseTechnique]) -> List[Finding]:
        """Scan a single file with applicable techniques."""
        findings: List[Finding] = []
        
        for technique_id, technique in techniques.items():
            try:
                if technique.can_analyze_file(file_path):
                    technique_findings = technique.analyze_file(file_path)
                    
                    # Filter findings by confidence threshold
                    technique_config = technique.get_technique_config()
                    filtered_findings = [
                        finding for finding in technique_findings
                        if finding.confidence >= technique_config.confidence_threshold
                    ]
                    
                    findings.extend(filtered_findings)
                    
            except Exception as e:
                # Log error but continue scanning
                # In a real implementation, this would use proper logging
                print(f"Warning: Error scanning {file_path} with {technique_id}: {e}")
        
        return findings
    
    def _should_track_file(self, file_path: Path) -> bool:
        """Determine if a file should be tracked even without findings."""
        # Track all files that were actually processed
        return True
    
    def format_results(self, results: ScanResults, output_format: str) -> str:
        """Format scan results in the specified format.
        
        Args:
            results: Scan results to format
            output_format: Target format (json, sarif, text, html)
            
        Returns:
            Formatted output string
        """
        reporter = self.reporter_factory.get_reporter(output_format)
        return reporter.format_results(results)
    
    def scan_and_report(
        self, 
        target_path: Path, 
        output_format: str = "json",
        output_file: Path = None
    ) -> ScanResults:
        """Convenience method to scan and generate formatted output.
        
        Args:
            target_path: Directory or file to scan
            output_format: Output format
            output_file: Optional output file path
            
        Returns:
            Scan results
        """
        results = self.scan(target_path)
        formatted_output = self.format_results(results, output_format)
        
        if output_file:
            output_file.write_text(formatted_output)
        else:
            print(formatted_output)
        
        return results