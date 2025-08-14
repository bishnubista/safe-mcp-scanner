"""JSON output reporter for scan results."""

import json
from datetime import datetime
from typing import Dict, Any

from .base import BaseReporter, ScanResults


class JSONReporter(BaseReporter):
    """JSON format reporter for scan results."""
    
    @property
    def format_name(self) -> str:
        return "json"
    
    @property
    def file_extension(self) -> str:
        return ".json"
    
    def format_results(self, results: ScanResults) -> str:
        """Format scan results as JSON.
        
        Args:
            results: Scan results to format
            
        Returns:
            JSON formatted string
        """
        # Build the main result structure
        json_data = {
            "scan_info": {
                "scanner_name": "SAFE-MCP Scanner",
                "scanner_version": results.scanner_version,
                "scan_timestamp": datetime.now().isoformat(),
                "scan_duration_seconds": round(results.scan_duration, 2),
                "total_files_scanned": len(results.scanned_files),
                "total_files_discovered": results.total_files
            },
            "summary": self._create_summary(results),
            "findings": [self._format_finding(finding) for finding in results.findings],
            "files_scanned": [str(path) for path in results.scanned_files]
        }
        
        return json.dumps(json_data, indent=2, ensure_ascii=False)
    
    def _create_summary(self, results: ScanResults) -> Dict[str, Any]:
        """Create summary section of the report."""
        findings_by_severity = results.get_findings_by_severity()
        findings_by_technique = results.get_findings_by_technique()
        
        return {
            "total_findings": len(results.findings),
            "findings_by_severity": {
                severity: len(findings) 
                for severity, findings in findings_by_severity.items()
                if findings  # Only include severities with findings
            },
            "findings_by_technique": {
                technique_id: len(findings)
                for technique_id, findings in findings_by_technique.items()
            },
            "unique_techniques_triggered": len(findings_by_technique),
            "files_with_findings": len(set(finding.file_path for finding in results.findings))
        }
    
    def _format_finding(self, finding) -> Dict[str, Any]:
        """Format a single finding for JSON output."""
        finding_data = {
            "technique_id": finding.technique_id,
            "file_path": str(finding.file_path),
            "severity": finding.severity,
            "confidence": finding.confidence,
            "message": finding.message,
            "description": finding.description,
            "recommendation": finding.recommendation
        }
        
        # Add location information if available
        if finding.line_number is not None:
            finding_data["line_number"] = finding.line_number
        
        if finding.column_number is not None:
            finding_data["column_number"] = finding.column_number
        
        # Add source code context if available and enabled
        if self.should_include_source(finding):
            finding_data["source_code"] = finding.source_code
        
        # Add metadata if available
        if finding.metadata:
            finding_data["metadata"] = finding.metadata
        
        return finding_data