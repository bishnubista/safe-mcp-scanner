"""SARIF (Static Analysis Results Interchange Format) reporter.

Generates SARIF 2.1.0 format output for integration with IDEs and security tools.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any
from collections import defaultdict

from .base import BaseReporter, ScanResults, Finding


class SARIFReporter(BaseReporter):
    """Generate SARIF 2.1.0 format output for tool integration."""

    @property
    def format_name(self) -> str:
        """Name of the output format."""
        return "sarif"

    @property
    def file_extension(self) -> str:
        """File extension for this format."""
        return ".sarif"

    def format_results(self, results: ScanResults) -> str:
        """Format scan results as SARIF JSON.

        Args:
            results: Scan results to format

        Returns:
            SARIF JSON string
        """
        sarif_output = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "safe-mcp-scanner",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/bishnubista/safe-mcp-scanner",
                            "shortDescription": {
                                "text": "Security vulnerability scanner for MCP (Model Context Protocol) servers"
                            },
                            "fullDescription": {
                                "text": "A defensive security tool that identifies vulnerabilities in MCP server implementations"
                            },
                            "rules": self._generate_rules(results.findings),
                        }
                    },
                    "results": self._generate_results(results.findings),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                    "properties": {
                        "scan_duration": results.scan_duration,
                        "files_scanned": len(results.scanned_files),
                        "total_files": results.total_files,
                    },
                }
            ],
        }

        return json.dumps(sarif_output, indent=2)

    def _generate_rules(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Generate SARIF rules from unique technique IDs.

        Args:
            findings: List of findings to extract rules from

        Returns:
            List of SARIF rule objects
        """
        # Deduplicate by technique_id and collect first instance of each
        seen_techniques: Dict[str, Finding] = {}

        for finding in findings:
            if finding.technique_id not in seen_techniques:
                seen_techniques[finding.technique_id] = finding

        rules = []
        for technique_id, finding in seen_techniques.items():
            rule = {
                "id": technique_id,
                "name": technique_id,
                "shortDescription": {
                    "text": finding.message or f"Security issue: {technique_id}"
                },
                "fullDescription": {
                    "text": finding.description or "Security vulnerability detected"
                },
                "defaultConfiguration": {
                    "level": self._severity_to_level(finding.severity)
                },
                "properties": {
                    "security-severity": str(self._severity_to_score(finding.severity)),
                    "tags": ["security", "mcp"],
                },
            }

            # Add help text if recommendation is available
            if finding.recommendation:
                rule["help"] = {
                    "text": finding.recommendation,
                    "markdown": finding.recommendation,
                }

            rules.append(rule)

        return rules

    def _generate_results(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Convert findings to SARIF results.

        Args:
            findings: List of findings to convert

        Returns:
            List of SARIF result objects
        """
        sarif_results = []

        for finding in findings:
            result = {
                "ruleId": finding.technique_id,
                "level": self._severity_to_level(finding.severity),
                "message": {
                    "text": finding.message or "Security vulnerability detected"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(finding.file_path),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": finding.line_number or 1,
                                "startColumn": finding.column_number or 1,
                            },
                        }
                    }
                ],
                "properties": {
                    "confidence": finding.confidence,
                    "severity": finding.severity,
                },
            }

            # Add source code snippet if available
            if finding.source_code:
                result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                    "text": finding.source_code
                }

            # Add metadata if available
            if finding.metadata:
                result["properties"]["metadata"] = finding.metadata

            sarif_results.append(result)

        return sarif_results

    def _severity_to_level(self, severity: str) -> str:
        """Map severity to SARIF level.

        Args:
            severity: Severity string (critical, high, medium, low)

        Returns:
            SARIF level (error, warning, note)
        """
        severity_lower = severity.lower()
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
        }
        return mapping.get(severity_lower, "warning")

    def _severity_to_score(self, severity: str) -> float:
        """Map severity to CVSS-like score for security-severity property.

        Args:
            severity: Severity string

        Returns:
            Score from 0.0 to 10.0
        """
        severity_lower = severity.lower()
        mapping = {
            "critical": 9.0,
            "high": 7.0,
            "medium": 5.0,
            "low": 3.0,
        }
        return mapping.get(severity_lower, 5.0)
