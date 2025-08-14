"""SAFE-T1101: Command Injection technique implementation."""

from pathlib import Path
from typing import List

from .base import BaseTechnique, Finding, register_technique
from ..detectors.pattern_matcher import PatternMatcher


@register_technique
class CommandInjectionTechnique(BaseTechnique):
    """Detects command injection vulnerabilities in MCP servers."""
    
    def __init__(self, config) -> None:
        super().__init__(config)
        self.pattern_matcher = PatternMatcher(config)
    
    @property
    def technique_id(self) -> str:
        return "SAFE-T1101"
    
    @property
    def name(self) -> str:
        return "Command Injection"
    
    @property
    def description(self) -> str:
        return "Detects potential command injection vulnerabilities in MCP server implementations"
    
    @property
    def severity(self) -> str:
        return "high"
    
    @property
    def tactic(self) -> str:
        return "Execution"
    
    @property
    def mitre_attack_mapping(self) -> str:
        return "T1059"  # Command and Scripting Interpreter
    
    @property
    def file_types(self) -> List[str]:
        return [".py", ".js", ".ts"]
    
    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a file for command injection vulnerabilities."""
        if not self.pattern_matcher.can_analyze_file(file_path):
            return []
        
        # Get patterns for command injection detection
        patterns = self.pattern_matcher.create_command_injection_patterns()
        
        # Run pattern matching
        findings = self.pattern_matcher.analyze_file(file_path, patterns)
        
        # Enhance findings with technique-specific information
        enhanced_findings = []
        for finding in findings:
            # Override technique ID to ensure consistency
            finding.technique_id = self.technique_id
            
            # Add MCP-specific context to recommendations
            if "MCP" not in finding.recommendation:
                finding.recommendation = (
                    f"In MCP servers: {finding.recommendation}. "
                    "Ensure all tool parameters are properly validated before use in system commands."
                )
            
            enhanced_findings.append(finding)
        
        return enhanced_findings