"""SAFE-T1001: Malicious Tool Descriptions technique implementation."""

from pathlib import Path
from typing import List

from .base import BaseTechnique, Finding, register_technique
from ..detectors.pattern_matcher import PatternMatcher


@register_technique
class MaliciousToolTechnique(BaseTechnique):
    """Detects potentially malicious MCP tool descriptions and configurations."""
    
    def __init__(self, config) -> None:
        super().__init__(config)
        self.pattern_matcher = PatternMatcher(config)
    
    @property
    def technique_id(self) -> str:
        return "SAFE-T1001"
    
    @property
    def name(self) -> str:
        return "Malicious Tool Descriptions"
    
    @property
    def description(self) -> str:
        return "Detects potentially malicious or deceptive tool descriptions in MCP configurations"
    
    @property
    def severity(self) -> str:
        return "high"
    
    @property
    def tactic(self) -> str:
        return "Initial Access"
    
    @property
    def mitre_attack_mapping(self) -> str:
        return "T1566"  # Phishing
    
    @property
    def file_types(self) -> List[str]:
        return [".json", ".yaml", ".yml"]
    
    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a file for malicious tool descriptions."""
        if not self.pattern_matcher.can_analyze_file(file_path):
            return []
        
        # Get patterns for malicious tool detection
        patterns = self.pattern_matcher.create_malicious_tool_patterns()
        
        # Run pattern matching
        findings = self.pattern_matcher.analyze_file(file_path, patterns)
        
        # Enhance findings with technique-specific information
        enhanced_findings = []
        for finding in findings:
            # Override technique ID to ensure consistency
            finding.technique_id = self.technique_id
            
            # Add MCP-specific context
            finding.recommendation = (
                "Review MCP tool description for social engineering indicators. "
                "Ensure tool descriptions accurately reflect their functionality and "
                "do not attempt to mislead users into providing sensitive information."
            )
            
            enhanced_findings.append(finding)
        
        return enhanced_findings