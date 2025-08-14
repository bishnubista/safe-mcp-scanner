"""Pattern-based detection engine for security issues."""

import re
from pathlib import Path
from typing import List, Dict, Any, Pattern

from ..techniques.base import Finding
from .base import BaseDetector


class PatternMatcher(BaseDetector):
    """Regex-based pattern matcher for detecting security issues."""
    
    def __init__(self, config) -> None:
        super().__init__(config)
        self._compiled_patterns: Dict[str, Pattern] = {}
    
    @property
    def name(self) -> str:
        return "Pattern Matcher"
    
    @property
    def supported_file_types(self) -> List[str]:
        return ["*"]  # Can analyze any text file
    
    def can_analyze_file(self, file_path: Path) -> bool:
        """Check if this detector can analyze the given file."""
        try:
            # Try to read a small portion to check if it's a text file
            with open(file_path, 'rb') as f:
                sample = f.read(1024)
                
            # Simple heuristic: if we can decode as UTF-8 and it's mostly printable, it's text
            try:
                decoded = sample.decode('utf-8')
                printable_ratio = sum(1 for c in decoded if c.isprintable() or c.isspace()) / len(decoded)
                return printable_ratio > 0.7
            except UnicodeDecodeError:
                return False
                
        except (IOError, OSError):
            return False
    
    def analyze_file(self, file_path: Path, patterns: List[Dict[str, Any]]) -> List[Finding]:
        """Analyze a file using the provided patterns.
        
        Args:
            file_path: Path to the file to analyze
            patterns: List of pattern dictionaries with keys:
                - pattern: regex pattern string
                - technique_id: SAFE-MCP technique identifier
                - severity: severity level
                - message: finding message template
                - confidence: confidence score
                
        Returns:
            List of security findings
        """
        findings: List[Finding] = []
        
        try:
            content = self.read_file_safely(file_path)
        except ValueError as e:
            # File too large or unreadable
            return findings
        
        lines = content.splitlines()
        
        for pattern_dict in patterns:
            pattern_findings = self._apply_pattern(
                file_path, 
                content, 
                lines, 
                pattern_dict
            )
            findings.extend(pattern_findings)
        
        return findings
    
    def _apply_pattern(
        self, 
        file_path: Path, 
        content: str, 
        lines: List[str], 
        pattern_dict: Dict[str, Any]
    ) -> List[Finding]:
        """Apply a single pattern to file content."""
        findings: List[Finding] = []
        
        pattern_str = pattern_dict.get("pattern", "")
        if not pattern_str:
            return findings
        
        # Compile pattern if not already cached
        pattern_key = f"{pattern_str}:{pattern_dict.get('flags', 0)}"
        if pattern_key not in self._compiled_patterns:
            flags = pattern_dict.get("flags", re.IGNORECASE | re.MULTILINE)
            try:
                self._compiled_patterns[pattern_key] = re.compile(pattern_str, flags)
            except re.error:
                # Invalid regex pattern
                return findings
        
        regex_pattern = self._compiled_patterns[pattern_key]
        
        # Search for matches
        for match in regex_pattern.finditer(content):
            # Find line number
            line_number = content[:match.start()].count('\n') + 1
            
            # Calculate column number
            line_start = content.rfind('\n', 0, match.start()) + 1
            column_number = match.start() - line_start + 1
            
            # Extract source context
            source_context = self.extract_source_context(
                content, 
                line_number, 
                self.config.output.max_lines_context
            )
            
            # Create finding
            finding = Finding(
                technique_id=pattern_dict.get("technique_id", "UNKNOWN"),
                file_path=file_path,
                line_number=line_number,
                column_number=column_number,
                severity=pattern_dict.get("severity", "medium"),
                confidence=pattern_dict.get("confidence", 0.7),
                message=pattern_dict.get("message", f"Pattern match: {match.group()}"),
                description=pattern_dict.get("description", "Security pattern detected"),
                recommendation=pattern_dict.get("recommendation", "Review the flagged code"),
                source_code=source_context,
                metadata={
                    "matched_text": match.group(),
                    "pattern": pattern_str,
                    "groups": match.groups() if match.groups() else [],
                    "groupdict": match.groupdict() if match.groupdict() else {}
                }
            )
            
            findings.append(finding)
        
        return findings
    
    def create_command_injection_patterns(self) -> List[Dict[str, Any]]:
        """Create patterns for detecting command injection vulnerabilities."""
        return [
            {
                "pattern": r"subprocess\.(call|check_call|check_output|run|Popen)\s*\(\s*f[\"'][^\"']*\{[^}]*\}[^\"']*[\"'].*shell\s*=\s*True",
                "technique_id": "SAFE-T1101",
                "severity": "high",
                "confidence": 0.9,
                "message": "Command injection via subprocess with f-string and shell=True",
                "description": "Subprocess call with f-string formatting and shell=True allows command injection",
                "recommendation": "Use parameterized commands without shell=True"
            },
            {
                "pattern": r"os\.(system|popen|exec[lv]?[pe]?)\s*\(\s*f[\"'][^\"']*\{[^}]*\}",
                "technique_id": "SAFE-T1101", 
                "severity": "high",
                "confidence": 0.9,
                "message": "Command injection via os module with f-string",
                "description": "OS command execution with f-string formatting allows command injection",
                "recommendation": "Use subprocess with argument lists instead of shell commands"
            },
            {
                "pattern": r"subprocess\.(call|check_call|check_output|run|Popen)\s*\([^)]*%[^)]*shell\s*=\s*True",
                "technique_id": "SAFE-T1101",
                "severity": "high",
                "confidence": 0.8,
                "message": "Command injection via subprocess with % formatting and shell=True",
                "description": "Subprocess call with % formatting and shell=True may allow command injection",
                "recommendation": "Use parameterized commands without shell=True"
            },
            {
                "pattern": r"subprocess\.(call|check_call|check_output|run|Popen)\s*\([^)]*\.format\([^)]*\)[^)]*shell\s*=\s*True",
                "technique_id": "SAFE-T1101",
                "severity": "high",
                "confidence": 0.8,
                "message": "Command injection via subprocess with .format() and shell=True", 
                "description": "Subprocess call with .format() and shell=True may allow command injection",
                "recommendation": "Use parameterized commands without shell=True"
            },
            {
                "pattern": r"shell\s*=\s*True",
                "technique_id": "SAFE-T1101",
                "severity": "high", 
                "confidence": 0.6,
                "message": "Shell execution enabled in subprocess call",
                "description": "Using shell=True can enable command injection if user input is involved",
                "recommendation": "Use shell=False and pass commands as argument lists"
            }
        ]
    
    def create_malicious_tool_patterns(self) -> List[Dict[str, Any]]:
        """Create patterns for detecting malicious tool descriptions."""
        return [
            {
                "pattern": r"[\"']description[\"']\s*:\s*[\"'][^\"']*(?:password|secret|token|key|credential)[^\"']*[\"']",
                "technique_id": "SAFE-T1001",
                "severity": "high",
                "confidence": 0.7,
                "message": "Tool description mentions sensitive information",
                "description": "MCP tool description may be designed to trick users into revealing credentials",
                "recommendation": "Review tool description for social engineering attempts"
            },
            {
                "pattern": r"[\"']name[\"']\s*:\s*[\"'][^\"']*(?:admin|root|system|debug)[^\"']*[\"']",
                "technique_id": "SAFE-T1001",
                "severity": "high",
                "confidence": 0.6,
                "message": "Tool name suggests elevated privileges",
                "description": "MCP tool name may indicate privilege escalation attempt",
                "recommendation": "Verify tool actually requires elevated privileges"
            }
        ]
    
    def create_oauth_theft_patterns(self) -> List[Dict[str, Any]]:
        """Create patterns for detecting OAuth token theft."""
        return [
            {
                "pattern": r"requests\.(?:get|post|put|patch|delete)\s*\([^)]*[\"']https?://[^/]*(?:evil|malicious|attacker)[^\"']*[\"']",
                "technique_id": "SAFE-T1201",
                "severity": "critical",
                "confidence": 0.9,
                "message": "HTTP request to suspicious domain",
                "description": "Network request to potentially malicious domain that could exfiltrate tokens",
                "recommendation": "Review the destination URL and ensure it's legitimate"
            },
            {
                "pattern": r"(?:access_token|bearer_token|oauth_token|authorization)\s*[=:]\s*[\"']?\{[^}]*\}[\"']?",
                "technique_id": "SAFE-T1201",
                "severity": "medium",
                "confidence": 0.7,
                "message": "Dynamic token construction detected",
                "description": "OAuth token being constructed from variables - ensure proper validation",
                "recommendation": "Validate token sources and implement proper token handling"
            }
        ]