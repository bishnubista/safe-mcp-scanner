"""Detector for hardcoded credentials in MCP configuration files.

Technique ID: MCP-CONFIG-001 (transitioning from SAFE-T naming)
Category: Configuration Security
Severity: Critical
"""

import re
import json
from pathlib import Path
from typing import List, Optional, Dict, Any

from .base import BaseTechnique, Finding, register_technique
from ..config import Config


@register_technique
class HardcodedCredentialsDetector(BaseTechnique):
    """Detects hardcoded API keys, tokens, and passwords in MCP configs."""

    @property
    def technique_id(self) -> str:
        return "MCP-CONFIG-001"

    @property
    def name(self) -> str:
        return "Hardcoded Credentials"

    @property
    def description(self) -> str:
        return (
            "Detects hardcoded credentials (API keys, tokens, passwords) "
            "in MCP configuration files. Credentials should be loaded from "
            "environment variables or secure secret management systems."
        )

    @property
    def severity(self) -> str:
        return "critical"

    @property
    def tactic(self) -> str:
        return "Configuration Security"

    @property
    def file_types(self) -> List[str]:
        return [".json", ".yaml", ".yml"]

    # High-entropy string patterns that look like secrets
    SECRET_PATTERNS = {
        "generic_secret": re.compile(
            r'["\'](api[_-]?key|token|password|secret)["\']\s*:\s*["\']([^"\'\s]{20,})["\']',
            re.IGNORECASE
        ),
        "openai_key": re.compile(r'["\']?(sk-proj-[a-zA-Z0-9]{48,})["\']?'),
        "openai_legacy": re.compile(r'["\']?(sk-[a-zA-Z0-9]{48,})["\']?'),
        "anthropic_key": re.compile(r'["\']?(sk-ant-[a-zA-Z0-9_-]{95,})["\']?'),
        "github_token": re.compile(r'["\']?(gh[ps]_[a-zA-Z0-9]{36,})["\']?'),
        "aws_key": re.compile(r'["\']?(AKIA[0-9A-Z]{16})["\']?'),
        "slack_token": re.compile(r'["\']?(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,})["\']?'),
        "stripe_key": re.compile(r'["\']?(sk_live_[a-zA-Z0-9]{24,})["\']?'),
        "google_api": re.compile(r'["\']?(AIza[0-9A-Za-z\\-_]{35})["\']?'),
        "jwt_token": re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'),
    }

    # Suspicious key names that likely contain secrets
    SUSPECT_KEYS = [
        "api_key", "apikey", "api-key",
        "password", "passwd", "pwd",
        "token", "access_token", "secret", "auth_token",
        "private_key", "client_secret", "session_secret",
        "database_password", "db_password",
        "encryption_key", "signing_key",
    ]

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a configuration file for hardcoded credentials."""
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            # Skip files that can't be read
            return findings

        # Method 1: Pattern matching for known secret formats
        findings.extend(self._pattern_based_detection(file_path, content))

        # Method 2: Parse JSON/YAML and check for suspicious keys with values
        if file_path.suffix == ".json":
            findings.extend(self._json_semantic_detection(file_path, content))

        return findings

    def _pattern_based_detection(self, file_path: Path, content: str) -> List[Finding]:
        """Use regex patterns to detect known secret formats."""
        findings = []

        for pattern_name, pattern in self.SECRET_PATTERNS.items():
            for match in pattern.finditer(content):
                # Calculate line number
                line_num = content[:match.start()].count('\n') + 1

                # Extract matched secret (truncate for safety)
                matched_text = match.group(0)
                if len(matched_text) > 40:
                    display_text = matched_text[:20] + "..." + matched_text[-10:]
                else:
                    display_text = matched_text[:15] + "..."

                # Get source context
                source_context = self._get_source_context(content, line_num)

                findings.append(self.create_finding(
                    file_path=file_path,
                    message=f"Hardcoded credential detected: {pattern_name.replace('_', ' ').title()}",
                    description=f"Found {pattern_name.replace('_', ' ')} hardcoded in configuration file",
                    line_number=line_num,
                    confidence=0.95,
                    severity="critical",
                    recommendation=(
                        "Move credentials to environment variables. "
                        f"Use ${{{pattern_name.upper()}}} or reference from secure secret manager."
                    ),
                    source_code=source_context,
                    pattern_matched=pattern_name,
                    secret_preview=display_text
                ))

        return findings

    def _json_semantic_detection(self, file_path: Path, content: str) -> List[Finding]:
        """Parse JSON and analyze for suspicious key-value pairs."""
        findings = []

        try:
            config = json.loads(content)
        except json.JSONDecodeError:
            # Not valid JSON, skip semantic analysis
            return findings

        # Recursively check configuration
        findings.extend(self._check_config_keys(file_path, config, content, path=""))

        return findings

    def _check_config_keys(
        self,
        file_path: Path,
        config: Any,
        content: str,
        path: str
    ) -> List[Finding]:
        """Recursively check configuration for suspicious keys with values."""
        findings = []

        if not isinstance(config, dict):
            return findings

        for key, value in config.items():
            current_path = f"{path}.{key}" if path else key

            # Check if key name is suspicious
            if any(suspect in key.lower() for suspect in self.SUSPECT_KEYS):
                # Check if value looks like a secret (not a reference to env var)
                if isinstance(value, str) and not self._is_env_reference(value):
                    # Reasonable minimum secret length and not empty
                    if len(value) >= 12 and value.strip():
                        # Check if it's not a placeholder
                        if not self._is_placeholder(value):
                            # Find line number
                            line_num = self._find_key_line_number(content, current_path)

                            # Get source context
                            source_context = self._get_source_context(content, line_num) if line_num else None

                            # Truncate value for display
                            if len(value) > 30:
                                display_value = value[:15] + "..." + value[-8:]
                            else:
                                display_value = value[:10] + "..."

                            findings.append(self.create_finding(
                                file_path=file_path,
                                message=f"Suspicious credential in config: {current_path}",
                                description=(
                                    f"Configuration key '{current_path}' contains what appears to be "
                                    "a hardcoded credential. This should be loaded from environment variables."
                                ),
                                line_number=line_num,
                                confidence=0.80,
                                severity="critical",
                                recommendation=(
                                    f"Replace with environment variable reference. "
                                    f"Set {key.upper()} as an environment variable and reference it "
                                    "instead of hardcoding the value."
                                ),
                                source_code=source_context,
                                config_path=current_path,
                                value_preview=display_value
                            ))

            # Recurse into nested objects
            if isinstance(value, dict):
                findings.extend(
                    self._check_config_keys(file_path, value, content, current_path)
                )
            # Check lists for nested objects
            elif isinstance(value, list):
                for idx, item in enumerate(value):
                    if isinstance(item, dict):
                        findings.extend(
                            self._check_config_keys(
                                file_path, item, content, f"{current_path}[{idx}]"
                            )
                        )

        return findings

    def _is_env_reference(self, value: str) -> bool:
        """Check if value is a reference to environment variable."""
        env_patterns = [
            r'^\$\{?[A-Z_][A-Z0-9_]*\}?$',  # ${VAR_NAME} or $VAR_NAME
            r'^<[A-Z_][A-Z0-9_]*>$',         # <VAR_NAME>
            r'^%[A-Z_][A-Z0-9_]*%$',         # %VAR_NAME%
            r'^\{\{[A-Z_][A-Z0-9_]*\}\}$',   # {{VAR_NAME}}
        ]
        return any(re.match(pattern, value.strip()) for pattern in env_patterns)

    def _is_placeholder(self, value: str) -> bool:
        """Check if value is a placeholder like 'your-api-key-here'."""
        placeholder_patterns = [
            r'your[_-]?(api[_-]?key|token|password|secret)',
            r'(api[_-]?key|token|password|secret)[_-]?here',
            r'(example|sample|placeholder)',
            r'^(xxx+|test|demo)$',
            r'^\*+$',
        ]
        value_lower = value.lower()
        return any(re.search(pattern, value_lower) for pattern in placeholder_patterns)

    def _find_key_line_number(self, content: str, key_path: str) -> Optional[int]:
        """Find the line number where a specific JSON key appears."""
        # Simple approach: find the last component of the path
        key_parts = key_path.split('.')
        final_key = key_parts[-1].split('[')[0]  # Remove array indices

        # Search for the key in quotes
        search_str = f'"{final_key}"'
        if search_str in content:
            return content[:content.find(search_str)].count('\n') + 1

        return None

    def _get_source_context(self, content: str, line_num: Optional[int], context_lines: int = 2) -> Optional[str]:
        """Extract source code context around a finding."""
        if line_num is None:
            return None

        lines = content.split('\n')
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)

        context = lines[start:end]
        return '\n'.join(context) if context else None
