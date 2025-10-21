# Implementation Plan: Making This Scanner Actually Work

## Current Status Assessment

### ✅ What Works
- Core architecture (Scanner, Config, FileDiscovery)
- CLI framework with Click
- JSON reporter
- 2 basic detectors (command injection, malicious descriptions)
- Test infrastructure (40 passing tests)
- File discovery and filtering

### ❌ What's Broken
- SARIF reporter (advertised but missing)
- Text reporter (advertised but missing)
- HTML reporter (advertised but missing)
- 75 promised detectors don't exist (only 2 work)
- No AST analysis despite being claimed
- Documentation wildly overpromises

### 🎯 Goal
Build a **practical, honest MCP vulnerability scanner** in 3 milestones

---

## Milestone 1: Fix The Foundation (1-2 weeks)

**Goal**: Make the scanner honest and usable with core features working

### Week 1: Critical Fixes

#### Task 1.1: Implement SARIF Reporter (Priority: CRITICAL)
**File**: `src/safe_mcp_scanner/reporters/sarif.py`
**Time**: 1-2 days

```python
"""SARIF reporter for IDE and security tool integration."""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from .base import BaseReporter, ScanResults, Finding


class SARIFReporter(BaseReporter):
    """Generate SARIF 2.1.0 format output."""

    def format_results(self, results: ScanResults) -> str:
        """Format scan results as SARIF JSON."""

        sarif_output = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "safe-mcp-scanner",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/your-org/safe-mcp-scanner",
                            "rules": self._generate_rules(results.findings),
                        }
                    },
                    "results": self._generate_results(results.findings),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.utcnow().isoformat() + "Z",
                        }
                    ],
                }
            ],
        }

        return json.dumps(sarif_output, indent=2)

    def _generate_rules(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Generate SARIF rules from unique techniques."""
        # Deduplicate by technique_id
        seen = set()
        rules = []

        for finding in findings:
            if finding.technique_id not in seen:
                rules.append(
                    {
                        "id": finding.technique_id,
                        "name": finding.technique_id,
                        "shortDescription": {"text": finding.message},
                        "fullDescription": {"text": finding.description},
                        "help": {"text": finding.recommendation},
                        "defaultConfiguration": {"level": self._severity_to_level(finding.severity)},
                        "properties": {"security-severity": str(self._severity_to_score(finding.severity))},
                    }
                )
                seen.add(finding.technique_id)

        return rules

    def _generate_results(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Convert findings to SARIF results."""
        return [
            {
                "ruleId": finding.technique_id,
                "level": self._severity_to_level(finding.severity),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(finding.file_path)},
                            "region": {
                                "startLine": finding.line_number or 1,
                                "startColumn": finding.column_number or 1,
                                "snippet": {"text": finding.source_code or ""},
                            },
                        }
                    }
                ],
                "properties": {"confidence": finding.confidence},
            }
            for finding in findings
        ]

    def _severity_to_level(self, severity: str) -> str:
        """Map severity to SARIF level."""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
        }
        return mapping.get(severity.lower(), "warning")

    def _severity_to_score(self, severity: str) -> float:
        """Map severity to CVSS-like score."""
        mapping = {
            "critical": 9.0,
            "high": 7.0,
            "medium": 5.0,
            "low": 3.0,
        }
        return mapping.get(severity.lower(), 5.0)
```

**Register in factory**:
```python
# src/safe_mcp_scanner/reporter_factory.py
from .reporters.sarif import SARIFReporter

class ReporterFactory:
    def __init__(self):
        self._reporters = {
            "json": JSONReporter,
            "sarif": SARIFReporter,  # ADD THIS
        }
```

**Test**:
```bash
uv run safe-mcp-scan scan . --format sarif --output report.sarif
```

#### Task 1.2: Implement Text Reporter (Priority: CRITICAL)
**File**: `src/safe_mcp_scanner/reporters/text.py`
**Time**: 1 day

```python
"""Human-readable text reporter with colors."""

from collections import Counter
from typing import List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .base import BaseReporter, ScanResults, Finding


class TextReporter(BaseReporter):
    """Generate human-readable console output."""

    SEVERITY_COLORS = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
    }

    SEVERITY_ICONS = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
    }

    def format_results(self, results: ScanResults) -> str:
        """Format scan results as colored text."""
        console = Console(record=True)

        # Header
        console.print("\n[bold cyan]🔍 MCP Security Scan Results[/bold cyan]")
        console.print("━" * 60)

        # Summary
        self._print_summary(console, results)
        console.print("━" * 60)

        # Findings
        if results.findings:
            self._print_findings(console, results.findings)
        else:
            console.print("\n[green]✅ No security issues found![/green]\n")

        # Footer
        console.print("━" * 60)
        self._print_footer(console, results)

        return console.export_text()

    def _print_summary(self, console: Console, results: ScanResults):
        """Print summary statistics."""
        severity_counts = Counter(f.severity.lower() for f in results.findings)

        console.print("\n[bold]📊 Summary[/bold]")
        console.print(f"  Total Findings: {len(results.findings)}")

        for severity in ["critical", "high", "medium", "low"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                icon = self.SEVERITY_ICONS[severity]
                color = self.SEVERITY_COLORS[severity]
                console.print(f"  {icon} {severity.capitalize()}: [{color}]{count}[/{color}]")

        console.print(f"  Files Scanned: {len(results.scanned_files)}")
        console.print(f"  Duration: {results.scan_duration:.2f}s")

    def _print_findings(self, console: Console, findings: List[Finding]):
        """Print detailed findings."""
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity.lower(), 4))

        for i, finding in enumerate(sorted_findings, 1):
            console.print()
            self._print_finding(console, finding, i)

    def _print_finding(self, console: Console, finding: Finding, index: int):
        """Print a single finding."""
        severity = finding.severity.lower()
        icon = self.SEVERITY_ICONS.get(severity, "⚪")
        color = self.SEVERITY_COLORS.get(severity, "white")

        # Title
        location = f"{finding.file_path}"
        if finding.line_number:
            location += f":{finding.line_number}"

        console.print(f"{icon} [{color}]{severity.upper()}[/{color}]: {finding.message}")
        console.print(f"  └─ File: {location}")
        console.print(f"  └─ Detector: {finding.technique_id}")

        # Description
        if finding.description:
            console.print(f"\n  [dim]Description:[/dim]")
            console.print(f"    {finding.description}")

        # Recommendation
        if finding.recommendation:
            console.print(f"\n  [green]💡 Recommendation:[/green]")
            console.print(f"    {finding.recommendation}")

        # Source code
        if finding.source_code:
            console.print(f"\n  [dim]Source:[/dim]")
            for line in finding.source_code.split('\n'):
                console.print(f"    {line}")

    def _print_footer(self, console: Console, results: ScanResults):
        """Print footer with verdict."""
        critical_count = sum(1 for f in results.findings if f.severity.lower() == "critical")
        high_count = sum(1 for f in results.findings if f.severity.lower() == "high")

        if critical_count > 0:
            console.print(f"\n[red bold]❌ Scan failed: {critical_count} critical issues found[/red bold]")
        elif high_count > 0:
            console.print(f"\n[yellow]⚠️  Warning: {high_count} high severity issues found[/yellow]")
        else:
            console.print("\n[green]✅ Scan passed[/green]")
```

**Register**:
```python
self._reporters = {
    "json": JSONReporter,
    "sarif": SARIFReporter,
    "text": TextReporter,  # ADD THIS
}
```

#### Task 1.3: Update Documentation to Match Reality (Priority: HIGH)
**Time**: 2-3 hours

**Update README.md**:
```markdown
# SAFE-MCP Scanner

A practical vulnerability scanner for MCP (Model Context Protocol) servers.

## Current Status: Alpha v0.1.0

**What works now:**
- ✅ 2 core detectors (command injection, malicious tool descriptions)
- ✅ 3 output formats (JSON, SARIF, Text)
- ✅ MCP config file detection
- ✅ Python/JavaScript file scanning
- ✅ CI/CD ready with exit codes

**Coming soon:**
- 🚧 10+ additional detectors for common MCP vulnerabilities
- 🚧 AST-based code analysis
- 🚧 Supply chain scanning
- 🚧 HTML reports

## Quick Start

```bash
# Scan an MCP server directory
uv run safe-mcp-scan scan /path/to/mcp/server

# Generate SARIF for GitHub
uv run safe-mcp-scan scan . --format sarif --output report.sarif

# CI/CD: Fail on critical issues
uv run safe-mcp-scan scan . --exit-code --max-critical 0
```

## Current Detectors

| ID | Name | Category | Severity |
|----|------|----------|----------|
| SAFE-T1001 | Malicious Tool Descriptions | Prompt Security | High |
| SAFE-T1101 | Command Injection | Code Execution | Critical |

**More detectors coming in future releases.**
```

**Update CLAUDE.md**:
```markdown
## Current Implementation Status

**Core Features** (v0.1.0):
- Scanner architecture: ✅ Complete
- CLI interface: ✅ Complete
- Configuration system: ✅ Complete
- JSON reporter: ✅ Complete
- SARIF reporter: ✅ Complete
- Text reporter: ✅ Complete

**Detectors**:
- Command injection: ✅ Working
- Malicious tool descriptions: ✅ Working
- Additional detectors: 🚧 In development

**Planned Features**:
- AST-based analysis
- Supply chain scanning
- Container security
- HTML reports
```

### Week 2: Core Detectors

#### Task 2.1: Hardcoded Credentials Detector (Priority: CRITICAL)
**File**: `src/safe_mcp_scanner/detectors/config/hardcoded_credentials.py`
**Time**: 2-3 days
**Impact**: ⭐⭐⭐⭐⭐

See example in REVISED_APPROACH.md

**Test cases**:
```python
def test_detects_openai_key():
    config = '''
    {
      "env": {
        "OPENAI_API_KEY": "sk-proj-abc123def456"
      }
    }
    '''
    findings = detector.analyze(config)
    assert len(findings) == 1
    assert findings[0].detector_id == "MCP-CONFIG-001"
```

#### Task 2.2: Path Traversal Detector (Priority: HIGH)
**File**: `src/safe_mcp_scanner/detectors/code/path_traversal.py`
**Time**: 1-2 days
**Impact**: ⭐⭐⭐⭐⭐

```python
"""Detects path traversal vulnerabilities in MCP tools."""

class PathTraversalDetector(BaseDetector):
    detector_id = "MCP-DATA-001"
    category = "Data Access"
    severity = "critical"

    UNSAFE_PATTERNS = [
        r'open\([^,]+\)',  # open(user_input)
        r'Path\([^)]+\)',  # Path(user_input)
        r'os\.path\.join\([^)]+\)',  # Without validation
    ]

    def analyze_file(self, file_path: Path) -> List[Finding]:
        if not file_path.suffix == '.py':
            return []

        findings = []
        content = file_path.read_text()

        # Look for file operations without path validation
        for line_num, line in enumerate(content.split('\n'), 1):
            # Check for file operations
            if any(pattern in line for pattern in ['open(', 'Path(', 'os.path.join(']):
                # Check if there's path validation nearby
                if not self._has_path_validation(content, line_num):
                    findings.append(self.create_finding(
                        file_path=file_path,
                        title="Potential path traversal vulnerability",
                        line_number=line_num,
                        confidence=0.7
                    ))

        return findings
```

#### Task 2.3: Insecure Transport Detector (Priority: HIGH)
**File**: `src/safe_mcp_scanner/detectors/config/insecure_transport.py`
**Time**: 1 day
**Impact**: ⭐⭐⭐⭐

```python
"""Detects HTTP instead of HTTPS in MCP configurations."""

class InsecureTransportDetector(BaseDetector):
    detector_id = "MCP-CONFIG-002"
    category = "Configuration Security"
    severity = "high"

    def analyze_file(self, file_path: Path) -> List[Finding]:
        if file_path.suffix not in ['.json', '.yaml', '.yml']:
            return []

        findings = []
        content = file_path.read_text()

        # Look for http:// URLs
        for match in re.finditer(r'["\'](http://[^"\']+)["\']', content):
            line_num = content[:match.start()].count('\n') + 1
            findings.append(self.create_finding(
                file_path=file_path,
                title="Insecure HTTP connection",
                description=f"Found HTTP URL: {match.group(1)}",
                recommendation="Use HTTPS instead of HTTP",
                line_number=line_num,
                confidence=0.9
            ))

        return findings
```

---

## Milestone 2: Enhanced Detection (Weeks 3-4)

### Goal: Add AST analysis and 5 more detectors

#### Task 3.1: Python AST Analyzer (Priority: HIGH)
**File**: `src/safe_mcp_scanner/analyzers/python_ast.py`
**Time**: 3-4 days

```python
"""Python AST analysis for detecting security issues."""

import ast
from pathlib import Path
from typing import List, Dict, Any


class PythonASTAnalyzer:
    """Analyzes Python code using AST."""

    def parse_file(self, file_path: Path) -> ast.Module:
        """Parse Python file to AST."""
        code = file_path.read_text()
        return ast.parse(code, filename=str(file_path))

    def find_function_calls(self, tree: ast.Module, function_names: List[str]) -> List[Dict[str, Any]]:
        """Find all calls to specified functions."""
        calls = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_function_name(node.func)
                if func_name in function_names:
                    calls.append({
                        'function': func_name,
                        'line': node.lineno,
                        'col': node.col_offset,
                        'args': [self._node_to_string(arg) for arg in node.args],
                        'kwargs': {kw.arg: self._node_to_string(kw.value) for kw in node.keywords},
                    })

        return calls

    def find_dangerous_functions(self, tree: ast.Module) -> List[Dict[str, Any]]:
        """Find calls to dangerous functions like eval, exec."""
        dangerous = ['eval', 'exec', '__import__', 'compile']
        return self.find_function_calls(tree, dangerous)

    def find_subprocess_calls(self, tree: ast.Module) -> List[Dict[str, Any]]:
        """Find subprocess calls with shell=True."""
        calls = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_function_name(node.func)
                if 'subprocess' in func_name or func_name in ['system', 'popen']:
                    # Check for shell=True
                    has_shell_true = any(
                        kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True
                        for kw in node.keywords
                    )

                    calls.append({
                        'function': func_name,
                        'line': node.lineno,
                        'shell': has_shell_true,
                        'dangerous': has_shell_true,
                    })

        return calls

    def _get_function_name(self, node: ast.AST) -> str:
        """Extract function name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value = self._get_function_name(node.value)
            return f"{value}.{node.attr}"
        return ""

    def _node_to_string(self, node: ast.AST) -> str:
        """Convert AST node to string representation."""
        return ast.unparse(node) if hasattr(ast, 'unparse') else ""
```

#### Task 3.2: Enhance Command Injection Detector with AST
**Time**: 2 days

Update existing detector to use AST analysis for more accurate detection.

#### Task 3.3: Add 5 More Detectors
**Time**: 1 week

1. `ArbitraryExecutionDetector` (eval/exec)
2. `OverlyPermissiveToolsDetector` (allow_all checks)
3. `DebugModeDetector` (debug flags in production)
4. `SQLInjectionDetector` (unsafe SQL in tools)
5. `TemplateInjectionDetector` (Jinja2/f-string injection)

---

## Milestone 3: Production Ready (Weeks 5-8)

### Features
- HTML reporter with interactive dashboard
- Supply chain scanning
- Container security analysis
- GitHub Action
- Full documentation
- 30+ detectors

---

## Testing Strategy

### For Each New Detector

```python
# tests/test_detectors/test_hardcoded_credentials.py

import pytest
from pathlib import Path
from safe_mcp_scanner.detectors.config.hardcoded_credentials import HardcodedCredentialsDetector


def test_detects_openai_key():
    """Test detection of OpenAI API key."""
    config_content = '''
    {
      "env": {
        "OPENAI_API_KEY": "sk-proj-abc123"
      }
    }
    '''
    findings = detector.analyze_string(config_content)
    assert len(findings) == 1
    assert "openai" in findings[0].title.lower()


def test_ignores_env_variable_reference():
    """Test that env variable references are not flagged."""
    config_content = '''
    {
      "env": {
        "OPENAI_API_KEY": "${OPENAI_API_KEY}"
      }
    }
    '''
    findings = detector.analyze_string(config_content)
    assert len(findings) == 0


def test_detects_multiple_secrets():
    """Test detection of multiple different secrets."""
    config_content = '''
    {
      "env": {
        "OPENAI_API_KEY": "sk-proj-abc123",
        "ANTHROPIC_API_KEY": "sk-ant-xyz789"
      }
    }
    '''
    findings = detector.analyze_string(config_content)
    assert len(findings) == 2
```

---

## Success Criteria

### Milestone 1 (Week 2)
- ✅ SARIF reporter works
- ✅ Text reporter works
- ✅ Documentation is honest about capabilities
- ✅ 3 new detectors implemented
- ✅ All reporters have tests
- ✅ Can find real vulnerabilities in sample MCP configs

### Milestone 2 (Week 4)
- ✅ AST analysis working
- ✅ 8 total detectors
- ✅ Enhanced command injection detection
- ✅ Test coverage > 80%

### Milestone 3 (Week 8)
- ✅ Production-ready scanner
- ✅ 30+ detectors
- ✅ HTML reporter
- ✅ Supply chain scanning
- ✅ GitHub Action
- ✅ Real-world usage examples

---

## Immediate Next Steps (This Week)

1. **Day 1-2**: Implement SARIF reporter
2. **Day 3**: Implement Text reporter
3. **Day 4**: Update all documentation
4. **Day 5**: Implement Hardcoded Credentials detector
5. **Day 6-7**: Test everything, write examples

**By end of week**: Working scanner with 3 reporters and 4 detectors

---

## How to Track Progress

Create issues for each task:
- [ ] #1: Implement SARIF Reporter
- [ ] #2: Implement Text Reporter
- [ ] #3: Update Documentation
- [ ] #4: Hardcoded Credentials Detector
- [ ] #5: Path Traversal Detector
- [ ] #6: Insecure Transport Detector
- [ ] #7: Python AST Analyzer

Use GitHub Project board with columns:
- 📋 Backlog
- 🚧 In Progress
- 👀 Review
- ✅ Done

---

## Questions?

**Q: Should we keep the SAFE-MCP framework reference?**
A: Only if it's real and maintained. If not, drop it and create our own MCP-specific taxonomy.

**Q: What about the 77 techniques promise?**
A: Remove it. Be honest: "Growing library of MCP-specific detectors"

**Q: Keep MITRE ATT&CK mapping?**
A: Optional metadata only. Don't force the mapping for MCP-specific issues.

**Q: What's the MVP?**
A: Working scanner with 10 solid detectors, 3 output formats, honest docs.
