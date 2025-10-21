# SAFE-MCP Scanner

A practical vulnerability scanner for MCP (Model Context Protocol) servers, focused on detecting real security issues in MCP implementations.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Scanner](https://img.shields.io/badge/security-scanner-red.svg)](https://github.com/fkautz/safe-mcp)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)](https://github.com/bishnubista/safe-mcp-scanner)

## Overview

SAFE-MCP Scanner is a defensive security tool that identifies vulnerabilities in MCP server implementations. Currently in **alpha** with core detection capabilities for the most common MCP security issues.

## Current Status (v0.1.0 - Alpha)

### ✅ What Works Now

- **Command Injection Detection**: Finds unsafe subprocess calls and shell injection vulnerabilities in MCP tools
- **Malicious Tool Descriptions**: Detects suspicious patterns in tool descriptions that may be used for phishing
- **Multiple Output Formats**: JSON, SARIF (for CI/CD integration), and human-readable text reports
- **MCP Configuration Scanning**: Analyzes `claude_desktop_config.json`, `mcp_config.json`, and related files
- **Pattern-Based Detection**: Regex-based security pattern matching
- **Extensible Architecture**: Plugin-based system for adding custom detectors

### 🚧 Coming Soon

- Hardcoded credentials detection in configuration files
- Path traversal vulnerability detection
- Insecure transport (HTTP vs HTTPS) detection
- AST-based code analysis for Python and JavaScript
- Supply chain security scanning
- Container security analysis
- HTML dashboard reports

## Features

- 🔍 **Security-Focused**: Detects critical MCP vulnerabilities like command injection and credential exposure
- 📊 **CI/CD Ready**: SARIF output for GitHub Advanced Security, exit codes for pipeline integration
- 🎯 **Low False Positives**: Pattern-based detection with confidence scoring
- 🔧 **Extensible**: Plugin architecture for custom detection rules
- 📦 **MCP-Specific**: Understands MCP server structure and configuration formats

## Installation

### Using uv (Recommended)

```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and setup
git clone https://github.com/your-org/safe-mcp-scanner
cd safe-mcp-scanner
uv sync
```

### Using pip

```bash
# From PyPI (when released)
pip install safe-mcp-scanner

# Development installation
git clone https://github.com/your-org/safe-mcp-scanner
cd safe-mcp-scanner
pip install -e .
```

## Quick Start

### With uv

```bash
# Basic scanning
uv run safe-mcp-scan scan /path/to/mcp/server

# Scan with configuration
uv run safe-mcp-scan scan --config mcp_config.json

# Generate SARIF report
uv run safe-mcp-scan scan /path --output sarif --file report.sarif

# Filter by severity
uv run safe-mcp-scan scan /path --min-severity high

# CI/CD integration
uv run safe-mcp-scan scan /path --exit-code --max-high 0
```

### With pip

```bash
# Basic scanning
safe-mcp-scan scan /path/to/mcp/server

# Scan with configuration
safe-mcp-scan scan --config mcp_config.json

# Generate SARIF report
safe-mcp-scan scan /path --output sarif --file report.sarif

# Filter by severity
safe-mcp-scan scan /path --min-severity high

# CI/CD integration
safe-mcp-scan scan /path --exit-code --max-high 0
```

## Current Detectors

| Detector ID | Name | Category | Severity | Status |
|-------------|------|----------|----------|--------|
| SAFE-T1001 | Malicious Tool Descriptions | Prompt Security | High | ✅ Active |
| SAFE-T1101 | Command Injection | Code Execution | Critical | ✅ Active |

### Detector Details

**SAFE-T1001: Malicious Tool Descriptions**
- Detects suspicious patterns in MCP tool descriptions
- Identifies potential credential phishing attempts
- Scans JSON/YAML configuration files
- Example: Tool descriptions asking users for passwords or API keys

**SAFE-T1101: Command Injection**
- Detects unsafe subprocess execution with `shell=True`
- Finds dangerous use of `os.system()` and similar functions
- Identifies command injection via f-strings and string formatting
- Scans Python and JavaScript MCP server implementations

### Planned Detectors (Coming Soon)

See [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) for the full roadmap of upcoming detection capabilities.

## Configuration Files Analyzed

- `claude_desktop_config.json` - Claude Desktop MCP configurations
- `mcp_config.json` - General MCP server configurations
- `.mcp/` directories - MCP project folders
- Docker Compose and Kubernetes manifests
- Python/JavaScript MCP server implementations

## Output Formats

The scanner supports three output formats:

### 1. JSON Report (Default)
Structured JSON output with detailed findings, ideal for programmatic consumption:
```json
{
  "scan_summary": {
    "total_findings": 2,
    "by_severity": {
      "critical": 1,
      "high": 1
    },
    "scan_duration": 0.45
  },
  "findings": [
    {
      "technique_id": "SAFE-T1101",
      "severity": "critical",
      "message": "Command injection vulnerability detected",
      "file_path": "server.py",
      "line_number": 42,
      "recommendation": "Avoid using shell=True with user input"
    }
  ]
}
```

### 2. SARIF Report (CI/CD Integration)
Standards-compliant SARIF 2.1.0 output for GitHub Advanced Security and other security platforms:
```bash
safe-mcp-scan scan . --format sarif --output report.sarif
```

### 3. Text Report (Human-Readable)
Color-coded console output with clear summaries and recommendations:
```bash
safe-mcp-scan scan . --format text
```

Output example:
```
🔍 MCP Security Scan Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 Summary
  Total Findings: 2
  🔴 Critical: 1
  🟠 High: 1

🔴 CRITICAL: Command injection vulnerability detected
  └─ File: server.py:42
  └─ ID: SAFE-T1101

  💡 Recommendation:
    Avoid using shell=True with subprocess calls
```

## Development Status

This project is currently in active development. The core framework and detection engines are being implemented following the roadmap in [IMPLEMENTATION.md](./IMPLEMENTATION.md).

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines on:

- Setting up the development environment
- Implementing new detection techniques
- Writing tests
- Documentation standards

## Architecture

For detailed technical information, see [ARCHITECTURE.md](./ARCHITECTURE.md).

## Security Notice

This is a **defensive security tool** designed to help developers identify vulnerabilities in their MCP server implementations. All detection patterns are focused on improving security posture.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [SAFE-MCP Framework](https://github.com/fkautz/safe-mcp) - The security framework this scanner implements
- [Model Context Protocol](https://github.com/modelcontextprotocol) - Official MCP specification

## Acknowledgments

- Thanks to the SAFE-MCP framework authors for providing the security taxonomy
- Built with inspiration from MITRE ATT&CK methodology
- Community contributors and security researchers

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning systems.