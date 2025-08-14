# SAFE-MCP Scanner

A comprehensive vulnerability scanner for MCP (Model Context Protocol) servers implementing the [SAFE-MCP framework](https://github.com/fkautz/safe-mcp).

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Scanner](https://img.shields.io/badge/security-scanner-red.svg)](https://github.com/fkautz/safe-mcp)

## Overview

SAFE-MCP Scanner is a defensive security tool that identifies vulnerabilities in MCP server implementations by detecting 77+ documented attack techniques across 14 tactical categories. Built upon the SAFE-MCP framework, it adapts MITRE ATT&CK methodology specifically for MCP environments.

## Features

- 🔍 **Comprehensive Detection**: 77+ attack techniques across 14 SAFE-MCP tactical categories
- 🏗️ **Multiple Analysis Methods**: Static code analysis, configuration scanning, pattern matching
- 📊 **Rich Reporting**: JSON, SARIF, HTML output formats with MITRE ATT&CK correlation
- 🚀 **CI/CD Ready**: Exit codes, thresholds, and automated scanning capabilities
- 🔧 **Extensible**: Plugin-based architecture for custom detection rules
- 📦 **Multi-Format**: Supports Python, JavaScript, JSON, YAML, Docker configurations

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

## Supported Detection Categories

### Initial Access (SAFE-T1001-T1008)
- Malicious Tool Descriptions
- Supply Chain Compromise
- Trojanized MCP Packages
- Public Endpoint Exploitation

### Execution (SAFE-T1101-T1106)
- Command Injection
- Tool Poisoning
- Prompt Injection via Parameters
- Over-Privileged Tool Abuse

### Credential Access (SAFE-T1201-T1207)
- OAuth Token Theft
- Environment Variable Harvesting
- Configuration File Credential Theft
- Session Hijacking

### And 11 Additional Categories
- Persistence
- Defense Evasion
- Discovery
- Collection
- Command and Control
- Exfiltration
- Impact
- Plus more...

## Configuration Files Analyzed

- `claude_desktop_config.json` - Claude Desktop MCP configurations
- `mcp_config.json` - General MCP server configurations
- `.mcp/` directories - MCP project folders
- Docker Compose and Kubernetes manifests
- Python/JavaScript MCP server implementations

## Output Formats

### JSON Report
```json
{
  "scan_summary": {
    "total_findings": 12,
    "high_severity": 3,
    "techniques_detected": ["SAFE-T1001", "SAFE-T1101"]
  },
  "findings": [...]
}
```

### SARIF Report
Standards-compliant SARIF output for IDE integration and security tools.

### HTML Report
Rich interactive reports with technique details and remediation guidance.

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