# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Python-based vulnerability scanner for MCP (Model Context Protocol) servers, implementing the SAFE-MCP framework from https://github.com/fkautz/safe-mcp. The scanner detects 77 documented attack techniques across 14 tactical categories, providing comprehensive security analysis for MCP server implementations.

### SAFE-MCP Framework Foundation
The scanner is built upon the SAFE-MCP framework which:
- Adapts MITRE ATT&CK methodology specifically for MCP environments
- Documents adversary tactics, techniques, and procedures (TTPs) for MCP
- Provides actionable mitigations for each identified technique
- Maps techniques to corresponding MITRE ATT&CK frameworks
- Enables threat assessment, developer mitigations, compliance mapping, and red team testing

## Development Commands

### Using uv (Recommended)

This project uses `uv` for fast, reliable Python package management:

```bash
# Setup and installation
uv sync                             # Install dependencies from uv.lock
uv sync --dev                       # Install with dev dependencies
uv pip install -e .                 # Development install

# Running the scanner
uv run safe-mcp-scan scan /path/to/mcp/server
uv run safe-mcp-scan scan --config mcp_config.json --output sarif
uv run python -m safe_mcp_scanner.cli scan /path/to/mcp/server

# Testing
uv run pytest                       # Run all tests
uv run pytest tests/test_scanner.py # Run specific test file
uv run pytest -v                    # Verbose test output
uv run pytest --cov=safe_mcp_scanner # Run with coverage

# Code quality
uv run black src/                   # Format code
uv run ruff check src/              # Lint code
uv run mypy src/                    # Type checking
```

### Using pip (Alternative)

```bash
# Setup and installation
pip install -e .                    # Development install
pip install -e ".[dev]"             # Install with dev dependencies

# CLI usage
safe-mcp-scan scan /path/to/mcp/server
safe-mcp-scan scan --config mcp_config.json --output sarif
```

## Architecture Overview

The project follows a modular plugin-based design with these core components:

### Core Structure
```
src/safe_mcp_scanner/
├── cli.py              # CLI interface using Click
├── scanner.py          # Main scanning orchestrator
├── techniques/         # SAFE-MCP technique implementations
├── detectors/          # Detection engines (AST, pattern matching, config)
└── reporters/          # Output formatters (JSON, SARIF, HTML)
```

### Key Detection Areas
Based on the SAFE-MCP framework's 14 tactical categories:
- **Initial Access**: Malicious tool descriptions, supply chain compromise, trojanized packages
- **Execution**: Command injection, tool poisoning, prompt injection, over-privileged tools
- **Credential Access**: OAuth token theft, audience confusion, token forwarding, environment harvesting
- **Persistence**: Configuration tampering, backdoor installation, privilege escalation
- **Defense Evasion**: Log manipulation, security tool bypass, obfuscation techniques
- **Discovery**: System reconnaissance, network enumeration, credential discovery
- **Collection**: Data harvesting, screen capture, clipboard access
- **Command and Control**: C2 communication, tunneling, protocol abuse
- **Exfiltration**: Data theft, covert channels, automated collection
- **Impact**: Data destruction, defacement, denial of service

### Detection Methods
- **Static Code Analysis**: AST parsing for Python/JavaScript MCP servers
- **Configuration Analysis**: JSON/YAML MCP config scanning
- **Pattern Matching**: Regex-based malicious pattern detection
- **Package Analysis**: Supply chain vulnerability scanning
- **Container Security**: Dockerfile and image analysis

## Target Scan Configurations
- `claude_desktop_config.json` - Claude Desktop MCP configurations
- `mcp_config.json` - General MCP server configs
- `.mcp/` directories - MCP project folders
- Docker Compose and Kubernetes manifests with MCP services

## Development Priorities
1. Core scanner framework and CLI interface
2. High-impact techniques from SAFE-MCP framework:
   - Initial Access techniques (malicious tool descriptions, supply chain compromise)
   - Execution techniques (command injection, tool poisoning, over-privileged tools)
   - Credential Access techniques (OAuth theft, environment variable harvesting)
3. JSON/SARIF reporting with SAFE-MCP technique ID mapping
4. Configuration file analysis for MCP servers
5. Supply chain scanning for MCP package dependencies
6. Container security checks for MCP deployments
7. Advanced features and CI/CD integrations with MITRE ATT&CK correlation

## SAFE-MCP Integration
The scanner maps each detection to specific SAFE-MCP technique IDs, enabling:
- Standardized threat categorization using SAFE-MCP taxonomy
- Actionable mitigation recommendations from the framework
- Correlation with MITRE ATT&CK techniques for broader security context
- Regular updates as new techniques emerge in the MCP threat landscape

## Security Context
This is a **defensive security tool** designed to identify vulnerabilities in MCP servers. All detection patterns and techniques are focused on helping developers secure their MCP implementations against the attack techniques documented in the SAFE-MCP framework.