# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Python-based vulnerability scanner for MCP (Model Context Protocol) servers. Currently in **alpha (v0.1.0)**, the scanner focuses on detecting critical security vulnerabilities in MCP server implementations and configurations.

### Current Implementation Status

**Core Features (Complete):**
- ✅ Scanner architecture and orchestration
- ✅ CLI interface with Click
- ✅ Configuration system (YAML/JSON)
- ✅ File discovery for MCP-specific files
- ✅ JSON reporter
- ✅ SARIF reporter (CI/CD integration)
- ✅ Text reporter (human-readable output)

**Active Detectors (2 working):**
- ✅ SAFE-T1001: Malicious Tool Descriptions (Prompt Security - High severity)
- ✅ SAFE-T1101: Command Injection (Code Execution - Critical severity)

**In Development:**
- 🚧 Hardcoded credentials detector
- 🚧 Path traversal detector
- 🚧 Insecure transport detector
- 🚧 Python AST analysis engine
- 🚧 JavaScript AST analysis engine

**Planned Features:**
- Supply chain vulnerability scanning
- Container security analysis (Dockerfile/K8s)
- HTML dashboard reporter
- Advanced data flow analysis
- 20+ additional MCP-specific detectors

See [REVISED_APPROACH.md](./REVISED_APPROACH.md) and [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) for detailed roadmap.

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

**Currently Implemented:**
- **Prompt Security** (SAFE-T1001): Malicious tool descriptions, credential phishing attempts
- **Code Execution** (SAFE-T1101): Command injection, unsafe subprocess calls

**In Development:**
- **Configuration Security**: Hardcoded credentials, insecure transport, debug mode
- **Data Access**: Path traversal, unrestricted file access, SQL injection
- **Supply Chain**: Vulnerable dependencies, package validation

**Planned Future Categories:**
- Persistence mechanisms
- Defense evasion techniques
- Discovery and reconnaissance
- Data collection methods
- Command and control
- Data exfiltration
- Impact and denial of service

### Detection Methods

**Currently Active:**
- ✅ **Pattern Matching**: Regex-based detection for known vulnerability patterns
- ✅ **Configuration Analysis**: JSON/YAML MCP config file parsing and validation
- ✅ **File Discovery**: MCP-specific file identification and categorization

**In Development:**
- 🚧 **AST Analysis**: Abstract Syntax Tree parsing for Python and JavaScript
- 🚧 **Semantic Analysis**: Context-aware code analysis for deeper insights

**Planned:**
- 📋 **Data Flow Analysis**: Track tainted data through code
- 📋 **Package Analysis**: Dependency vulnerability scanning
- 📋 **Container Security**: Dockerfile and image analysis

## Target Scan Configurations
- `claude_desktop_config.json` - Claude Desktop MCP configurations
- `mcp_config.json` - General MCP server configs
- `.mcp/` directories - MCP project folders
- Docker Compose and Kubernetes manifests with MCP services

## Development Priorities (Current Milestone)

**Milestone 1 - Fix the Foundation (In Progress):**
1. ✅ Core scanner framework and CLI interface (Complete)
2. ✅ JSON/SARIF/Text reporting (Complete)
3. 🚧 Hardcoded credentials detector (In Progress)
4. 🚧 Path traversal detector (In Progress)
5. 🚧 Insecure transport detector (Planned)
6. ✅ Documentation updates to reflect reality (Complete)

**Milestone 2 - Enhanced Detection (Next):**
1. Python AST analysis engine
2. JavaScript AST analysis engine
3. Expand to 10 total working detectors
4. Improve detection accuracy with semantic analysis

**Milestone 3 - Production Ready:**
1. Supply chain scanning for dependencies
2. Container security analysis
3. HTML dashboard reporter
4. GitHub Action for automated scanning
5. 30+ detectors across all MCP security categories

See [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) for detailed task breakdown.

## Detector Taxonomy

The scanner uses MCP-specific detector IDs rather than forcing MITRE ATT&CK mapping:

**Current Naming Convention:**
- `SAFE-T1001` through `SAFE-T1106`: Initial implementation (being migrated)
- Future detectors will use MCP-specific categories:
  - `MCP-CONFIG-xxx`: Configuration security issues
  - `MCP-EXEC-xxx`: Code execution vulnerabilities
  - `MCP-DATA-xxx`: Data access issues
  - `MCP-PROMPT-xxx`: Prompt security concerns
  - `MCP-SUPPLY-xxx`: Supply chain vulnerabilities
  - `MCP-NET-xxx`: Network security issues

This approach provides clearer categorization for MCP-specific vulnerabilities while maintaining compatibility with existing detectors.

## Security Context
This is a **defensive security tool** designed to identify vulnerabilities in MCP servers. All detection patterns and techniques are focused on helping developers secure their MCP implementations against the attack techniques documented in the SAFE-MCP framework.