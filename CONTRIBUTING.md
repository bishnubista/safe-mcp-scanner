# Contributing to SAFE-MCP Scanner

Thank you for your interest in contributing to SAFE-MCP Scanner! This document provides guidelines and information for contributors.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Code Style](#code-style)
- [Adding Detection Techniques](#adding-detection-techniques)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Security Vulnerability Reporting](#security-vulnerability-reporting)

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/safe-mcp-scanner.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Submit a pull request

## Development Environment

### Prerequisites
- Python 3.9 or higher
- Git
- uv (Python package manager) - [Installation guide](https://github.com/astral-sh/uv)
- A text editor or IDE (VS Code, PyCharm, etc.)

### Setup with uv (Recommended)
```bash
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone https://github.com/your-org/safe-mcp-scanner.git
cd safe-mcp-scanner

# Install dependencies
uv sync --dev

# Run the scanner
uv run safe-mcp-scan --help
```

### Alternative Setup with pip
```bash
# Clone the repository
git clone https://github.com/your-org/safe-mcp-scanner.git
cd safe-mcp-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"
```

### Development Tools
We use the following tools for development:

- **Black**: Code formatting
- **Ruff**: Linting and code quality
- **MyPy**: Type checking
- **Pytest**: Testing framework
- **Pre-commit**: Git hooks for code quality

```bash
# Install pre-commit hooks (with uv)
uv run pre-commit install

# Run code quality checks with uv
uv run black src/
uv run ruff check src/
uv run mypy src/

# Or without uv (if using pip)
black src/
ruff check src/
mypy src/
```

## Code Style

### Python Style Guidelines
- Follow PEP 8 with Black formatting
- Use type hints for all functions and methods
- Maximum line length: 88 characters (Black default)
- Use descriptive variable names
- Add docstrings for all public functions, classes, and modules

### Example:
```python
from typing import List, Dict, Optional
from pathlib import Path

def scan_mcp_config(
    config_path: Path,
    techniques: Optional[List[str]] = None
) -> Dict[str, List[str]]:
    """Scan MCP configuration file for vulnerabilities.
    
    Args:
        config_path: Path to the MCP configuration file
        techniques: Optional list of SAFE-MCP technique IDs to check
        
    Returns:
        Dictionary mapping technique IDs to found vulnerabilities
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config file is malformed
    """
    # Implementation here
    pass
```

### Commit Message Format
Use conventional commit format with DCO signoff:
```
type(scope): description

[optional body]

[optional footer]

Signed-off-by: Your Name <your.email@example.com>
```

Examples:
- `feat(detector): add SAFE-T1001 malicious description detection`
- `fix(cli): resolve output format selection bug`
- `docs(readme): update installation instructions`

### DCO (Developer Certificate of Origin)
All commits must be signed off to indicate that you agree to the [Developer Certificate of Origin](https://developercertificate.org/):

```bash
# Sign off your commits automatically
git commit -s -m "feat: add new detection technique"

# Or add signoff to existing commit
git commit --amend --signoff

# Configure git to always sign off
git config --global format.signoff true
```

The signoff certifies that you wrote the patch or have the right to pass it on as open-source.

## Adding Detection Techniques

### 1. Choose a SAFE-MCP Technique
Reference the [SAFE-MCP framework](https://github.com/fkautz/safe-mcp) to select a technique to implement.

### 2. Create Detection Module
Create a new file in `src/safe_mcp_scanner/techniques/`:

```python
# src/safe_mcp_scanner/techniques/safe_t1001.py
from typing import List, Dict, Any
from ..detectors.base import BaseDetector, Finding

class MaliciousDescriptionDetector(BaseDetector):
    """Detector for SAFE-T1001: Malicious Tool Descriptions."""
    
    technique_id = "SAFE-T1001"
    technique_name = "Malicious Tool Descriptions"
    tactic = "Initial Access"
    
    def scan(self, target: Any) -> List[Finding]:
        """Scan for malicious tool descriptions."""
        findings = []
        # Detection logic here
        return findings
```

### 3. Add Detection Patterns
Define patterns in the appropriate detector:

```python
MALICIOUS_PATTERNS = [
    r"<!--.*?-->",  # Hidden HTML comments
    r"\\u[0-9a-fA-F]{4}",  # Unicode escapes
    r"(ignore|disregard|forget).*(previous|above|instruction)",
]
```

### 4. Write Tests
Create comprehensive tests in `tests/test_techniques/`:

```python
# tests/test_techniques/test_safe_t1001.py
import pytest
from safe_mcp_scanner.techniques.safe_t1001 import MaliciousDescriptionDetector

def test_malicious_description_detection():
    detector = MaliciousDescriptionDetector()
    # Test cases here
    pass
```

### 5. Add Documentation
Update technique documentation in `docs/techniques/SAFE-T1001.md`.

## Testing

### Running Tests with uv
```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=safe_mcp_scanner

# Run specific test file
uv run pytest tests/test_scanner.py

# Run with verbose output
uv run pytest -v

# Run tests in parallel
uv run pytest -n auto
```

### Running Tests without uv
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=safe_mcp_scanner
```

### Test Requirements
- **Unit Tests**: Test individual functions and methods
- **Integration Tests**: Test component interactions
- **End-to-End Tests**: Test complete scanning workflows
- **Test Coverage**: Maintain >90% code coverage
- **Test Data**: Use fixtures in `tests/fixtures/`

### Test Categories
1. **Detector Tests**: Verify detection accuracy
2. **Scanner Tests**: Test scanning orchestration
3. **Reporter Tests**: Verify output formatting
4. **CLI Tests**: Test command-line interface
5. **Configuration Tests**: Test config file handling

## Documentation

### Types of Documentation
- **Code Documentation**: Docstrings and inline comments
- **User Documentation**: Usage guides and examples
- **Developer Documentation**: Architecture and implementation details
- **Technique Documentation**: SAFE-MCP technique descriptions

### Documentation Standards
- Use Google-style docstrings
- Include examples in documentation
- Update relevant docs with code changes
- Use Markdown for documentation files

## Pull Request Process

### Before Submitting
1. Ensure all commits are signed off (DCO requirement)
2. Run all code quality checks: `uv run black src/`, `uv run ruff check src/`, `uv run mypy src/`
3. Run all tests: `uv run pytest`
4. Update documentation if needed
5. Add tests for new functionality
6. Update CHANGELOG.md if applicable

### PR Checklist
- [ ] All commits are signed off (`Signed-off-by: Name <email>`)
- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] Added tests for new functionality
- [ ] Documentation updated
- [ ] SAFE-MCP technique IDs properly referenced
- [ ] Security implications considered
- [ ] Breaking changes documented

### Review Process
1. Automated checks must pass
2. At least one maintainer review required
3. Security-sensitive changes require security team review
4. Documentation changes reviewed for clarity
5. Performance impact assessed for large changes

## Issue Reporting

### Bug Reports
Include:
- Python version and OS
- Scanner version
- Full command executed
- Expected vs actual behavior
- Relevant log output
- Minimal reproduction case

### Feature Requests
Include:
- SAFE-MCP technique ID (if applicable)
- Use case description
- Proposed implementation approach
- Security considerations

### Issue Labels
- `bug`: Something isn't working
- `enhancement`: New feature request
- `technique`: New SAFE-MCP technique implementation
- `documentation`: Documentation improvements
- `security`: Security-related issues
- `performance`: Performance improvements

## Security Vulnerability Reporting

### Responsible Disclosure
- **Do not** open public issues for security vulnerabilities
- Email: security@your-org.com
- Encrypt with our PGP key (available on our website)
- Include detailed reproduction steps
- Allow reasonable time for patching before disclosure

### Security Review Process
1. Acknowledge receipt within 24 hours
2. Initial assessment within 72 hours
3. Regular updates on progress
4. Coordinated disclosure timeline
5. Credit in security advisory (if desired)

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you agree to uphold this code. Please report unacceptable behavior to conduct@your-org.com.

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation
- Conference presentations (with permission)

## Questions?

- Open a discussion in GitHub Discussions
- Join our community chat (link TBD)
- Email: contributors@your-org.com

Thank you for contributing to MCP security! 🔐