# Installation Guide

This guide covers all methods for installing and setting up SAFE-MCP Scanner.

## Requirements

### System Requirements
- **Python**: 3.9 or higher
- **Operating System**: Linux, macOS, Windows
- **Memory**: 512MB RAM minimum, 2GB recommended
- **Disk Space**: 100MB for installation, additional space for scan results

### Python Environment
We recommend using a virtual environment to avoid dependency conflicts:

```bash
# Check Python version
python --version  # Should be 3.9 or higher

# Create virtual environment (optional but recommended)
python -m venv safe-mcp-env
source safe-mcp-env/bin/activate  # On Windows: safe-mcp-env\Scripts\activate
```

## Installation Methods

### Method 1: uv Installation (Fastest)

[uv](https://github.com/astral-sh/uv) is a fast Python package manager written in Rust:

```bash
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone https://github.com/your-org/safe-mcp-scanner.git
cd safe-mcp-scanner

# Install dependencies
uv sync

# Run the scanner
uv run safe-mcp-scan --version
```

### Method 2: PyPI Installation (Traditional)

```bash
# Install from PyPI
pip install safe-mcp-scanner

# Verify installation
safe-mcp-scan --version
```

### Method 3: pipx Installation (Isolated)

[pipx](https://pipxproject.github.io/pipx/) installs the tool in an isolated environment:

```bash
# Install pipx if not already installed
python -m pip install --user pipx
python -m pipx ensurepath

# Install safe-mcp-scanner
pipx install safe-mcp-scanner

# Verify installation
safe-mcp-scan --version
```

### Method 4: Development Installation

For contributors or users who want the latest features:

```bash
# Clone the repository
git clone https://github.com/your-org/safe-mcp-scanner.git
cd safe-mcp-scanner

# Using uv (recommended for development)
uv sync --dev
uv run safe-mcp-scan --version

# Or using pip
pip install -e .
pip install -e ".[dev]"  # With dev dependencies
safe-mcp-scan --version
```

### Method 5: Docker Installation

Run the scanner in a containerized environment:

```bash
# Pull the Docker image
docker pull your-org/safe-mcp-scanner:latest

# Run a scan
docker run --rm -v $(pwd):/scan your-org/safe-mcp-scanner:latest scan /scan

# Create an alias for easier use
echo 'alias safe-mcp-scan="docker run --rm -v \$(pwd):/scan your-org/safe-mcp-scanner:latest"' >> ~/.bashrc
source ~/.bashrc
```

### Method 6: Binary Downloads

Pre-built binaries are available for major platforms:

1. Go to [Releases](https://github.com/your-org/safe-mcp-scanner/releases)
2. Download the appropriate binary for your platform
3. Extract and add to your PATH

```bash
# Linux/macOS
wget https://github.com/your-org/safe-mcp-scanner/releases/download/v1.0.0/safe-mcp-scanner-linux-x64.tar.gz
tar -xzf safe-mcp-scanner-linux-x64.tar.gz
sudo mv safe-mcp-scan /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/your-org/safe-mcp-scanner/releases/download/v1.0.0/safe-mcp-scanner-windows-x64.zip" -OutFile "safe-mcp-scanner.zip"
Expand-Archive -Path "safe-mcp-scanner.zip" -DestinationPath "C:\Program Files\safe-mcp-scanner"
# Add C:\Program Files\safe-mcp-scanner to your PATH
```

## Post-Installation Setup

### Configuration Directory

The scanner creates configuration files in standard locations:

```bash
# Linux/macOS
~/.config/safe-mcp-scanner/

# Windows
%APPDATA%\safe-mcp-scanner\

# You can also use a project-specific config
.safe-mcp-scanner.yaml  # In your project directory
```

### Initial Configuration

Create a basic configuration file:

```bash
# Generate default configuration
safe-mcp-scan config init

# Edit the configuration
safe-mcp-scan config edit
```

### Verify Installation

Run a test scan to verify everything is working:

```bash
# Test with built-in examples
safe-mcp-scan scan --help

# Run a basic scan on the current directory
safe-mcp-scan scan . --output console

# Check scanner status
safe-mcp-scan doctor
```

## IDE Integration

### VS Code Integration

Install the SARIF Viewer extension for VS Code to view scan results:

1. Install the "SARIF Viewer" extension
2. Run a scan with SARIF output: `safe-mcp-scan scan /path --output sarif --file results.sarif`
3. Open the SARIF file in VS Code

### Other IDEs

Most modern IDEs support SARIF format. Consult your IDE's documentation for SARIF integration.

## Troubleshooting

### Common Installation Issues

#### Python Version Issues
```bash
# Error: Python version too old
# Solution: Upgrade Python or use pyenv

# Install pyenv (macOS)
brew install pyenv
pyenv install 3.11
pyenv global 3.11

# Install pyenv (Linux)
curl https://pyenv.run | bash
pyenv install 3.11
pyenv global 3.11
```

#### Permission Issues
```bash
# Error: Permission denied
# Solution: Use --user flag or virtual environment

pip install --user safe-mcp-scanner

# Or create virtual environment
python -m venv venv
source venv/bin/activate
pip install safe-mcp-scanner
```

#### Dependency Conflicts
```bash
# Error: Dependency version conflicts
# Solution: Use virtual environment or pipx

# Create clean environment
python -m venv clean-env
source clean-env/bin/activate
pip install safe-mcp-scanner

# Or use pipx for isolation
pipx install safe-mcp-scanner
```

#### Network Issues
```bash
# Error: Can't connect to PyPI
# Solution: Use alternative index or offline installation

# Use alternative index
pip install -i https://pypi.org/simple/ safe-mcp-scanner

# Or download wheel manually
wget https://pypi.org/packages/.../safe_mcp_scanner-1.0.0-py3-none-any.whl
pip install safe_mcp_scanner-1.0.0-py3-none-any.whl
```

### Diagnostic Commands

```bash
# Check system requirements
safe-mcp-scan doctor

# Verify technique loading
safe-mcp-scan techniques list

# Test configuration
safe-mcp-scan config validate

# Debug mode
safe-mcp-scan scan /path --debug --verbose
```

### Platform-Specific Issues

#### macOS
```bash
# Homebrew installation
brew tap your-org/safe-mcp-scanner
brew install safe-mcp-scanner

# Gatekeeper issues
xattr -d com.apple.quarantine /usr/local/bin/safe-mcp-scan
```

#### Windows
```powershell
# Windows Subsystem for Linux (WSL)
wsl --install
wsl
pip install safe-mcp-scanner

# PowerShell execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### Linux
```bash
# Ubuntu/Debian dependencies
sudo apt update
sudo apt install python3.9 python3.9-venv python3.9-pip

# CentOS/RHEL dependencies
sudo yum install python39 python39-pip python39-venv

# Alpine Linux
sudo apk add python3 python3-dev py3-pip
```

## Updating

### uv Updates
```bash
# Update with uv
cd safe-mcp-scanner
git pull origin main
uv sync
```

### PyPI Updates
```bash
# Check current version
safe-mcp-scan --version

# Update to latest version
pip install --upgrade safe-mcp-scanner

# Update with pipx
pipx upgrade safe-mcp-scanner
```

### Development Updates
```bash
cd safe-mcp-scanner
git pull origin main

# With uv
uv sync --dev

# With pip
pip install -e .
```

### Docker Updates
```bash
docker pull your-org/safe-mcp-scanner:latest
```

## Uninstalling

### PyPI Uninstall
```bash
pip uninstall safe-mcp-scanner
```

### pipx Uninstall
```bash
pipx uninstall safe-mcp-scanner
```

### Docker Cleanup
```bash
docker rmi your-org/safe-mcp-scanner:latest
```

### Complete Cleanup
```bash
# Remove configuration files
rm -rf ~/.config/safe-mcp-scanner/

# Remove cache files
rm -rf ~/.cache/safe-mcp-scanner/

# Windows
rmdir /s "%APPDATA%\safe-mcp-scanner"
```

## Getting Help

- 📖 **Documentation**: [docs/README.md](../README.md)
- 🐛 **Issues**: [GitHub Issues](https://github.com/your-org/safe-mcp-scanner/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/your-org/safe-mcp-scanner/discussions)
- 📧 **Support**: support@your-org.com