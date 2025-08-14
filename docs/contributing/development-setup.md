# Development Environment Setup

This guide will help you set up a development environment for contributing to SAFE-MCP Scanner.

## Prerequisites

### Required Software
- **Python 3.9+**: For running and testing the scanner
- **Git**: For version control
- **Make** (optional): For using Makefile commands
- **Docker** (optional): For containerized testing

### Recommended Tools
- **VS Code** or **PyCharm**: IDE with Python support
- **pyenv**: Python version management
- **pipx**: Isolated Python application installation
- **GitHub CLI**: For easier GitHub operations

## Quick Setup

### 1. Clone the Repository
```bash
# Fork the repository on GitHub first, then clone your fork
git clone https://github.com/YOUR_USERNAME/safe-mcp-scanner.git
cd safe-mcp-scanner

# Add upstream remote
git remote add upstream https://github.com/your-org/safe-mcp-scanner.git
```

### 2. Set Up Python Environment
```bash
# Option A: Using venv (built-in)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Option B: Using pyenv (recommended)
pyenv install 3.11.0
pyenv virtualenv 3.11.0 safe-mcp-scanner
pyenv activate safe-mcp-scanner

# Option C: Using conda
conda create -n safe-mcp-scanner python=3.11
conda activate safe-mcp-scanner
```

### 3. Install Development Dependencies
```bash
# Install the package in editable mode with dev dependencies
pip install -e ".[dev]"

# Or install from requirements files
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 4. Install Pre-commit Hooks
```bash
# Install pre-commit hooks for code quality
pre-commit install

# Test the hooks
pre-commit run --all-files
```

### 5. Verify Setup
```bash
# Run tests to verify everything works
pytest

# Check code quality
make lint  # or run black, ruff, mypy manually

# Test the CLI
safe-mcp-scan --help
```

## Detailed Setup Instructions

### Development Dependencies

The development environment includes these key tools:

```toml
# pyproject.toml [project.optional-dependencies]
dev = [
    # Testing
    "pytest>=7.0.0",
    "pytest-cov>=4.0.0",
    "pytest-mock>=3.10.0",
    "pytest-xdist>=3.0.0",
    
    # Code Quality
    "black>=23.0.0",
    "ruff>=0.1.0",
    "mypy>=1.0.0",
    "pre-commit>=3.0.0",
    
    # Documentation
    "mkdocs>=1.5.0",
    "mkdocs-material>=9.0.0",
    
    # Development Tools
    "ipython>=8.0.0",
    "ipdb>=0.13.0",
]
```

### IDE Configuration

#### VS Code Setup
Create `.vscode/settings.json`:

```json
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.flake8Enabled": false,
    "python.linting.mypyEnabled": true,
    "python.formatting.provider": "black",
    "python.formatting.blackArgs": ["--line-length=88"],
    "python.testing.pytestEnabled": true,
    "python.testing.pytestArgs": ["tests/"],
    "[python]": {
        "editor.formatOnSave": true,
        "editor.codeActionsOnSave": {
            "source.organizeImports": true
        }
    }
}
```

Install recommended extensions:
```bash
# Install VS Code extensions
code --install-extension ms-python.python
code --install-extension ms-python.black-formatter
code --install-extension ms-python.mypy-type-checker
code --install-extension charliermarsh.ruff
```

#### PyCharm Setup
1. Open the project in PyCharm
2. Configure Python interpreter: `Settings > Python Interpreter > Add > Existing environment`
3. Enable these inspections:
   - PEP 8 coding style violation
   - Type checker compatible issues
   - Unused imports/variables

### Make Commands

We provide a Makefile for common development tasks:

```makefile
# Makefile
.PHONY: help install test lint format clean docs

help:
	@echo "Available commands:"
	@echo "  install     Install development dependencies"
	@echo "  test        Run all tests"
	@echo "  lint        Run code quality checks"
	@echo "  format      Format code with black"
	@echo "  clean       Clean build artifacts"
	@echo "  docs        Build documentation"

install:
	pip install -e ".[dev]"
	pre-commit install

test:
	pytest -v --cov=safe_mcp_scanner --cov-report=html

lint:
	black --check src/ tests/
	ruff check src/ tests/
	mypy src/

format:
	black src/ tests/
	ruff check --fix src/ tests/

clean:
	rm -rf build/ dist/ *.egg-info/
	rm -rf .coverage htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +

docs:
	mkdocs build
```

## Development Workflow

### 1. Create Feature Branch
```bash
# Sync with upstream
git fetch upstream
git checkout main
git merge upstream/main

# Create feature branch
git checkout -b feature/your-feature-name
```

### 2. Development Loop
```bash
# Make your changes
# ...

# Run tests frequently
pytest tests/test_your_feature.py -v

# Check code quality
make lint

# Format code
make format

# Run full test suite
make test
```

### 3. Pre-commit Checks
```bash
# Pre-commit hooks run automatically on commit
git add .
git commit -m "feat: add new feature"

# Or run manually
pre-commit run --all-files
```

### 4. Submit Pull Request
```bash
# Push to your fork
git push origin feature/your-feature-name

# Create PR using GitHub CLI (optional)
gh pr create --title "Add new feature" --body "Description of changes"
```

## Testing Environment

### Running Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=safe_mcp_scanner

# Run specific test file
pytest tests/test_scanner.py

# Run specific test function
pytest tests/test_scanner.py::test_scan_directory

# Run tests in parallel
pytest -n auto

# Run tests with debugging
pytest --pdb

# Generate HTML coverage report
pytest --cov=safe_mcp_scanner --cov-report=html
open htmlcov/index.html
```

### Test Categories
- **Unit Tests**: `tests/unit/` - Test individual functions
- **Integration Tests**: `tests/integration/` - Test component interactions
- **End-to-End Tests**: `tests/e2e/` - Test complete workflows
- **Performance Tests**: `tests/performance/` - Benchmark performance

### Test Data
Test fixtures are in `tests/fixtures/`:
- `vulnerable_mcp_server/` - MCP server with known vulnerabilities
- `secure_mcp_server/` - Properly secured MCP server
- `config_samples/` - Various MCP configuration files
- `test_files/` - Sample files for testing detection

## Code Quality Standards

### Code Formatting
We use **Black** for consistent code formatting:
```bash
# Format all Python files
black src/ tests/

# Check formatting without making changes
black --check src/ tests/

# Format specific file
black src/safe_mcp_scanner/scanner.py
```

### Linting
We use **Ruff** for fast Python linting:
```bash
# Lint all files
ruff check src/ tests/

# Auto-fix issues where possible
ruff check --fix src/ tests/

# Check specific rules
ruff check --select E,W src/
```

### Type Checking
We use **MyPy** for static type checking:
```bash
# Type check all files
mypy src/

# Type check specific file
mypy src/safe_mcp_scanner/scanner.py

# Generate type checking report
mypy --html-report mypy-report src/
```

### Import Organization
We use **isort** for consistent import ordering:
```bash
# Sort imports in all files
isort src/ tests/

# Check import sorting
isort --check-only src/ tests/
```

## Debugging

### Local Debugging
```bash
# Run with debug output
safe-mcp-scan scan /path --debug --verbose

# Use Python debugger
python -m pdb -m safe_mcp_scanner.cli scan /path

# Use ipdb for better debugging experience
pip install ipdb
python -c "import ipdb; ipdb.set_trace(); from safe_mcp_scanner.cli import main; main()"
```

### Test Debugging
```bash
# Debug failing tests
pytest --pdb tests/test_failing.py

# Debug specific test
pytest --pdb -k test_specific_function

# Use ipdb in tests
# Add this to your test:
# import ipdb; ipdb.set_trace()
```

## Documentation Development

### Building Documentation
```bash
# Install documentation dependencies
pip install -e ".[docs]"

# Build documentation
mkdocs build

# Serve documentation locally
mkdocs serve
# Open http://localhost:8000
```

### Documentation Standards
- Use **Markdown** for all documentation
- Follow **Google docstring** style for Python code
- Include **examples** in all documentation
- Keep **line length** under 88 characters
- Use **relative links** for internal references

## Docker Development

### Development Container
```dockerfile
# Dockerfile.dev
FROM python:3.11-slim

WORKDIR /app
COPY requirements*.txt ./
RUN pip install -r requirements-dev.txt

COPY . .
RUN pip install -e .

CMD ["bash"]
```

```bash
# Build development image
docker build -f Dockerfile.dev -t safe-mcp-scanner:dev .

# Run development container
docker run -it --rm -v $(pwd):/app safe-mcp-scanner:dev

# Run tests in container
docker run --rm -v $(pwd):/app safe-mcp-scanner:dev pytest
```

## Common Issues and Solutions

### Import Errors
```bash
# Error: Module not found
# Solution: Install in editable mode
pip install -e .

# Error: Relative imports
# Solution: Run from project root
cd safe-mcp-scanner
python -m safe_mcp_scanner.cli
```

### Test Failures
```bash
# Error: Fixture not found
# Solution: Check conftest.py files

# Error: Path issues in tests
# Solution: Use fixtures for file paths
```

### Performance Issues
```bash
# Profile code performance
python -m cProfile -o profile.stats -m safe_mcp_scanner.cli scan /path
python -c "import pstats; pstats.Stats('profile.stats').sort_stats('tottime').print_stats(20)"

# Memory profiling
pip install memory-profiler
python -m memory_profiler safe_mcp_scanner/cli.py
```

## Getting Help

- 📖 **Documentation**: [docs/README.md](../README.md)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/your-org/safe-mcp-scanner/discussions)
- 🐛 **Issues**: [GitHub Issues](https://github.com/your-org/safe-mcp-scanner/issues)
- 📧 **Development**: dev@your-org.com

## Next Steps

After setting up your development environment:

1. Read the [Architecture Overview](../../ARCHITECTURE.md)
2. Check the [Implementation Plan](../../IMPLEMENTATION.md)
3. Look at [open issues](https://github.com/your-org/safe-mcp-scanner/issues) for contribution opportunities
4. Join our [community discussions](https://github.com/your-org/safe-mcp-scanner/discussions)

Happy coding! 🚀