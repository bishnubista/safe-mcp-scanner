# SAFE-MCP Scanner Architecture

This document describes the technical architecture and design decisions for the SAFE-MCP Scanner.

## Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Core Components](#core-components)
- [Data Flow](#data-flow)
- [Plugin Architecture](#plugin-architecture)
- [Detection Engine Design](#detection-engine-design)
- [Reporting System](#reporting-system)
- [Configuration Management](#configuration-management)
- [Performance Considerations](#performance-considerations)
- [Security Considerations](#security-considerations)
- [Extension Points](#extension-points)

## Overview

SAFE-MCP Scanner follows a modular, plugin-based architecture designed for:
- **Extensibility**: Easy addition of new detection techniques
- **Performance**: Efficient scanning of large codebases
- **Maintainability**: Clear separation of concerns
- **Testability**: Isolated components for unit testing
- **Standards Compliance**: SARIF output and MITRE ATT&CK integration

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CLI Interface                           │
│                      (cli.py)                               │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                 Scanner Orchestrator                        │
│                   (scanner.py)                              │
└─────────────────────┬───────────────────────────────────────┘
                      │
         ┌────────────┼────────────┐
         │            │            │
┌────────┴─────┐ ┌────┴──────┐ ┌──┴────────┐
│  Detectors   │ │Techniques │ │ Reporters │
│              │ │           │ │           │
│ ┌──────────┐ │ │ ┌───────┐ │ │ ┌───────┐ │
│ │AST       │ │ │ │T-1001 │ │ │ │ JSON  │ │
│ │Analyzer  │ │ │ │T-1101 │ │ │ │ SARIF │ │
│ │          │ │ │ │T-1201 │ │ │ │ HTML  │ │
│ └──────────┘ │ │ │  ...  │ │ │ └───────┘ │
│              │ │ └───────┘ │ │           │
│ ┌──────────┐ │ └───────────┘ └───────────┘
│ │Pattern   │ │
│ │Matcher   │ │
│ └──────────┘ │
│              │
│ ┌──────────┐ │
│ │Config    │ │
│ │Analyzer  │ │
│ └──────────┘ │
└──────────────┘
```

## Core Components

### 1. CLI Interface (`src/safe_mcp_scanner/cli.py`)
- **Purpose**: Command-line interface using Click framework
- **Responsibilities**:
  - Parse command-line arguments
  - Validate input parameters
  - Initialize scanner with configuration
  - Handle output formatting and display

### 2. Scanner Orchestrator (`src/safe_mcp_scanner/scanner.py`)
- **Purpose**: Main scanning logic coordinator
- **Responsibilities**:
  - Manage scanning workflow
  - Coordinate detector and technique execution
  - Aggregate findings from all sources
  - Handle error recovery and logging

### 3. Detectors (`src/safe_mcp_scanner/detectors/`)
- **Purpose**: Core analysis engines
- **Components**:
  - `BaseDetector`: Abstract base class for all detectors
  - `ASTAnalyzer`: Python/JavaScript AST parsing
  - `PatternMatcher`: Regex-based pattern detection
  - `ConfigAnalyzer`: JSON/YAML configuration analysis
  - `PackageAnalyzer`: Dependency and supply chain analysis

### 4. Techniques (`src/safe_mcp_scanner/techniques/`)
- **Purpose**: SAFE-MCP technique implementations
- **Structure**: One module per technique (e.g., `safe_t1001.py`)
- **Base Class**: `BaseTechnique` with standard interface

### 5. Reporters (`src/safe_mcp_scanner/reporters/`)
- **Purpose**: Output formatting and generation
- **Components**:
  - `JSONReporter`: Structured JSON output
  - `SARIFReporter`: SARIF format for tool integration
  - `HTMLReporter`: Human-readable reports
  - `ConsoleReporter`: Terminal output

## Data Flow

```
Input Files/Config
        │
        ▼
┌───────────────┐
│  File System  │
│   Discovery   │
└───────┬───────┘
        │
        ▼
┌───────────────┐    ┌─────────────────┐
│   Detectors   │◄───┤   Techniques    │
│   Execute     │    │   Registry      │
└───────┬───────┘    └─────────────────┘
        │
        ▼
┌───────────────┐
│   Finding     │
│ Aggregation   │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│   Reporters   │
│   Generate    │
└───────┬───────┘
        │
        ▼
   Output Files
```

### Data Models

#### Finding
```python
@dataclass
class Finding:
    technique_id: str
    technique_name: str
    tactic: str
    severity: Severity
    confidence: float
    file_path: Path
    line_number: Optional[int]
    description: str
    mitigation: str
    mitre_attack_id: Optional[str]
    evidence: Dict[str, Any]
```

#### ScanResult
```python
@dataclass
class ScanResult:
    scan_id: str
    timestamp: datetime
    target_path: Path
    findings: List[Finding]
    summary: ScanSummary
    metadata: ScanMetadata
```

## Plugin Architecture

### Technique Registration
Techniques are automatically discovered and registered using a decorator pattern:

```python
from safe_mcp_scanner.core.registry import register_technique

@register_technique("SAFE-T1001")
class MaliciousDescriptionDetector(BaseTechnique):
    def scan(self, target: ScanTarget) -> List[Finding]:
        # Implementation
        pass
```

### Detector Interface
```python
class BaseDetector(ABC):
    @abstractmethod
    def can_analyze(self, target: ScanTarget) -> bool:
        """Check if detector can analyze the target."""
        
    @abstractmethod
    def analyze(self, target: ScanTarget) -> AnalysisResult:
        """Analyze the target and return results."""
```

## Detection Engine Design

### Multi-Stage Analysis
1. **File Discovery**: Identify relevant files and configurations
2. **Static Analysis**: AST parsing and code structure analysis
3. **Pattern Matching**: Regex and string pattern detection
4. **Configuration Analysis**: JSON/YAML structure and content analysis
5. **Cross-Reference Analysis**: Correlation between different file types

### Technique Implementation Pattern
```python
class BaseTechnique:
    technique_id: str
    technique_name: str
    tactic: str
    mitre_attack_ids: List[str]
    
    def __init__(self, config: TechniqueConfig):
        self.config = config
        self.detectors = self._get_required_detectors()
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        findings = []
        for detector in self.detectors:
            if detector.can_analyze(target):
                results = detector.analyze(target)
                findings.extend(self._process_results(results))
        return findings
```

## Reporting System

### Report Generation Pipeline
```
Findings → Report Builder → Template Engine → Output Writer
```

### SARIF Integration
- Maps SAFE-MCP techniques to SARIF rules
- Includes remediation guidance
- Supports tool integration metadata

### Report Templates
- Jinja2 templates for HTML reports
- JSON schema validation for structured output
- SARIF schema compliance

## Configuration Management

### Configuration Hierarchy
1. **Default Config**: Built-in defaults
2. **System Config**: `/etc/safe-mcp-scanner/config.yaml`
3. **User Config**: `~/.config/safe-mcp-scanner/config.yaml`
4. **Project Config**: `.safe-mcp-scanner.yaml`
5. **Command Line**: CLI arguments (highest priority)

### Configuration Schema
```yaml
# .safe-mcp-scanner.yaml
scan:
  techniques:
    enabled: ["SAFE-T1001", "SAFE-T1101"]
    disabled: []
  severity:
    min_level: "medium"
    fail_on: ["high", "critical"]
  
output:
  format: "json"
  file: "scan-results.json"
  verbose: false

detectors:
  ast_analyzer:
    timeout_seconds: 30
    max_file_size_mb: 10
  pattern_matcher:
    case_sensitive: false
    multiline: true
```

## Performance Considerations

### Scalability Features
- **Parallel Processing**: Multi-threaded file analysis
- **Memory Management**: Streaming for large files
- **Caching**: Detection result caching
- **Incremental Scanning**: Only scan changed files

### Performance Optimizations
- **Early Termination**: Stop on critical findings (configurable)
- **File Filtering**: Skip non-relevant files
- **Lazy Loading**: Load detectors and techniques on demand
- **Progress Tracking**: Real-time progress reporting

### Resource Limits
```python
DEFAULT_LIMITS = {
    "max_file_size": 50 * 1024 * 1024,  # 50MB
    "max_files": 10000,
    "timeout_seconds": 300,
    "max_memory_mb": 1024
}
```

## Security Considerations

### Defensive Design
- **Input Validation**: All inputs validated and sanitized
- **Path Traversal Protection**: Secure file path handling
- **Resource Limits**: Prevent DoS through resource exhaustion
- **Privilege Separation**: Minimal required permissions

### Secure Defaults
- **Safe Execution**: No code execution by default
- **Output Sanitization**: Prevent injection in reports
- **Logging Safety**: No sensitive data in logs
- **Error Handling**: Fail securely on errors

## Extension Points

### Adding New Techniques
1. Implement `BaseTechnique` interface
2. Register with `@register_technique` decorator
3. Add tests in `tests/techniques/`
4. Update documentation

### Custom Detectors
1. Extend `BaseDetector` class
2. Register in detector registry
3. Configure in technique requirements

### Output Formats
1. Implement `BaseReporter` interface
2. Register in reporter registry
3. Add CLI option for format

### Integration Points
- **CI/CD**: Exit codes and threshold configuration
- **IDEs**: SARIF output for integration
- **SIEM**: Structured logging and alerts
- **APIs**: JSON output for programmatic access

## Future Architecture Considerations

### Planned Enhancements
- **Real-time Monitoring**: File system watching
- **Distributed Scanning**: Multi-node scanning
- **Machine Learning**: Pattern learning from findings
- **API Server**: REST API for scan orchestration

### Backwards Compatibility
- **Versioned APIs**: Maintain compatibility across versions
- **Migration Tools**: Automatic config migration
- **Deprecation Policy**: Clear deprecation timeline

This architecture supports the project's goals of comprehensive MCP security scanning while maintaining extensibility and performance.