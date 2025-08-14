# Examples and Use Cases

This directory contains practical examples and use cases for SAFE-MCP Scanner, demonstrating how to use the tool in various scenarios.

## Quick Start Examples

### Basic Directory Scan
```bash
# Scan current directory
safe-mcp-scan scan .

# Scan specific directory
safe-mcp-scan scan /path/to/mcp/server

# Scan with verbose output
safe-mcp-scan scan /path/to/mcp/server --verbose
```

### Configuration-Based Scanning
```bash
# Scan using MCP configuration file
safe-mcp-scan scan --config claude_desktop_config.json

# Scan with custom scanner configuration
safe-mcp-scan scan /path --config-file .safe-mcp-scanner.yaml
```

### Output Format Examples
```bash
# Generate JSON report
safe-mcp-scan scan /path --output json --file report.json

# Generate SARIF for IDE integration
safe-mcp-scan scan /path --output sarif --file results.sarif

# Generate HTML report
safe-mcp-scan scan /path --output html --file report.html

# Output to console with colors
safe-mcp-scan scan /path --output console --color
```

## Advanced Use Cases

### Technique-Specific Scanning
```bash
# Scan for specific techniques
safe-mcp-scan scan /path --techniques SAFE-T1001,SAFE-T1101,SAFE-T1201

# Scan by tactical category
safe-mcp-scan scan /path --tactic initial-access

# Exclude specific techniques
safe-mcp-scan scan /path --exclude SAFE-T1105,SAFE-T1106

# Scan only high-severity techniques
safe-mcp-scan scan /path --min-severity high
```

### CI/CD Integration Examples
```bash
# Fail build on critical findings
safe-mcp-scan scan /path --exit-code --max-critical 0

# Fail on any high-severity findings
safe-mcp-scan scan /path --exit-code --max-high 0 --max-critical 0

# Generate reports for multiple formats in CI
safe-mcp-scan scan /path \
  --output json --file ci-results.json \
  --output sarif --file ci-results.sarif \
  --exit-code --max-high 5
```

## Common Scanning Scenarios

### 1. New MCP Server Development
When developing a new MCP server, run comprehensive scans regularly:

```bash
# During development - quick scan
safe-mcp-scan scan src/ --min-severity medium --output console

# Pre-commit scan - comprehensive
safe-mcp-scan scan . --output json --file pre-commit-scan.json

# Pre-release scan - strict
safe-mcp-scan scan . --exit-code --max-medium 0 --max-high 0 --max-critical 0
```

### 2. Third-Party MCP Server Evaluation
When evaluating third-party MCP servers for security:

```bash
# Initial assessment
safe-mcp-scan scan vendor-mcp-server/ --output html --file vendor-assessment.html

# Focus on critical techniques
safe-mcp-scan scan vendor-mcp-server/ \
  --techniques SAFE-T1001,SAFE-T1101,SAFE-T1201,SAFE-T1002 \
  --output json --file vendor-critical.json

# Supply chain analysis
safe-mcp-scan scan vendor-mcp-server/ \
  --tactic initial-access \
  --include-supply-chain \
  --output sarif --file vendor-supply-chain.sarif
```

### 3. Continuous Monitoring
For ongoing security monitoring of MCP deployments:

```bash
# Daily security scan
safe-mcp-scan scan /production/mcp/servers/ \
  --config /etc/safe-mcp-scanner/production.yaml \
  --output json --file "daily-scan-$(date +%Y-%m-%d).json"

# Configuration drift detection
safe-mcp-scan scan /production/mcp/configs/ \
  --baseline /security/baselines/mcp-baseline.json \
  --output json --file config-drift.json

# Real-time monitoring (when implemented)
safe-mcp-scan monitor /production/mcp/ \
  --webhook https://security-alerts.company.com/webhook \
  --min-severity high
```

## Configuration Examples

### Project Configuration (.safe-mcp-scanner.yaml)
```yaml
# Comprehensive project configuration
scan:
  # Include/exclude patterns
  include:
    - "src/**/*.py"
    - "src/**/*.js"
    - "*.json"
    - "*.yaml"
    - "*.yml"
  
  exclude:
    - "tests/"
    - "venv/"
    - "node_modules/"
    - "*.pyc"
  
  # Technique configuration
  techniques:
    enabled:
      - "SAFE-T1001"  # Malicious Tool Descriptions
      - "SAFE-T1101"  # Command Injection
      - "SAFE-T1201"  # OAuth Token Theft
      - "SAFE-T1204"  # Environment Variable Harvesting
    
    # Technique-specific settings
    settings:
      SAFE-T1001:
        pattern_sensitivity: "high"
        check_comments: true
      SAFE-T1101:
        shell_injection: true
        eval_injection: true

  # Severity filtering
  severity:
    min_level: "low"
    fail_on: ["high", "critical"]
    suppress_info: false

# Output configuration
output:
  formats:
    - type: "console"
      color: true
      verbose: false
    - type: "json"
      file: "scan-results.json"
      pretty: true
    - type: "sarif"
      file: "results.sarif"
  
  # Report customization
  include_mitigations: true
  include_evidence: true
  include_references: true

# Performance settings
performance:
  max_file_size_mb: 50
  timeout_seconds: 300
  parallel_jobs: 4
  cache_results: true
```

### CI/CD Configuration Examples

#### GitHub Actions
```yaml
# .github/workflows/security-scan.yml
name: MCP Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install SAFE-MCP Scanner
      run: pip install safe-mcp-scanner
    
    - name: Run Security Scan
      run: |
        safe-mcp-scan scan . \
          --output json --file security-results.json \
          --output sarif --file security-results.sarif \
          --exit-code --max-high 0 --max-critical 0
    
    - name: Upload SARIF results
      if: always()
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: security-results.sarif
    
    - name: Upload scan results
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: security-scan-results
        path: |
          security-results.json
          security-results.sarif
```

#### Jenkins Pipeline
```groovy
// Jenkinsfile
pipeline {
    agent any
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Security Scan') {
            steps {
                sh '''
                    pip install safe-mcp-scanner
                    safe-mcp-scan scan . \
                        --output json --file security-results.json \
                        --output html --file security-report.html \
                        --exit-code --max-high 2 --max-critical 0
                '''
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'security-*.json,security-*.html', allowEmptyArchive: true
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: '.',
                reportFiles: 'security-report.html',
                reportName: 'MCP Security Report'
            ])
        }
        
        failure {
            emailext(
                subject: "MCP Security Scan Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "Security scan found critical vulnerabilities. Check the report.",
                to: "security-team@company.com"
            )
        }
    }
}
```

#### GitLab CI
```yaml
# .gitlab-ci.yml
stages:
  - security

mcp-security-scan:
  stage: security
  image: python:3.11-slim
  
  before_script:
    - pip install safe-mcp-scanner
  
  script:
    - |
      safe-mcp-scan scan . \
        --output json --file security-results.json \
        --output html --file security-report.html \
        --exit-code --max-high 1 --max-critical 0
  
  artifacts:
    when: always
    reports:
      # GitLab can parse SARIF reports
      sast: security-results.sarif
    paths:
      - security-results.json
      - security-report.html
    expire_in: 1 week
  
  only:
    - merge_requests
    - main
    - develop
```

## Real-World Examples

### Example 1: E-commerce MCP Server
A typical e-commerce MCP server with payment processing:

```bash
# Comprehensive scan focusing on financial data protection
safe-mcp-scan scan ecommerce-mcp/ \
  --techniques SAFE-T1201,SAFE-T1204,SAFE-T1205 \
  --include-pattern "payment/**" \
  --include-pattern "checkout/**" \
  --min-severity medium \
  --output html --file ecommerce-security-report.html
```

### Example 2: Content Management MCP Server
A content management system with user-generated content:

```bash
# Focus on injection and XSS vulnerabilities
safe-mcp-scan scan cms-mcp/ \
  --techniques SAFE-T1101,SAFE-T1103 \
  --include-pattern "content/**" \
  --include-pattern "user/**" \
  --output sarif --file cms-security.sarif
```

### Example 3: IoT Device MCP Server
An IoT device management server:

```bash
# Focus on device communication and credential security
safe-mcp-scan scan iot-mcp/ \
  --tactic credential-access \
  --tactic execution \
  --include-pattern "device/**" \
  --include-pattern "communication/**" \
  --output json --file iot-security.json
```

## Performance Optimization Examples

### Large Codebase Scanning
```bash
# Optimize for large codebases
safe-mcp-scan scan large-project/ \
  --parallel-jobs 8 \
  --timeout 600 \
  --max-file-size 100 \
  --cache-results \
  --exclude "test/**" \
  --exclude "docs/**"

# Incremental scanning (scan only changed files)
safe-mcp-scan scan large-project/ \
  --since-commit HEAD~1 \
  --output json --file incremental-scan.json
```

### Memory-Constrained Environments
```bash
# Optimize for low-memory environments
safe-mcp-scan scan project/ \
  --max-memory 512 \
  --parallel-jobs 2 \
  --stream-results \
  --minimal-output
```

## Integration Examples

### SIEM Integration
```bash
# Generate structured logs for SIEM ingestion
safe-mcp-scan scan /production/mcp/ \
  --output json \
  --structured-logging \
  --syslog-facility local0 \
  --min-severity medium
```

### Vulnerability Management Integration
```bash
# Generate vulnerability database compatible output
safe-mcp-scan scan /path \
  --output json \
  --include-cvss \
  --include-cwe \
  --vulnerability-format \
  --file vulnerabilities.json
```

## Troubleshooting Examples

### Debug Mode Scanning
```bash
# Debug scan issues
safe-mcp-scan scan problematic-project/ \
  --debug \
  --verbose \
  --log-level DEBUG \
  --output console

# Profile performance issues
safe-mcp-scan scan slow-project/ \
  --profile \
  --benchmark \
  --output json --file performance-profile.json
```

### Validation and Testing
```bash
# Validate configuration
safe-mcp-scan config validate .safe-mcp-scanner.yaml

# Test technique detection
safe-mcp-scan test-technique SAFE-T1001 test-files/

# Dry run without actual scanning
safe-mcp-scan scan project/ --dry-run --verbose
```

## Custom Technique Examples

See [Adding Techniques Guide](../contributing/adding-techniques.md) for implementing custom techniques:

```python
# Example: Custom technique for detecting deprecated MCP patterns
from safe_mcp_scanner.techniques.base import BaseTechnique

class DeprecatedPatternDetector(BaseTechnique):
    technique_id = "CUSTOM-T001"
    technique_name = "Deprecated MCP Patterns"
    # ... implementation
```

## More Examples

- **[MCP Server Examples](mcp-servers.md)**: Sample vulnerable and secure MCP servers
- **[CI/CD Examples](ci-cd-examples.md)**: Detailed CI/CD integration examples
- **[Configuration Examples](configuration-examples.md)**: Advanced configuration scenarios

## Need Help?

- 📖 **Documentation**: [../README.md](../README.md)
- 💡 **Use Cases**: [GitHub Discussions](https://github.com/your-org/safe-mcp-scanner/discussions)
- 🐛 **Issues**: [GitHub Issues](https://github.com/your-org/safe-mcp-scanner/issues)
- 📧 **Support**: examples@your-org.com