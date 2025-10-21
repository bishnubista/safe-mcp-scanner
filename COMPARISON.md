# Current vs. Recommended Approach: Side-by-Side Comparison

## Example: Detecting Hardcoded Credentials

### Current Approach (SAFE-MCP Framework Style)

**File**: `src/safe_mcp_scanner/techniques/initial_access/malicious_tool_description.py`

```python
@register_technique
class MaliciousToolDescriptionTechnique(BaseTechnique):
    """SAFE-T1001: Detects malicious tool descriptions in MCP configs."""

    technique_id = "SAFE-T1001"
    name = "Malicious Tool Descriptions"
    tactic = "Initial Access"
    description = "Detects suspicious tool descriptions that may be used for phishing"
    severity = "high"
    mitre_attack_mapping = "T1566"  # Phishing
    file_types = [".json", ".yaml", ".yml"]

    def analyze_file(self, file_path: Path) -> List[Finding]:
        patterns = PatternMatcher.create_malicious_tool_patterns()
        # Only 2 basic regex patterns...
```

**Problems**:
- ❌ Forced MITRE ATT&CK mapping that doesn't really fit
- ❌ Vague "tactic" categories from enterprise security
- ❌ Only detects credentials in tool descriptions, not actual config
- ❌ Limited to 2 regex patterns
- ❌ No context-aware analysis

### Recommended Approach (MCP-Specific)

**File**: `src/safe_mcp_scanner/detectors/config/hardcoded_credentials.py`

```python
class HardcodedCredentialsDetector(BaseDetector):
    """Detects hardcoded API keys, tokens, and passwords in MCP configs."""

    detector_id = "MCP-CONFIG-001"
    category = "Configuration Security"
    name = "Hardcoded Credentials"
    severity = "critical"

    PATTERNS = {
        "openai_key": re.compile(r'sk-[a-zA-Z0-9]{32,}'),
        "anthropic_key": re.compile(r'sk-ant-[a-zA-Z0-9-]{50,}'),
        "github_token": re.compile(r'gh[ps]_[a-zA-Z0-9]{36,}'),
        "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
        # ... 15+ specific patterns
    }

    def analyze_file(self, file_path: Path) -> List[Finding]:
        # 1. Pattern matching for known formats
        # 2. JSON/YAML parsing and semantic analysis
        # 3. Key name + value analysis
        # 4. Entropy calculation for unknown secrets
        # 5. Environment variable reference detection
```

**Benefits**:
- ✅ Clear purpose: find hardcoded credentials
- ✅ Multiple detection methods (patterns + semantic analysis)
- ✅ MCP-specific context (knows about MCP config structure)
- ✅ Actionable severity (critical = fix immediately)
- ✅ Practical recommendations (use env vars)

---

## Detection Coverage Comparison

### Current State: 2 Detectors

| ID | Name | Works? | Usefulness |
|----|------|--------|------------|
| SAFE-T1001 | Malicious Tool Descriptions | ✅ Yes | ⭐⭐ Limited |
| SAFE-T1101 | Command Injection | ✅ Yes | ⭐⭐⭐⭐ Good |

**Total**: 2 working detectors finding limited types of issues

### Recommended MVP: 12 Core Detectors

| ID | Name | Priority | Impact |
|----|------|----------|--------|
| **Configuration Security** ||||
| MCP-CONFIG-001 | Hardcoded Credentials | 🔴 Critical | ⭐⭐⭐⭐⭐ |
| MCP-CONFIG-002 | Insecure Transport (HTTP) | 🔴 Critical | ⭐⭐⭐⭐ |
| MCP-CONFIG-003 | Overly Permissive Tools | 🟡 High | ⭐⭐⭐⭐ |
| MCP-CONFIG-004 | Debug Mode in Production | 🟡 High | ⭐⭐⭐ |
| **Code Execution** ||||
| MCP-EXEC-001 | Command Injection | 🔴 Critical | ⭐⭐⭐⭐⭐ |
| MCP-EXEC-002 | Arbitrary Code Execution | 🔴 Critical | ⭐⭐⭐⭐⭐ |
| MCP-EXEC-003 | Template Injection | 🟡 High | ⭐⭐⭐⭐ |
| **Data Access** ||||
| MCP-DATA-001 | Path Traversal | 🔴 Critical | ⭐⭐⭐⭐⭐ |
| MCP-DATA-002 | Unrestricted File Access | 🟡 High | ⭐⭐⭐⭐ |
| MCP-DATA-003 | SQL Injection | 🟡 High | ⭐⭐⭐⭐ |
| **Prompt Security** ||||
| MCP-PROMPT-001 | Malicious Descriptions | 🟢 Medium | ⭐⭐⭐ |
| MCP-PROMPT-002 | Instruction Injection | 🟢 Medium | ⭐⭐⭐ |

**Total**: 12 focused detectors finding real vulnerabilities

---

## Output Format Comparison

### Current State

**JSON** ✅ Works
```json
{
  "findings": [
    {
      "technique_id": "SAFE-T1001",
      "severity": "high",
      "message": "Suspicious pattern found"
    }
  ]
}
```

**SARIF** ❌ Crashes
```bash
$ safe-mcp-scan scan --format sarif
ValueError: Unsupported format 'sarif'
```

**Text** ❌ Crashes
```bash
$ safe-mcp-scan scan --format text
ValueError: Unsupported format 'text'
```

### Recommended Implementation

**JSON** ✅ Enhanced
```json
{
  "scan_summary": {
    "total_findings": 5,
    "by_severity": {"critical": 2, "high": 2, "medium": 1},
    "by_category": {"Configuration Security": 3, "Code Execution": 2}
  },
  "findings": [
    {
      "detector_id": "MCP-CONFIG-001",
      "category": "Configuration Security",
      "severity": "critical",
      "title": "Hardcoded OpenAI API Key",
      "file": "claude_desktop_config.json",
      "line": 15,
      "description": "OpenAI API key found hardcoded in configuration",
      "impact": "Exposed API key can lead to unauthorized access and charges",
      "recommendation": "Move to environment variable: OPENAI_API_KEY",
      "cwe": "CWE-798",
      "confidence": 0.95
    }
  ]
}
```

**SARIF** ✅ Implemented
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "safe-mcp-scanner",
        "rules": [...]
      }
    },
    "results": [
      {
        "ruleId": "MCP-CONFIG-001",
        "level": "error",
        "message": {
          "text": "Hardcoded OpenAI API Key"
        },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {
              "uri": "claude_desktop_config.json"
            },
            "region": {
              "startLine": 15
            }
          }
        }]
      }
    ]
  }]
}
```

**Text** ✅ Implemented
```
🔍 MCP Security Scan Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 Summary
  Total Findings: 5
  🔴 Critical: 2
  🟡 High: 2
  🟢 Medium: 1

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 CRITICAL: Hardcoded OpenAI API Key
  └─ File: claude_desktop_config.json:15
  └─ Category: Configuration Security
  └─ Detector: MCP-CONFIG-001

  Description:
    OpenAI API key found hardcoded in configuration file

  Impact:
    Exposed API key can lead to unauthorized access and API charges

  Recommendation:
    Move to environment variable: OPENAI_API_KEY

  Source:
    13 |   "mcpServers": {
    14 |     "my-server": {
    15 |       "env": {
    16 |         "OPENAI_API_KEY": "sk-proj-abc123..."  ← HERE
    17 |       }

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Architecture Comparison

### Current Architecture

```
src/safe_mcp_scanner/
├── techniques/              ❌ Confusing name
│   ├── __init__.py          ✅ Registry works
│   ├── base.py              ✅ Good abstraction
│   ├── initial_access/      ❌ MITRE categories don't fit
│   │   └── malicious_tool_description.py
│   └── execution/
│       └── command_injection.py
├── detectors/               ⚠️ Exists but only has base
│   ├── base.py
│   └── pattern_matcher.py   ✅ This is good!
└── reporters/               ⚠️ Only 1 of 3 works
    ├── json.py              ✅ Works
    ├── sarif.py             ❌ Missing
    └── text.py              ❌ Missing
```

**Problems**:
- Mixing "techniques" (MITRE) and "detectors" (actual)
- MITRE tactic categories (Initial Access, Execution) don't map well to MCP
- Missing critical reporters that CLI advertises

### Recommended Architecture

```
src/safe_mcp_scanner/
├── detectors/               ✅ Clear purpose
│   ├── base.py              ✅ Keep existing
│   ├── config/              ✅ MCP-specific categories
│   │   ├── hardcoded_credentials.py
│   │   ├── insecure_transport.py
│   │   ├── overly_permissive.py
│   │   └── debug_mode.py
│   ├── code/                ✅ Code analysis
│   │   ├── command_injection.py  ✅ Enhance existing
│   │   ├── arbitrary_execution.py
│   │   ├── template_injection.py
│   │   └── unsafe_deserialization.py
│   ├── data/                ✅ Data access
│   │   ├── path_traversal.py
│   │   ├── unrestricted_file_access.py
│   │   └── sql_injection.py
│   ├── prompt/              ✅ MCP-specific
│   │   ├── malicious_descriptions.py  ✅ Move existing
│   │   └── instruction_injection.py
│   └── supply_chain/        ✅ Future
│       ├── vulnerable_dependencies.py
│       └── package_validation.py
├── analyzers/               ✅ NEW: Shared analysis engines
│   ├── pattern_matcher.py   ✅ Move from detectors
│   ├── python_ast.py        ✅ AST analysis
│   ├── javascript_ast.py    ✅ Use esprima
│   └── config_parser.py     ✅ MCP config semantics
└── reporters/               ✅ Complete all formats
    ├── base.py              ✅ Keep
    ├── json.py              ✅ Enhance
    ├── sarif.py             ✅ IMPLEMENT
    ├── text.py              ✅ IMPLEMENT
    └── html.py              ✅ Future
```

---

## Real-World Example

### Scenario: Scanning a Real MCP Server

**File**: `claude_desktop_config.json`
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
      "env": {
        "OPENAI_API_KEY": "sk-proj-abcd1234567890"
      }
    },
    "brave-search": {
      "command": "python",
      "args": ["-c", "import subprocess; subprocess.run(input(), shell=True)"],
      "env": {
        "BRAVE_API_KEY": "${BRAVE_API_KEY}"
      }
    }
  }
}
```

### Current Scanner Output

```bash
$ safe-mcp-scan scan claude_desktop_config.json

Found 0 findings
```

**Why?** Only looks for tool descriptions, not actual config issues.

### Recommended Scanner Output

```bash
$ safe-mcp-scan scan claude_desktop_config.json

🔍 MCP Security Scan Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 Summary: 4 findings
  🔴 Critical: 2
  🟡 High: 2

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 CRITICAL: Hardcoded OpenAI API Key (MCP-CONFIG-001)
  └─ claude_desktop_config.json:7
  └─ Hardcoded API key found in configuration
  💡 Move to environment variable: OPENAI_API_KEY

🔴 CRITICAL: Arbitrary Command Execution (MCP-EXEC-002)
  └─ claude_desktop_config.json:13
  └─ MCP server executes arbitrary Python code with shell=True
  💡 Replace with safe MCP server implementation

🟡 HIGH: Unrestricted Filesystem Access (MCP-DATA-002)
  └─ claude_desktop_config.json:5
  └─ Filesystem server has root access "/"
  💡 Restrict to specific safe directories

🟡 HIGH: Insecure Package Installation (MCP-CONFIG-005)
  └─ claude_desktop_config.json:4
  └─ npx with -y flag installs packages without confirmation
  💡 Pin package versions for security

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

❌ Scan failed: 2 critical issues found
```

**Now this is useful!**

---

## Migration Path

### Step 1: Keep What Works ✅

**Don't break existing functionality:**
- Keep `Scanner` class
- Keep `Config` class
- Keep `FileDiscovery`
- Keep `JSONReporter`
- Keep existing 2 detectors (just rename)

### Step 2: Add Missing Core Features ✅

**Fill the gaps:**
1. Implement `SARIFReporter` (2-3 days)
2. Implement `TextReporter` (1-2 days)
3. Update documentation to match reality (1 day)

### Step 3: Expand Detectors ✅

**Add high-impact detectors:**
1. `HardcodedCredentialsDetector` (2-3 days)
2. `PathTraversalDetector` (1-2 days)
3. `ArbitraryExecutionDetector` (2 days)
4. `InsecureTransportDetector` (1 day)
5. `OverlyPermissiveToolsDetector` (2 days)

**Total**: 1-2 weeks to MVP

### Step 4: Advanced Features ✅

**Later milestones:**
- Python AST analyzer (1 week)
- JavaScript AST analyzer (1 week)
- Supply chain scanning (2 weeks)
- Container security (2 weeks)

---

## Conclusion

### Current Approach Issues
1. ❌ Over-promises (77 techniques → 2 exist)
2. ❌ Wrong abstraction (MITRE ATT&CK doesn't fit MCP)
3. ❌ Missing advertised features (SARIF, Text reporters)
4. ❌ Limited detection methods (only regex)

### Recommended Approach Benefits
1. ✅ Honest capabilities (12 solid detectors)
2. ✅ MCP-specific taxonomy (meaningful categories)
3. ✅ Complete core features (all reporters work)
4. ✅ Multiple detection methods (patterns + AST + semantic)

### Bottom Line

**The project has a solid foundation but needs to:**
- Drop the MITRE ATT&CK forced mapping
- Focus on real MCP vulnerabilities
- Complete the features it advertises
- Grow incrementally with quality

**This can be a genuinely useful tool—it just needs to be practical and honest about what it does.**
