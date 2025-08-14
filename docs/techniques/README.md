# SAFE-MCP Techniques Overview

This document provides an overview of all SAFE-MCP attack techniques that the scanner can detect, based on the [SAFE-MCP framework](https://github.com/fkautz/safe-mcp).

## Introduction

The SAFE-MCP framework adapts MITRE ATT&CK methodology specifically for Model Context Protocol (MCP) environments. It documents 77 attack techniques across 14 tactical categories, providing a comprehensive security framework for MCP implementations.

## Technique Naming Convention

SAFE-MCP techniques follow the format: `SAFE-T<TACTIC><TECHNIQUE>`
- **SAFE**: Framework identifier
- **T**: Technique indicator
- **TACTIC**: 4-digit tactic number (1001-1400+)
- **TECHNIQUE**: 2-digit technique number within tactic (01-99)

## Tactical Categories

### Initial Access (SAFE-T1001-T1008)
Techniques that attackers use to gain their initial foothold within MCP environments.

| Technique ID | Name | Severity | Status |
|--------------|------|----------|--------|
| SAFE-T1001 | [Malicious Tool Descriptions](initial-access.md#safe-t1001) | High | ✅ Implemented |
| SAFE-T1002 | [Supply Chain Compromise](initial-access.md#safe-t1002) | Critical | 🚧 In Progress |
| SAFE-T1003 | [Trojanized MCP Packages](initial-access.md#safe-t1003) | High | 📋 Planned |
| SAFE-T1004 | [Insecure Direct Object References](initial-access.md#safe-t1004) | Medium | 📋 Planned |
| SAFE-T1005 | [Public Endpoint Exploitation](initial-access.md#safe-t1005) | High | 📋 Planned |
| SAFE-T1006 | [User Social Engineering Install](initial-access.md#safe-t1006) | Medium | 📋 Planned |
| SAFE-T1007 | [OAuth Authorization Phishing](initial-access.md#safe-t1007) | High | 📋 Planned |
| SAFE-T1008 | [Authorization Server Mix-up](initial-access.md#safe-t1008) | Medium | 📋 Planned |

### Execution (SAFE-T1101-T1106)
Techniques that result in adversary-controlled code running on MCP servers.

| Technique ID | Name | Severity | Status |
|--------------|------|----------|--------|
| SAFE-T1101 | [Command Injection](execution.md#safe-t1101) | Critical | ✅ Implemented |
| SAFE-T1102 | [Tool Poisoning](execution.md#safe-t1102) | High | 🚧 In Progress |
| SAFE-T1103 | [Prompt Injection via Tool Parameters](execution.md#safe-t1103) | High | 📋 Planned |
| SAFE-T1104 | [Over-Privileged Tool Abuse](execution.md#safe-t1104) | High | ✅ Implemented |
| SAFE-T1105 | [Resource Exhaustion DoS](execution.md#safe-t1105) | Medium | 📋 Planned |
| SAFE-T1106 | [Container Escape via Tool](execution.md#safe-t1106) | Critical | 📋 Planned |

### Credential Access (SAFE-T1201-T1207)
Techniques for stealing credentials and authentication information.

| Technique ID | Name | Severity | Status |
|--------------|------|----------|--------|
| SAFE-T1201 | [OAuth Token Theft](credential-access.md#safe-t1201) | High | ✅ Implemented |
| SAFE-T1202 | [OAuth Audience Confusion](credential-access.md#safe-t1202) | Medium | 📋 Planned |
| SAFE-T1203 | [Token Forwarding Attack](credential-access.md#safe-t1203) | High | 📋 Planned |
| SAFE-T1204 | [Environment Variable Harvesting](credential-access.md#safe-t1204) | Medium | ✅ Implemented |
| SAFE-T1205 | [Configuration File Credential Theft](credential-access.md#safe-t1205) | Medium | 📋 Planned |
| SAFE-T1206 | [Memory Credential Extraction](credential-access.md#safe-t1206) | High | 📋 Planned |
| SAFE-T1207 | [Session Hijacking](credential-access.md#safe-t1207) | High | 📋 Planned |

### Other Tactical Categories (Coming Soon)

The following tactical categories are part of the SAFE-MCP framework and will be implemented in future releases:

- **Persistence (SAFE-T1300+)**: Maintaining access to MCP environments
- **Privilege Escalation (SAFE-T1400+)**: Gaining higher-level permissions
- **Defense Evasion (SAFE-T1500+)**: Avoiding security detection
- **Discovery (SAFE-T1600+)**: Exploring MCP environments
- **Lateral Movement (SAFE-T1700+)**: Moving through MCP networks
- **Collection (SAFE-T1800+)**: Gathering data from MCP systems
- **Command and Control (SAFE-T1900+)**: Communicating with compromised systems
- **Exfiltration (SAFE-T2000+)**: Stealing data from MCP environments
- **Impact (SAFE-T2100+)**: Disrupting or destroying MCP operations

## Implementation Status

### Legend
- ✅ **Implemented**: Technique is fully implemented and tested
- 🚧 **In Progress**: Technique is currently being developed
- 📋 **Planned**: Technique is planned for future implementation
- ❌ **Not Planned**: Technique is not currently planned for implementation

### Current Coverage
- **Total Techniques**: 77 (SAFE-MCP framework)
- **Implemented**: 5 techniques
- **In Progress**: 2 techniques
- **Planned**: 70 techniques

### Priority Implementation Order
1. **High-Impact Techniques**: Critical and high-severity techniques first
2. **Common Attack Vectors**: Frequently observed techniques in MCP environments
3. **Detection Complexity**: Simpler detections implemented before complex ones
4. **Community Requests**: Techniques requested by the community

## Using Technique Filters

You can filter scans to specific techniques or tactical categories:

```bash
# Scan for specific techniques
safe-mcp-scan scan /path --techniques SAFE-T1001,SAFE-T1101

# Scan by tactic
safe-mcp-scan scan /path --tactic initial-access

# Exclude specific techniques
safe-mcp-scan scan /path --exclude SAFE-T1105

# Scan only high severity techniques
safe-mcp-scan scan /path --min-severity high
```

## Contributing New Techniques

Interested in implementing a SAFE-MCP technique? See our [Adding Techniques Guide](../contributing/adding-techniques.md) for detailed instructions.

### Requirements for New Techniques
1. **SAFE-MCP Alignment**: Must correspond to documented SAFE-MCP technique
2. **Accurate Detection**: Low false positive/negative rates
3. **Comprehensive Testing**: Unit tests and integration tests
4. **Clear Documentation**: Usage examples and mitigation guidance
5. **Performance Consideration**: Efficient implementation

## References

- [SAFE-MCP Framework](https://github.com/fkautz/safe-mcp) - Official framework documentation
- [MITRE ATT&CK](https://attack.mitre.org/) - Original ATT&CK framework
- [Model Context Protocol](https://github.com/modelcontextprotocol) - MCP specification
- [Contributing Guide](../contributing/adding-techniques.md) - How to add new techniques