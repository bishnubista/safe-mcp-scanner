"""Configuration management for the SAFE-MCP Scanner."""

import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

import yaml
from pydantic import BaseModel, Field, ConfigDict, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class TechniqueConfig(BaseModel):
    """Configuration for individual SAFE-MCP techniques."""
    
    enabled: bool = True
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    confidence_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    custom_patterns: List[str] = Field(default_factory=list)
    exclude_patterns: List[str] = Field(default_factory=list)


class ScanConfig(BaseModel):
    """Configuration for scan behavior."""
    
    max_file_size: int = Field(default=10 * 1024 * 1024)  # 10MB
    max_files: Optional[int] = Field(default=None)
    follow_symlinks: bool = Field(default=False)
    include_patterns: List[str] = Field(default_factory=lambda: [
        "**/*.py", "**/*.js", "**/*.ts", "**/*.json", "**/*.yaml", "**/*.yml"
    ])
    exclude_patterns: List[str] = Field(default_factory=lambda: [
        "**/.git/**", "**/node_modules/**", "**/__pycache__/**", 
        "**/venv/**", "**/env/**", "**/.env/**"
    ])
    timeout_seconds: Optional[int] = Field(default=300)  # 5 minutes


class OutputConfig(BaseModel):
    """Configuration for output formatting."""
    
    format: str = Field(default="json", pattern="^(json|sarif|text|html)$")
    include_source: bool = Field(default=True)
    include_metadata: bool = Field(default=True)
    max_lines_context: int = Field(default=5)
    sarif_schema_version: str = Field(default="2.1.0")


class Config(BaseSettings):
    """Main configuration class with validation and hierarchy support."""
    
    model_config = SettingsConfigDict(
        env_prefix="SAFE_MCP_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="forbid"
    )
    
    # Core settings
    enabled_techniques: Optional[List[str]] = Field(default=None)
    disabled_techniques: List[str] = Field(default_factory=list)
    fail_on_severity: Optional[str] = Field(default=None, pattern="^(any|low|medium|high|critical)$")
    
    # Component configurations
    scan: ScanConfig = Field(default_factory=ScanConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    techniques: Dict[str, TechniqueConfig] = Field(default_factory=dict)
    
    # Plugin and extension settings
    plugin_directories: List[Path] = Field(default_factory=list)
    custom_rules: List[Path] = Field(default_factory=list)
    
    @field_validator("plugin_directories", "custom_rules", mode="before")
    @classmethod
    def validate_paths(cls, v: Any) -> List[Path]:
        """Convert string paths to Path objects."""
        if isinstance(v, (str, Path)):
            return [Path(v)]
        if isinstance(v, list):
            return [Path(item) for item in v]
        return v
    
    @field_validator("enabled_techniques", mode="before")
    @classmethod
    def validate_technique_list(cls, v: Any) -> Optional[List[str]]:
        """Validate technique ID format."""
        if v is None:
            return None
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            for technique_id in v:
                if not technique_id.startswith("SAFE-T"):
                    raise ValueError(f"Invalid technique ID format: {technique_id}")
            return v
        raise ValueError("enabled_techniques must be a string or list of strings")
    
    def get_technique_config(self, technique_id: str) -> TechniqueConfig:
        """Get configuration for a specific technique."""
        return self.techniques.get(technique_id, TechniqueConfig())
    
    def is_technique_enabled(self, technique_id: str) -> bool:
        """Check if a technique is enabled."""
        if self.enabled_techniques is not None:
            return technique_id in self.enabled_techniques
        return technique_id not in self.disabled_techniques
    
    def should_scan_file(self, file_path: Path) -> bool:
        """Check if a file should be scanned based on patterns."""
        import fnmatch
        from pathlib import PurePath
        
        # Convert to string for pattern matching
        path_str = str(file_path)
        pure_path = PurePath(file_path)
        
        # Check exclude patterns first
        for pattern in self.scan.exclude_patterns:
            # Handle different pattern types
            if "**" in pattern:
                # For patterns like **/node_modules/**, check if the path contains the directory
                if "/**" in pattern:
                    # Extract the directory name (e.g., "node_modules" from "**/node_modules/**")
                    parts = pattern.split("/")
                    for i, part in enumerate(parts):
                        if part and part != "**":
                            # Check if this directory appears in the path
                            if f"/{part}/" in f"/{path_str}/" or path_str.startswith(f"{part}/") or path_str.endswith(f"/{part}"):
                                return False
                else:
                    # Pattern like **/*.py - check suffix
                    suffix = pattern.replace("**/", "")
                    if fnmatch.fnmatch(path_str.split("/")[-1], suffix):
                        return False
            elif pure_path.match(pattern):
                return False
        
        # Check include patterns
        for pattern in self.scan.include_patterns:
            if "**" in pattern:
                # Pattern like **/*.py - check file extension
                suffix = pattern.replace("**/", "")
                if pure_path.match(suffix):
                    return True
            elif pure_path.match(pattern):
                return True
        
        return False


def find_config_files() -> List[Path]:
    """Find configuration files following the hierarchy."""
    config_files = []
    
    # 1. Project configuration
    project_configs = [
        Path.cwd() / ".safe-mcp-scanner.yaml",
        Path.cwd() / ".safe-mcp-scanner.yml",
        Path.cwd() / "safe-mcp-scanner.yaml",
        Path.cwd() / "safe-mcp-scanner.yml",
    ]
    for config_file in project_configs:
        if config_file.exists():
            config_files.append(config_file)
            break
    
    # 2. User configuration
    user_config_dir = Path.home() / ".config" / "safe-mcp-scanner"
    user_configs = [
        user_config_dir / "config.yaml",
        user_config_dir / "config.yml",
    ]
    for config_file in user_configs:
        if config_file.exists():
            config_files.append(config_file)
            break
    
    # 3. System configuration
    system_configs = [
        Path("/etc/safe-mcp-scanner/config.yaml"),
        Path("/etc/safe-mcp-scanner/config.yml"),
    ]
    for config_file in system_configs:
        if config_file.exists():
            config_files.append(config_file)
            break
    
    return config_files


def load_yaml_config(config_path: Path) -> Dict[str, Any]:
    """Load configuration from a YAML file."""
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in config file {config_path}: {e}")
    except Exception as e:
        raise ValueError(f"Error reading config file {config_path}: {e}")


def merge_configs(*configs: Dict[str, Any]) -> Dict[str, Any]:
    """Merge multiple configuration dictionaries.
    
    Later configs override earlier ones. Nested dictionaries are merged recursively.
    """
    result = {}
    
    for config in configs:
        if not config:
            continue
            
        for key, value in config.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = merge_configs(result[key], value)
            else:
                result[key] = value
    
    return result


def load_config(config_path: Optional[Path] = None) -> Config:
    """Load configuration following the hierarchy.
    
    Configuration hierarchy (highest to lowest priority):
    1. Explicit config file path (if provided)
    2. Environment variables (SAFE_MCP_*)
    3. Project configuration (.safe-mcp-scanner.yaml)
    4. User configuration (~/.config/safe-mcp-scanner/)
    5. System configuration (/etc/safe-mcp-scanner/)
    6. Default built-in configuration
    """
    # Start with default configuration
    config_data = {}
    
    # Load configuration files (lowest to highest priority)
    if config_path is None:
        config_files = find_config_files()
        config_files.reverse()  # Reverse for proper priority order
    else:
        config_files = [config_path]
    
    # Merge configuration files
    for config_file in config_files:
        file_config = load_yaml_config(config_file)
        config_data = merge_configs(config_data, file_config)
    
    # Create Config instance (which will also load environment variables)
    try:
        return Config(**config_data)
    except Exception as e:
        raise ValueError(f"Invalid configuration: {e}")


def create_default_config_file(config_path: Path) -> None:
    """Create a default configuration file."""
    default_config = {
        "scan": {
            "max_file_size": 10485760,  # 10MB
            "follow_symlinks": False,
            "include_patterns": [
                "**/*.py", "**/*.js", "**/*.ts", "**/*.json", 
                "**/*.yaml", "**/*.yml"
            ],
            "exclude_patterns": [
                "**/.git/**", "**/node_modules/**", "**/__pycache__/**",
                "**/venv/**", "**/env/**", "**/.env/**"
            ],
            "timeout_seconds": 300
        },
        "output": {
            "format": "json",
            "include_source": True,
            "include_metadata": True,
            "max_lines_context": 5
        },
        "disabled_techniques": [],
        "techniques": {
            "SAFE-T1001": {
                "enabled": True,
                "severity": "high",
                "confidence_threshold": 0.8
            }
        }
    }
    
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.dump(default_config, f, default_flow_style=False, indent=2)