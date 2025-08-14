"""Base class for SAFE-MCP technique implementations."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..config import Config


@dataclass
class Finding:
    """Represents a security finding from a technique."""
    
    technique_id: str
    file_path: Path
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    severity: str = "medium"
    confidence: float = 0.7
    message: str = ""
    description: str = ""
    recommendation: str = ""
    source_code: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self) -> None:
        if self.metadata is None:
            self.metadata = {}


class BaseTechnique(ABC):
    """Abstract base class for SAFE-MCP techniques."""
    
    def __init__(self, config: Config) -> None:
        self.config = config
    
    @property
    @abstractmethod
    def technique_id(self) -> str:
        """SAFE-MCP technique identifier (e.g., 'SAFE-T1001')."""
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable technique name."""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Technique description."""
        pass
    
    @property
    @abstractmethod
    def severity(self) -> str:
        """Default severity level for this technique."""
        pass
    
    @property
    @abstractmethod
    def tactic(self) -> str:
        """SAFE-MCP tactic category."""
        pass
    
    @property
    def mitre_attack_mapping(self) -> Optional[str]:
        """Optional MITRE ATT&CK technique mapping."""
        return None
    
    @property
    def file_types(self) -> List[str]:
        """File extensions this technique can analyze."""
        return ["*"]
    
    def is_enabled(self) -> bool:
        """Check if this technique is enabled in configuration."""
        return self.config.is_technique_enabled(self.technique_id)
    
    def get_technique_config(self):
        """Get technique-specific configuration."""
        return self.config.get_technique_config(self.technique_id)
    
    @abstractmethod
    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a file and return security findings.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            List of security findings
        """
        pass
    
    def can_analyze_file(self, file_path: Path) -> bool:
        """Check if this technique can analyze the given file."""
        if "*" in self.file_types:
            return True
        
        file_ext = file_path.suffix.lower()
        return file_ext in self.file_types or f"*{file_ext}" in self.file_types
    
    def create_finding(
        self,
        file_path: Path,
        message: str,
        line_number: Optional[int] = None,
        column_number: Optional[int] = None,
        severity: Optional[str] = None,
        confidence: Optional[float] = None,
        description: Optional[str] = None,
        recommendation: Optional[str] = None,
        source_code: Optional[str] = None,
        **metadata
    ) -> Finding:
        """Helper method to create a finding with technique defaults."""
        technique_config = self.get_technique_config()
        
        return Finding(
            technique_id=self.technique_id,
            file_path=file_path,
            line_number=line_number,
            column_number=column_number,
            severity=severity or technique_config.severity,
            confidence=confidence or technique_config.confidence_threshold,
            message=message,
            description=description or self.description,
            recommendation=recommendation or self._get_default_recommendation(),
            source_code=source_code,
            metadata=metadata
        )
    
    def _get_default_recommendation(self) -> str:
        """Get default recommendation for this technique."""
        return f"Review and mitigate the security issue identified by {self.technique_id}"


def register_technique(technique_class: type) -> type:
    """Decorator to register a technique class."""
    from . import TECHNIQUE_REGISTRY
    
    if not issubclass(technique_class, BaseTechnique):
        raise ValueError(f"Technique {technique_class} must inherit from BaseTechnique")
    
    # Create a temporary instance to get the technique ID
    temp_instance = technique_class(config=None)  # type: ignore
    technique_id = temp_instance.technique_id
    
    TECHNIQUE_REGISTRY[technique_id] = technique_class
    return technique_class