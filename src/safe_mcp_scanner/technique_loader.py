"""Technique loading and management for SAFE-MCP Scanner."""

import importlib
import importlib.util
import pkgutil
from pathlib import Path
from typing import Dict, Type, List

from .config import Config
from .techniques.base import BaseTechnique
from .techniques import TECHNIQUE_REGISTRY


class TechniqueLoader:
    """Loads and manages SAFE-MCP technique implementations."""
    
    def __init__(self, config: Config) -> None:
        self.config = config
        self._loaded_techniques: Dict[str, BaseTechnique] = {}
    
    def load_techniques(self) -> Dict[str, BaseTechnique]:
        """Load all available techniques.
        
        Returns:
            Dictionary mapping technique IDs to instantiated technique objects
        """
        # Load built-in techniques
        self._load_builtin_techniques()
        
        # Load custom techniques from plugin directories
        for plugin_dir in self.config.plugin_directories:
            self._load_custom_techniques(plugin_dir)
        
        return self._loaded_techniques.copy()
    
    def _load_builtin_techniques(self) -> None:
        """Load built-in SAFE-MCP techniques."""
        # Import all modules in the techniques package to trigger registration
        import safe_mcp_scanner.techniques
        
        techniques_package = safe_mcp_scanner.techniques
        techniques_path = Path(techniques_package.__file__).parent
        
        # Walk through all Python modules in the techniques directory
        for module_info in pkgutil.walk_packages([str(techniques_path)], 
                                                prefix="safe_mcp_scanner.techniques."):
            try:
                importlib.import_module(module_info.name)
            except ImportError as e:
                # Log warning but continue loading other techniques
                print(f"Warning: Could not load technique module {module_info.name}: {e}")
        
        # Instantiate registered techniques
        for technique_id, technique_class in TECHNIQUE_REGISTRY.items():
            try:
                technique_instance = technique_class(self.config)
                self._loaded_techniques[technique_id] = technique_instance
            except Exception as e:
                print(f"Warning: Could not instantiate technique {technique_id}: {e}")
    
    def _load_custom_techniques(self, plugin_dir: Path) -> None:
        """Load custom techniques from a plugin directory.
        
        Args:
            plugin_dir: Directory containing custom technique plugins
        """
        if not plugin_dir.exists() or not plugin_dir.is_dir():
            return
        
        # Add plugin directory to Python path temporarily
        import sys
        original_path = sys.path.copy()
        
        try:
            sys.path.insert(0, str(plugin_dir))
            
            # Look for Python files in the plugin directory
            for python_file in plugin_dir.glob("*.py"):
                if python_file.name.startswith("_"):
                    continue  # Skip private modules
                
                module_name = python_file.stem
                try:
                    # Import the custom module
                    spec = importlib.util.spec_from_file_location(module_name, python_file)
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        
                        # Check if any new techniques were registered
                        for technique_id, technique_class in TECHNIQUE_REGISTRY.items():
                            if technique_id not in self._loaded_techniques:
                                technique_instance = technique_class(self.config)
                                self._loaded_techniques[technique_id] = technique_instance
                
                except Exception as e:
                    print(f"Warning: Could not load custom technique from {python_file}: {e}")
        
        finally:
            # Restore original Python path
            sys.path = original_path
    
    def get_technique(self, technique_id: str) -> BaseTechnique:
        """Get a specific technique by ID.
        
        Args:
            technique_id: SAFE-MCP technique identifier
            
        Returns:
            Technique instance
            
        Raises:
            KeyError: If technique is not found
        """
        if technique_id not in self._loaded_techniques:
            raise KeyError(f"Technique {technique_id} not found")
        
        return self._loaded_techniques[technique_id]
    
    def get_techniques_by_tactic(self, tactic: str) -> List[BaseTechnique]:
        """Get all techniques for a specific tactic.
        
        Args:
            tactic: SAFE-MCP tactic category
            
        Returns:
            List of technique instances
        """
        return [
            technique for technique in self._loaded_techniques.values()
            if technique.tactic.lower() == tactic.lower()
        ]
    
    def get_techniques_for_file_type(self, file_extension: str) -> List[BaseTechnique]:
        """Get techniques that can analyze a specific file type.
        
        Args:
            file_extension: File extension (e.g., '.py', '.js')
            
        Returns:
            List of applicable technique instances
        """
        applicable_techniques = []
        
        for technique in self._loaded_techniques.values():
            if "*" in technique.file_types or file_extension in technique.file_types:
                applicable_techniques.append(technique)
        
        return applicable_techniques
    
    def validate_technique_config(self) -> List[str]:
        """Validate technique configuration and return any issues.
        
        Returns:
            List of validation error messages
        """
        issues = []
        
        # Check for enabled techniques that don't exist
        if self.config.enabled_techniques:
            for technique_id in self.config.enabled_techniques:
                if technique_id not in self._loaded_techniques:
                    issues.append(f"Enabled technique not found: {technique_id}")
        
        # Check for disabled techniques that don't exist
        for technique_id in self.config.disabled_techniques:
            if technique_id not in self._loaded_techniques:
                issues.append(f"Disabled technique not found: {technique_id}")
        
        # Check technique-specific configurations
        for technique_id in self.config.techniques.keys():
            if technique_id not in self._loaded_techniques:
                issues.append(f"Configuration found for unknown technique: {technique_id}")
        
        return issues
    
    def get_technique_info(self) -> Dict[str, dict]:
        """Get information about all loaded techniques.
        
        Returns:
            Dictionary with technique metadata
        """
        info = {}
        
        for technique_id, technique in self._loaded_techniques.items():
            info[technique_id] = {
                "name": technique.name,
                "description": technique.description,
                "tactic": technique.tactic,
                "severity": technique.severity,
                "file_types": technique.file_types,
                "enabled": technique.is_enabled(),
                "mitre_attack_mapping": technique.mitre_attack_mapping
            }
        
        return info