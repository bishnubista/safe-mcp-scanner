"""SAFE-MCP technique implementations."""

from typing import Dict, List
from .base import BaseTechnique

__all__ = ["BaseTechnique"]

# Registry for technique discovery
TECHNIQUE_REGISTRY: Dict[str, BaseTechnique] = {}

# Import all techniques to register them
# (must come after TECHNIQUE_REGISTRY is defined to avoid circular imports)
from . import command_injection
from . import malicious_tools
from . import hardcoded_credentials