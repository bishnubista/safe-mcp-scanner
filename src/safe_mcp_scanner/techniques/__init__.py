"""SAFE-MCP technique implementations."""

from typing import Dict, List
from .base import BaseTechnique

__all__ = ["BaseTechnique"]

# Registry for technique discovery
TECHNIQUE_REGISTRY: Dict[str, BaseTechnique] = {}