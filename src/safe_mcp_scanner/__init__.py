"""SAFE-MCP Scanner: A vulnerability scanner for MCP servers implementing the SAFE-MCP framework."""

__version__ = "0.1.0"
__author__ = "SAFE-MCP Scanner Team"
__license__ = "MIT"

from .scanner import Scanner

__all__ = ["Scanner"]