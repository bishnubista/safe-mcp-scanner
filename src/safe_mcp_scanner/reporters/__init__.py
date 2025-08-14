"""Output formatters for scan results."""

from .base import BaseReporter
from .json_reporter import JSONReporter

__all__ = ["BaseReporter", "JSONReporter"]