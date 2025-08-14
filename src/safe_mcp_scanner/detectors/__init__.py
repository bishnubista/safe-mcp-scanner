"""Detection engines for different file types and analysis methods."""

from .base import BaseDetector
from .pattern_matcher import PatternMatcher

__all__ = ["BaseDetector", "PatternMatcher"]