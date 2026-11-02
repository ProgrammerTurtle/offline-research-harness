"""Offline, synthetic evaluator-integrity experiments. No network or model client."""

from .runner import Episode
from .tasks import make_case

__all__ = ["Episode", "make_case"]
