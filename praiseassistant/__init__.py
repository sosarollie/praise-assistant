"""PraiseAssistant: evidence-based, dependency-free pentest workflow control.

The public local-helper interfaces are generic. OMP is the host, not a bundled
binary. No role/model performance claims are made.
"""

from __future__ import annotations

from . import policy, runtime
from .runtime import (
    PraiseError,
    artifact,
    connect,
    get_candidate,
    init_engagement,
    load_scope,
    model_family,
    record_event,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "policy",
    "runtime",
    "PraiseError",
    "init_engagement",
    "load_scope",
    "connect",
    "artifact",
    "model_family",
    "get_candidate",
    "record_event",
]
