"""Dependency-free, engagement-local coordination for native OMP agents."""
from __future__ import annotations

from . import policy, runtime
from .config import ROLE_DESCRIPTIONS, ROLE_NAMES, dispatch, load_roles, set_role_model
from .errors import PraiseError
from .runtime import (
    artifact,
    connect,
    inbox,
    init_engagement,
    load_scope,
    peers,
    project_messages,
    register_agent,
    send_message,
    show,
)

__version__ = "0.2.0"

__all__ = [
    "__version__", "policy", "runtime", "PraiseError", "ROLE_NAMES", "ROLE_DESCRIPTIONS",
    "load_roles", "set_role_model", "dispatch", "init_engagement", "load_scope", "connect",
    "artifact", "register_agent", "send_message", "inbox", "peers", "project_messages", "show",
]
