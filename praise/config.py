"""Canonical role selectors, persisted independently of OMP's other settings."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
from importlib import resources
import json
import os
from pathlib import Path
import re
import tempfile

from .errors import PraiseError

ROLE_NAMES = ("lead", "planner", "scout", "finder", "verifier", "exploiter", "skeptic", "reviewer", "tester")
ROLE_DESCRIPTIONS = {
    "lead": "Coordinate scope, delegation, and completion.",
    "planner": "Plan the scoped work and its dependencies.",
    "scout": "Map unfamiliar surfaces and locate relevant code.",
    "finder": "Investigate evidence-backed issues.",
    "verifier": "Check evidence and reachable boundaries.",
    "exploiter": "Develop minimal authorized reproductions.",
    "skeptic": "Independently challenge evidence and conclusions.",
    "reviewer": "Review surviving conclusions independently.",
    "tester": "Validate proposed changes against their requirements.",
}
_SELECTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*(?::[A-Za-z0-9][A-Za-z0-9._-]*)?\Z")


def agent_dir(home=None) -> Path:
    if home is not None:
        return Path(home).expanduser().resolve() / ".omp" / "agent"
    configured = os.environ.get("PI_CODING_AGENT_DIR")
    return Path(configured).expanduser().resolve() if configured else Path.home() / ".omp" / "agent"


def validate_model(model: str) -> str:
    if not isinstance(model, str) or len(model) > 256 or not _SELECTOR.fullmatch(model):
        raise PraiseError("model must be a provider/model[:effort] selector of at most 256 characters")
    return model


def _read_json(path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise PraiseError(f"cannot read role configuration: {exc}") from exc
    if not isinstance(value, dict):
        raise PraiseError("role configuration must be a JSON object")
    return value


def _validate(catalog: dict) -> dict:
    models = catalog.get("models")
    if catalog.get("schema_version") != 3 or not isinstance(models, dict) or set(models) != set(ROLE_NAMES):
        raise PraiseError("role configuration requires schema_version 3 and exactly the canonical roles")
    return {"schema_version": 3, "models": {role: validate_model(models[role]) for role in ROLE_NAMES}}


def default_roles() -> dict:
    return _validate(_read_json(resources.files("praise").joinpath("roles.json")))


def _read_roles(directory: Path) -> dict:
    """Read without mutation; installer uses this in its file transaction."""
    path = directory / "praise.json"
    if path.is_symlink():
        raise PraiseError("symlink role configuration refused")
    if path.exists():
        return _validate(_read_json(path))
    catalog = default_roles()
    legacy = directory / "crew.json"
    if legacy.is_symlink():
        raise PraiseError("symlink legacy configuration refused")
    if legacy.exists():
        old = _read_json(legacy)
        if "models" in old:
            values = old["models"]
            if not isinstance(values, dict):
                raise PraiseError("legacy models must be a mapping")
            for role in ROLE_NAMES:
                if role in values:
                    catalog["models"][role] = validate_model(values[role])
        else:
            if "lead_model" in old:
                catalog["models"]["lead"] = validate_model(old["lead_model"])
            roles = old.get("roles", {})
            if not isinstance(roles, dict):
                raise PraiseError("legacy roles must be a mapping")
            for role in ROLE_NAMES[1:]:
                legacy_name = "security-reviewer" if role == "reviewer" else f"pentest-{role}"
                entry = roles.get(role, roles.get(legacy_name))
                if entry is None:
                    continue
                models = entry.get("models") if isinstance(entry, dict) else None
                if not isinstance(models, list) or not models:
                    raise PraiseError(f"legacy role {role} requires a model selector")
                catalog["models"][role] = validate_model(models[0])
    return catalog


@contextmanager
def config_lock(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / ".praise.lock"
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "a+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def atomic_write(target: Path, data: bytes, mode: int = 0o600) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            temporary.chmod(mode)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)


def role_bytes(catalog: dict) -> bytes:
    return (json.dumps(catalog, indent=2) + "\n").encode("utf-8")


def load_roles(home=None) -> dict:
    directory = agent_dir(home)
    with config_lock(directory):
        catalog = _read_roles(directory)
        if not (directory / "praise.json").exists():
            atomic_write(directory / "praise.json", role_bytes(catalog))
        return catalog


def set_role_model(role: str, model: str, home=None) -> dict:
    if role not in ROLE_NAMES:
        raise PraiseError(f"unknown role: {role}")
    validate_model(model)
    directory = agent_dir(home)
    with config_lock(directory):
        catalog = _read_roles(directory)
        catalog["models"][role] = model
        atomic_write(directory / "praise.json", role_bytes(catalog))
    return {"role": role, "model": model, "updated": True}


def dispatch(role: str, home=None) -> dict:
    if role not in ROLE_NAMES:
        raise PraiseError(f"unknown role: {role}")
    return {"role": role, "agent": role, "model": load_roles(home)["models"][role]}
