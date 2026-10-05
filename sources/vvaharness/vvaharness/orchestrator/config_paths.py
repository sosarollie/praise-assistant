# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""orchestrator.config_paths — see package docstring."""
from __future__ import annotations

from pathlib import Path

from vvaharness.config import is_network_path
# Safe at module scope: `exploit_verification/__init__` imports nothing and `options`
# pulls only stdlib, so this adds no import weight and cannot cycle back here.
from vvaharness.exploit_verification.settings import EV_MODULES as _EV_MODULES


def _app_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _default_config() -> Path:
    cwd_cfg = Path.cwd() / "config.yaml"
    if cwd_cfg.exists():
        return cwd_cfg
    return _packaged_default()


def _packaged_default() -> Path:
    """The bundled default profile — the trusted fallback used when a config
    sourced from inside the scan target is refused."""
    return _app_root() / "config" / "profiles" / "default.yaml"


def _path_within(candidate, root) -> bool:
    """True if `candidate` resolves at or under `root` (both fully resolved).
    Used to refuse a config/.env that lives INSIDE the scanned (untrusted)
    repository, which an attacker who controls the checkout could plant."""
    try:
        Path(candidate).resolve().relative_to(Path(root).resolve())
        return True
    except (ValueError, OSError):
        return False


def _resolve_against(base: Path, p: str) -> str:
    # Refuse UNC/network input paths before they reach any loader's
    # is_file()/read — on Windows that touch leaks the user's NTLM hash over
    # SMB. Covers every injected input that funnels through here: inject.*
    # (cve/controls/cmdb), step_remediate policy/playbook (via _resolve_input),
    # and TLS ca_cert/client_cert. Check the raw value and the base-joined
    # result (a UNC base would taint an otherwise-relative path).
    if is_network_path(p):
        raise ValueError(
            f"refusing network/UNC input path {p!r} "
            f"(reading it could leak credentials over SMB)")
    pp = Path(p)
    resolved = pp if pp.is_absolute() else (base / pp)
    if is_network_path(resolved):
        raise ValueError(
            f"refusing network/UNC input path {str(resolved)!r} "
            f"(reading it could leak credentials over SMB)")
    return str(resolved)


# Every model role a profile can configure. The single definition — doctor
# (util.environment) imports it from here rather than keeping its own copy,
# which had already drifted (it omitted graph_annotate).
_MODEL_ROLES = ("graph_annotate", "callgraph_creation", "autoexclude",
                "preprocess", "threatmodel", "decompose", "deepdive", "verify",
                "dedup", "chain", "remediate", "validate", "exploit_verification")

# The S0 callgraph-annotator roles, live only under step0.callgraph_detection:
# llm. In rules mode their models are never called at runtime (taint.yaml ships
# exactly that shape), so probing/credential-checking them would fatally fail a
# config that scans fine today.
_CALLGRAPH_ROLES = frozenset({"graph_annotate", "callgraph_creation"})


def _callgraph_llm_selected(cfg) -> bool:
    """True when ``step0.callgraph_detection`` selects the LLM annotator.

    Mirrors the callgraph engine's own mode predicate
    (pipeline/stages/callgraph_engine/__init__.py): the value is stripped and
    lower-cased, and an absent, empty, or unrecognised value falls back to
    ``"rules"`` — i.e. anything that is not exactly ``llm`` means the annotator
    model is dead config and must not be preflighted.
    """
    step0 = getattr(cfg, "step0", None)
    mode = str(getattr(step0, "callgraph_detection", "rules")
               or "rules").strip().lower()
    return mode == "llm"


#: Roles whose config is a MAP of sub-roles rather than a single model node, so the node
#: to resolve is one level down. ``validate`` runs its whole panel on the orchestrator's
#: backend, so only that one is checked; ``exploit_verification`` genuinely mixes
#: backends per purpose, so each sub-role is yielded separately and checked on its own.
#: ``exploit_verification``'s four names are imported rather than restated: the same tuple
#: also names the behaviour sub-blocks under ``step6_exploit_verification``, so all three
#: readers (this one, ``verify.run``, and the config block itself) share one definition.
_SUB_ROLES: dict[str, tuple[str, ...]] = {
    "validate": ("orchestrator",),
    "exploit_verification": _EV_MODULES,
}

#: The role names :func:`_iter_model_roles` reports for exploit verification, derived
#: from the map above so the two cannot drift. Callers that must exclude EV — the
#: credential preflight on a run that cannot reach it — filter on these.
EV_MODEL_ROLES: tuple[str, ...] = tuple(
    f"exploit_verification.{s}" for s in _SUB_ROLES["exploit_verification"])

def _iter_model_roles(cfg):
    """Yield ``(role, model_cfg_node)`` for every configured, ACTIVE model role.

    Skips the S0 callgraph roles unless ``step0.callgraph_detection: llm``, so
    preflight/doctor only ever probe models a scan under this config could
    actually call: in rules mode those roles are dead config and probing them
    would fail a profile that scans fine.
    """
    for r in _MODEL_ROLES:
        if r in _CALLGRAPH_ROLES and not _callgraph_llm_selected(cfg):
            continue
        m = getattr(cfg.models, r, None)
        if m is None:
            continue
        subs = _SUB_ROLES.get(r)
        if subs is None:
            yield r, m
            continue
        for sub in subs:
            node = getattr(m, sub, None)
            # Absent sub-roles are skipped rather than reported: they are optional by
            # design (EV without an `attacker` simply runs no adaptive loop), and
            # demanding a credential for a role nobody configured would fail a scan
            # over a feature it never intended to use.
            if node is None:
                continue
            # `validate` keeps reporting under its own name: callers classify roles by it
            # (see `llm.POST_SCAN_ROLES` / `preflight._post_scan_only`, which downgrade a
            # post-scan credential gap to a WARN), and a sub-role name would not match.
            yield (r if len(subs) == 1 else f"{r}.{sub}"), node
