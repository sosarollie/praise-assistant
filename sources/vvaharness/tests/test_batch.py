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

"""Per-repo state reset in vvaharness.orchestrator.batch.

Batch runs scan repos back-to-back in ONE process, so any process-global
one-shot state armed by repo 1 would silence the same diagnostic for every
later repo. The driver already reset TOKENS/STAGES/COUNTERS, the
response-quality counters and the CLI abort flag; these tests pin the
warn-once registries to the same contract: a warn-once diagnostic provoked by
repo N and again by repo N+1 must print for BOTH. That matters concretely for
the deepagents "no token usage recorded" WARN — on that route it is the only
signal that a stage's usage went unrecorded (the calls == calls_with_usage
check is vacuous there), so losing it hides a silent zero-cost stage in every
repo after the first.
"""
from __future__ import annotations

from types import SimpleNamespace

import vvaharness.backends.harness.deepagents.client as da_client
import vvaharness.backends.harness.deepagents.tools as da_tools
import vvaharness.backends.harness.deepagents.usage as da_usage
import vvaharness.backends.llm.deepagents as da
import vvaharness.backends.llm.sdk as sdk
import vvaharness.util.warn_once as warn_once_mod
import vvaharness.orchestrator.store as store
from vvaharness.orchestrator import batch
from vvaharness.orchestrator.scan import ScanOutcome
from vvaharness.util.warn_once import reset_warn_once_registries, warn_once

# (registry set, distinctive one-shot message) — one entry per warn-once
# scope in the process. The sets are pinned BY NAME on their owning modules,
# matching how sibling tests address them; the reset must clear these exact
# objects in place, never re-home them.
_SCOPES = (
    (store._PERM_WARNED, "WARNONCE-TEST perm"),
    (da._NO_USAGE_WARNED_TAGS, "WARNONCE-TEST no-usage"),
    (da._WARNED_LEGACY_KW, "WARNONCE-TEST legacy-kw"),
    (da_tools._WARNED_UNKNOWN_TOOLS, "WARNONCE-TEST unknown-tool"),
    (sdk._CACHE_ROUTE_NOTED, "WARNONCE-TEST cache-route"),
    # Registered for reset but previously unexercised here — found by
    # test_scopes_cover_every_registered_warn_once_site below.
    (da_usage._EXCLUSIVE_USAGE_WARNED, "WARNONCE-TEST exclusive-usage"),
    (da_client._EFFORT_UNSUPPORTED_WARNED, "WARNONCE-TEST effort"),
    (da_client._TRANSPORT_FALLBACK_WARNED, "WARNONCE-TEST transport-fallback"),
)


def test_scopes_cover_every_registered_warn_once_site():
    """Parity guard: this file's _SCOPES must not drift from _REGISTRY_SITES.

    The batch re-arm test only proves what _SCOPES lists. A new warn-once site
    registered for reset but absent here silently drops out of coverage — which
    is exactly what happened when the cache-route note was added.
    """
    import sys as _sys
    registered = set()
    for mod_name, attr in warn_once_mod._REGISTRY_SITES:
        mod = _sys.modules.get(mod_name)
        if mod is not None:
            registered.add(id(getattr(mod, attr)))
    covered = {id(reg) for reg, _ in _SCOPES}
    assert registered <= covered, (
        "warn_once registries registered for reset but not exercised by "
        "_SCOPES — add them above"
    )


def _clear_scopes():
    for reg, _ in _SCOPES:
        reg.clear()


def _provoke_all_scopes():
    """What a scan stage does: fire each one-shot diagnostic once."""
    for reg, msg in _SCOPES:
        warn_once(reg, "batch-reset-probe", msg)


def _mk_repos(tmp_path, n=2):
    refs = []
    for i in range(n):
        d = tmp_path / f"repo{i}"
        d.mkdir()
        (d / "app.py").write_text("print('x')\n", encoding="utf-8")
        refs.append(d)
    return refs


def _args(tmp_path, **over):
    base = dict(workspace=str(tmp_path / "ws"), group_by_app=False,
                stop_after=None, keep_clones=True, resume=False)
    base.update(over)
    return SimpleNamespace(**base)


def test_reset_warn_once_registries_clears_in_place():
    _clear_scopes()
    _provoke_all_scopes()
    ids = [id(reg) for reg, _ in _SCOPES]
    assert all(reg for reg, _ in _SCOPES)
    reset_warn_once_registries()
    # Cleared, and the module-level set OBJECTS are untouched (sibling tests
    # pin them by name, so re-binding instead of clearing would break them).
    assert all(not reg for reg, _ in _SCOPES)
    assert ids == [id(reg) for reg, _ in _SCOPES]


def test_batch_rearms_warn_once_between_repos(tmp_path, monkeypatch, capsys):
    """Two repos in one batch, both provoking the same warn-once conditions:
    the warning must appear for BOTH repos, not just the first."""
    _clear_scopes()
    refs = _mk_repos(tmp_path)
    list_file = tmp_path / "repos.txt"
    list_file.write_text(
        "".join(f"app{i},repo{i},{d}\n" for i, d in enumerate(refs)),
        encoding="utf-8")

    def fake_scan(repo, module, app_id, args, cfg, path_prefix=None):
        _provoke_all_scopes()
        return ScanOutcome(report_path=None, finding_count=0, exit_code=0)

    monkeypatch.setattr(batch, "scan_repo", fake_scan)
    rc = batch.run_batch(list_file, _args(tmp_path), SimpleNamespace())
    err = capsys.readouterr().err
    assert rc == 0
    for _, msg in _SCOPES:
        assert err.count(msg) == 2, (
            f"one-shot diagnostic {msg!r} must fire once per repo "
            f"(saw {err.count(msg)}) — warn-once registries not re-armed "
            f"between batch repos")


def test_batch_grouped_rearms_warn_once_between_app_groups(
        tmp_path, monkeypatch, capsys):
    _clear_scopes()
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(tmp_path / "state"))
    refs = _mk_repos(tmp_path)
    list_file = tmp_path / "repos.txt"
    list_file.write_text(
        "".join(f"app{i},repo{i},{d}\n" for i, d in enumerate(refs)),
        encoding="utf-8")

    def fake_scan(repo, module, app_id, args, cfg, path_prefix=None):
        _provoke_all_scopes()
        return ScanOutcome(report_path=None, finding_count=0, exit_code=0)

    monkeypatch.setattr(batch, "scan_repo", fake_scan)
    rc = batch.run_batch(list_file, _args(tmp_path, group_by_app=True),
                         SimpleNamespace())
    err = capsys.readouterr().err
    assert rc == 0
    for _, msg in _SCOPES:
        assert err.count(msg) == 2, (
            f"one-shot diagnostic {msg!r} must fire once per app-group "
            f"(saw {err.count(msg)})")
