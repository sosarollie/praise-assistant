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

"""S1 via:deepagents route tests — stage branching, degrade, and path shapes.

The stages call ``_deepagents.dispatch_prompt`` / ``dispatch_agentic``; the
via branch lives in that dispatcher, so these tests patch its two legs — the
module-level deepagents wrappers (``_deepagents.prompt`` / ``.agentic``) and
the legacy registry (``_deepagents.registry.prompt`` / ``.agentic``) — arming
whichever leg must NOT fire to fail, so a routing regression cannot pass
silently.
"""

from __future__ import annotations

import json
import types

import pytest
import yaml

import vvaharness.pipeline.stages.s1_autoexclude as s1a
import vvaharness.pipeline.stages.s1_preprocess as s1
from vvaharness.models import ContextPackage


def _repo(tmp_path):
    (tmp_path / "src").mkdir(parents=True)
    (tmp_path / "src" / "app.py").write_text(
        "def run():\n    return eval('1')\n", encoding="utf-8"
    )
    return tmp_path


def _preprocess_cfg(model_node):
    return types.SimpleNamespace(
        step1=types.SimpleNamespace(
            mode="full",
            allowed_tools=["Read", "Glob", "Grep"],
            max_budget_usd=0.1,
            max_turns=2,
            call_graph="tree_sitter",
            call_graph_supplement=False,
            call_graph_validate=False,
            exclude_dirs=None,
            exclude_exts=None,
            exclude_globs=None,
            max_file_kb=1024,
        ),
        models=types.SimpleNamespace(preprocess=model_node),
        sdk=types.SimpleNamespace(api_key="sk-test"),
        _scan_progress=None,
    )


def _quiet_graphs(monkeypatch):
    monkeypatch.setattr(s1, "_supplement_call_graph", lambda *a, **k: None)

    class _TsGraph:
        @staticmethod
        def build(data, all_files, repo_root, cfg):
            data.setdefault("call_graph", {})
            data.setdefault("call_graph_files", {})
            data.setdefault("def_spans", {})
            return True

    monkeypatch.setattr(s1, "ts_graph", _TsGraph, raising=False)


def _map_json(file="src/app.py"):
    return json.dumps({
        "language": "python",
        "modules": [{"name": "app", "files": [file], "loc": 2, "purpose": "app"}],
        "entry_points": [{"file": file, "function": "run", "kind": "network",
                          "reachable_from_unauth": True}],
        "unsafe_sinks": [{"file": file, "line": 2, "function": "eval",
                          "snippet": "eval('1')"}],
        "call_graph": {},
        "notes": "",
    })


def _fail_registry(monkeypatch, name):
    """Arm the dispatcher's legacy leg to fail: via:deepagents must never
    reach ``registry.prompt``/``registry.agentic``."""
    monkeypatch.setattr(
        s1._deepagents.registry, name,
        lambda *a, **k: pytest.fail("legacy dispatcher was called"),
    )


def _fail_wrapper(monkeypatch, name):
    """Arm the dispatcher's deepagents leg to fail: a legacy via must never
    reach the harness wrappers."""
    monkeypatch.setattr(
        s1._deepagents, name,
        lambda *a, **k: pytest.fail("deepagents wrapper was called"),
    )


# ── preprocess: via branching ────────────────────────────────────────────────

def test_preprocess_deepagents_via_routes_through_wrapper(tmp_path, monkeypatch):
    _quiet_graphs(monkeypatch)
    _fail_registry(monkeypatch, "agentic")
    node = types.SimpleNamespace(id="claude-test", via="deepagents")
    cfg = _preprocess_cfg(node)
    captured = {}

    def fake_agentic(user_prompt, **kw):
        captured["user_prompt"] = user_prompt
        captured.update(kw)
        return _map_json()

    monkeypatch.setattr(s1._deepagents, "agentic", fake_agentic)

    pkg = s1.run(str(_repo(tmp_path)), cfg, known_cves=[], controls=[])

    assert isinstance(pkg, ContextPackage)
    assert captured["system_prompt"] is s1.SYSTEM
    assert captured["user_prompt"].startswith("Map this repository")
    assert captured["model"] is node
    assert captured["allowed_tools"] == ["Read", "Glob", "Grep"]
    assert captured["cwd"] == str(tmp_path)
    assert captured["max_budget_usd"] == 0.1
    assert captured["max_turns"] == 2
    assert captured["graph_name"] == "s1-preprocess"
    assert captured["sdk_cfg"] is cfg.sdk
    assert captured["openai_cfg"] is None
    assert [e.file for e in pkg.entry_points] == ["src/app.py"]
    assert [s.file for s in pkg.unsafe_sinks] == ["src/app.py"]


def test_preprocess_legacy_via_keeps_exact_kwargs(tmp_path, monkeypatch):
    _quiet_graphs(monkeypatch)
    node = types.SimpleNamespace(id="claude-test", via="sdk")
    cfg = _preprocess_cfg(node)
    _fail_wrapper(monkeypatch, "agentic")
    captured = {}

    def fake_agentic(user_prompt, **kw):
        captured["user_prompt"] = user_prompt
        captured.update(kw)
        return _map_json()

    monkeypatch.setattr(s1._deepagents.registry, "agentic", fake_agentic)

    pkg = s1.run(str(_repo(tmp_path)), cfg, known_cves=[], controls=[])

    assert isinstance(pkg, ContextPackage)
    # The legacy leg keeps the registry signature: no deepagents-only kwargs
    # (graph_name/sdk_cfg/openai_cfg/cfg_dir) leak in.
    assert set(captured) == {"user_prompt", "model", "system_prompt",
                             "allowed_tools", "cwd", "max_budget_usd",
                             "max_turns", "tag"}
    assert captured["model"] is node


def test_preprocess_bare_string_model_stays_legacy(tmp_path, monkeypatch):
    _quiet_graphs(monkeypatch)
    cfg = _preprocess_cfg("claude-test")
    _fail_wrapper(monkeypatch, "agentic")
    monkeypatch.setattr(s1._deepagents.registry, "agentic",
                        lambda *a, **k: _map_json())

    pkg = s1.run(str(_repo(tmp_path)), cfg, known_cves=[], controls=[])
    assert isinstance(pkg, ContextPackage)


def test_preprocess_deepagents_degrades_on_garbage(tmp_path, monkeypatch, capsys):
    _quiet_graphs(monkeypatch)
    _fail_registry(monkeypatch, "agentic")
    cfg = _preprocess_cfg(types.SimpleNamespace(id="claude-test", via="deepagents"))
    monkeypatch.setattr(s1._deepagents, "agentic", lambda *a, **k: "no json here")

    pkg = s1.run(str(_repo(tmp_path)), cfg, known_cves=[], controls=[])

    assert isinstance(pkg, ContextPackage)
    assert pkg.entry_points == []
    assert "WARN: mapper response not parseable" in capsys.readouterr().err


def test_preprocess_deepagents_empty_reply_degrades(tmp_path, monkeypatch, capsys):
    _quiet_graphs(monkeypatch)
    _fail_registry(monkeypatch, "agentic")
    cfg = _preprocess_cfg(types.SimpleNamespace(id="claude-test", via="deepagents"))
    monkeypatch.setattr(s1._deepagents, "agentic", lambda *a, **k: "")

    pkg = s1.run(str(_repo(tmp_path)), cfg, known_cves=[], controls=[])

    assert isinstance(pkg, ContextPackage)
    assert "WARN: mapper response not parseable" in capsys.readouterr().err


# ── virtual-root path shapes ─────────────────────────────────────────────────

def test_virtual_root_paths_survive_scope_filter(tmp_path, monkeypatch):
    _quiet_graphs(monkeypatch)
    _fail_registry(monkeypatch, "agentic")
    cfg = _preprocess_cfg(types.SimpleNamespace(id="claude-test", via="deepagents"))
    monkeypatch.setattr(
        s1._deepagents, "agentic", lambda *a, **k: _map_json(file="/src/app.py")
    )

    pkg = s1.run(str(_repo(tmp_path)), cfg, known_cves=[], controls=[])

    assert [e.file for e in pkg.entry_points] == ["src/app.py"]
    assert [s.file for s in pkg.unsafe_sinks] == ["src/app.py"]


def test_norm_rel_strips_virtual_root():
    assert s1._norm_rel("/srv/repo", "/src/app.py") == "src/app.py"
    assert s1._norm_rel("/srv/repo", "//src/app.py") == "src/app.py"


@pytest.mark.parametrize(("path", "expected"), [
    ("src/app.py", "src/app.py"),                # already relative
    ("./src/app.py", "src/app.py"),              # leading ./
    ("/srv/repo/src/app.py", "src/app.py"),      # absolute under the root
    ("src\\app.py", "src/app.py"),               # backslashes
    ("", ""),                                    # empty passthrough
])
def test_norm_rel_previously_accepted_forms_unchanged(path, expected):
    assert s1._norm_rel("/srv/repo", path) == expected


def test_norm_rel_out_of_repo_absolute_still_fails_membership():
    # "/etc/passwd" now normalizes to "etc/passwd", which is not in the
    # inventory — the filter still drops it (strictly drop-reducing change).
    rel = s1._norm_rel("/srv/repo", "/etc/passwd")
    assert rel == "etc/passwd"
    assert rel not in {"src/app.py"}


# ── autoexclude: via branching ───────────────────────────────────────────────

def _autoexclude_cfg(autoexclude_node, preprocess_node="stub-model"):
    return types.SimpleNamespace(
        step1=types.SimpleNamespace(),
        models=types.SimpleNamespace(
            autoexclude=autoexclude_node, preprocess=preprocess_node
        ),
        sdk=types.SimpleNamespace(api_key="sk-test"),
    )


def test_autoexclude_deepagents_via_routes_through_wrapper(tmp_path, monkeypatch):
    _fail_registry(monkeypatch, "prompt")
    node = types.SimpleNamespace(id="claude-test", via="deepagents")
    cfg = _autoexclude_cfg(node)
    captured = {}

    def fake_prompt(user_prompt, **kw):
        captured["user_prompt"] = user_prompt
        captured.update(kw)
        return "```yaml\nexclude_dirs:\n  - generated\n```"

    monkeypatch.setattr(s1a._deepagents, "prompt", fake_prompt)
    repo = _repo(tmp_path / "repo")

    out = s1a.run(repo, cfg, out_path=tmp_path / "overlay.yaml")

    overlay = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert overlay["exclude_dirs"] == ["generated"]
    assert captured["model"] is node
    assert captured["system_prompt"] is s1a._SYSTEM
    assert captured["cwd"] == str(repo)
    assert captured["tag"] == "s1 autoexclude"
    assert captured["graph_name"] == "s1-autoexclude"
    assert captured["sdk_cfg"] is cfg.sdk
    assert captured["openai_cfg"] is None


def test_autoexclude_deepagents_garbage_still_writes_empty_overlay(
        tmp_path, monkeypatch):
    _fail_registry(monkeypatch, "prompt")
    cfg = _autoexclude_cfg(types.SimpleNamespace(id="claude-test", via="deepagents"))
    monkeypatch.setattr(s1a._deepagents, "prompt", lambda *a, **k: "not yaml { ] :")

    out = s1a.run(_repo(tmp_path / "repo"), cfg, out_path=tmp_path / "overlay.yaml")

    assert out.is_file()
    overlay = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert overlay == {"exclude_dirs": [], "exclude_exts": [], "exclude_globs": []}


def test_autoexclude_legacy_via_untouched(tmp_path, monkeypatch):
    _fail_wrapper(monkeypatch, "prompt")
    captured = {}

    def fake_prompt(user_prompt, **kw):
        captured.update(kw)
        return "```yaml\n{}\n```"

    monkeypatch.setattr(s1a._deepagents.registry, "prompt", fake_prompt)
    cfg = _autoexclude_cfg(types.SimpleNamespace(id="claude-test", via="sdk"))

    out = s1a.run(_repo(tmp_path / "repo"), cfg, out_path=tmp_path / "overlay.yaml")

    assert out.is_file()
    # The legacy leg keeps the registry signature: no deepagents-only kwargs.
    assert set(captured) == {"model", "system_prompt", "max_tokens", "tag"}


def test_autoexclude_fallback_node_follows_preprocess_via(tmp_path, monkeypatch):
    _fail_registry(monkeypatch, "prompt")
    preprocess = types.SimpleNamespace(id="claude-test", via="deepagents")
    cfg = _autoexclude_cfg(None, preprocess_node=preprocess)
    captured = {}

    def fake_prompt(user_prompt, **kw):
        captured.update(kw)
        return "```yaml\n{}\n```"

    monkeypatch.setattr(s1a._deepagents, "prompt", fake_prompt)

    s1a.run(_repo(tmp_path / "repo"), cfg, out_path=tmp_path / "overlay.yaml")

    assert captured["model"] is preprocess
