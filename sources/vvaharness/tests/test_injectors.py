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

"""Unit tests for the context injectors.

Covers vvaharness.injectors.cve_feed.load_cves and
vvaharness.injectors.design_controls.load_controls: happy-path parsing
from a tmp_path fixture, the {"cves":...} / {controls:...} wrapper forms,
missing-file behaviour, graceful degradation on malformed input, and the
shape / types of the returned model instances.
"""
from __future__ import annotations

import json

import pytest

from vvaharness.injectors import cve_feed, design_controls
from vvaharness.models import CVE, Control
from vvaharness.util import errlog as _errlog


def test_load_cves_bare_list(tmp_path):
    feed = tmp_path / "cves.json"
    feed.write_text(
        json.dumps(
            [
                {
                    "id": "CVE-2024-1234",
                    "summary": "heap overflow in parser",
                    "affected_files": ["src/parse.c"],
                    "cvss": 9.8,
                    "patched": False,
                },
                {"id": "CVE-2024-5678", "summary": "info leak"},
            ]
        ),
        encoding="utf-8",
    )

    out = cve_feed.load_cves(feed)

    assert isinstance(out, list)
    assert len(out) == 2
    assert all(isinstance(c, CVE) for c in out)
    first = out[0]
    assert first.id == "CVE-2024-1234"
    assert first.summary == "heap overflow in parser"
    assert first.affected_files == ["src/parse.c"]
    assert first.cvss == 9.8
    assert first.patched is False
    # defaults applied on the minimal second item
    assert out[1].affected_files == []
    assert out[1].cvss is None
    assert out[1].patched is False


def test_load_cves_wrapper_dict(tmp_path):
    feed = tmp_path / "cves.json"
    feed.write_text(
        json.dumps({"cves": [{"id": "CVE-2025-0001", "summary": "uaf"}]}),
        encoding="utf-8",
    )

    out = cve_feed.load_cves(feed)

    assert len(out) == 1
    assert out[0].id == "CVE-2025-0001"


def test_load_cves_accepts_str_path(tmp_path):
    feed = tmp_path / "cves.json"
    feed.write_text(json.dumps([{"id": "CVE-2024-9999", "summary": "x"}]),
                    encoding="utf-8")

    # pass a plain str rather than a Path object
    out = cve_feed.load_cves(str(feed))
    assert len(out) == 1
    assert out[0].id == "CVE-2024-9999"


def test_load_cves_missing_file_returns_empty(tmp_path):
    out = cve_feed.load_cves(tmp_path / "does-not-exist.json")
    assert out == []


def test_load_cves_dict_without_cves_key_degrades(tmp_path, capsys):
    # A dict that is NOT a wrapper is malformed input -> degrade to [].
    feed = tmp_path / "cves.json"
    feed.write_text(json.dumps({"id": "CVE-2024-1", "summary": "lone obj"}),
                    encoding="utf-8")

    out = cve_feed.load_cves(feed)

    assert out == []
    err = capsys.readouterr().err
    assert "could not load CVE feed" in err


def test_load_cves_invalid_json_degrades(tmp_path, capsys):
    feed = tmp_path / "cves.json"
    feed.write_text("{not valid json", encoding="utf-8")

    out = cve_feed.load_cves(feed)

    assert out == []
    assert "could not load CVE feed" in capsys.readouterr().err


def test_load_cves_item_failing_validation_skipped(tmp_path, capsys):
    # missing required "summary" -> that ONE record is skipped (per-item
    # isolation). With no other records the feed loads to []; the WARN names the
    # per-record skip, not a whole-feed load failure.
    feed = tmp_path / "cves.json"
    feed.write_text(json.dumps([{"id": "CVE-2024-1"}]), encoding="utf-8")

    out = cve_feed.load_cves(feed)

    assert out == []
    assert "skipped 1 malformed CVE record" in capsys.readouterr().err


def test_load_cves_partial_accept_keeps_valid_drops_bad(tmp_path, capsys):
    # The core of the per-item isolation fix: a malformed record must NOT
    # suppress the valid records around it.
    feed = tmp_path / "cves.json"
    feed.write_text(json.dumps([
        {"id": "CVE-2024-1111", "summary": "valid one"},
        {"id": "CVE-2024-BAD"},                         # missing summary -> skip
        {"id": "CVE-2024-2222", "summary": "valid two"},
    ]), encoding="utf-8")

    out = cve_feed.load_cves(feed)

    assert [c.id for c in out] == ["CVE-2024-1111", "CVE-2024-2222"]
    assert "skipped 1 malformed CVE record" in capsys.readouterr().err


def test_load_cves_non_list_payload_degrades(tmp_path, capsys):
    # {"cves": <non-list>} is structurally malformed -> degrade to [] + WARN,
    # rather than iterating a scalar.
    feed = tmp_path / "cves.json"
    feed.write_text(json.dumps({"cves": 123}), encoding="utf-8")

    out = cve_feed.load_cves(feed)

    assert out == []
    assert "could not load CVE feed" in capsys.readouterr().err


def test_load_cves_skipped_item_writes_errlog(tmp_path):
    # A skipped record is recorded individually (stage inject.cves.item, with
    # the offending id) without aborting the rest of the feed.
    feed = tmp_path / "cves.json"
    feed.write_text(json.dumps([
        {"id": "CVE-OK", "summary": "ok"},
        {"id": "CVE-BAD"},                              # missing summary
    ]), encoding="utf-8")

    out = cve_feed.load_cves(feed)

    assert [c.id for c in out] == ["CVE-OK"]
    record = json.loads(_errlog._path.read_text(encoding="utf-8").strip())
    assert record["stage"] == "inject.cves.item"
    assert "CVE-BAD" in record["unit"]


def test_load_cves_degrade_writes_errlog(tmp_path):
    # The structured error log must capture the parse failure.
    feed = tmp_path / "cves.json"
    feed.write_text("garbage", encoding="utf-8")

    out = cve_feed.load_cves(feed)

    assert out == []
    log_path = _errlog._path
    assert log_path.exists()
    record = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert record["stage"] == "inject.cves"
    assert record["unit"] == str(feed)


def test_load_controls_bare_list(tmp_path):
    cfg = tmp_path / "controls.yaml"
    cfg.write_text(
        "- name: auth-gateway\n"
        "  kind: auth\n"
        "  protects:\n"
        "    - src/api/*.py\n"
        "  notes: edge auth\n"
        "- name: wasm-sandbox\n"
        "  kind: sandbox\n",
        encoding="utf-8",
    )

    out = design_controls.load_controls(cfg)

    assert isinstance(out, list)
    assert len(out) == 2
    assert all(isinstance(c, Control) for c in out)
    assert out[0].name == "auth-gateway"
    assert out[0].kind == "auth"
    assert out[0].protects == ["src/api/*.py"]
    assert out[0].notes == "edge auth"
    # defaults on the minimal item
    assert out[1].name == "wasm-sandbox"
    assert out[1].kind == "sandbox"
    assert out[1].protects == []
    assert out[1].notes == ""


def test_load_controls_wrapper_mapping(tmp_path):
    cfg = tmp_path / "controls.yaml"
    cfg.write_text(
        "controls:\n"
        "  - name: rbac\n"
        "    kind: auth\n",
        encoding="utf-8",
    )

    out = design_controls.load_controls(cfg)

    assert len(out) == 1
    assert out[0].name == "rbac"
    assert out[0].kind == "auth"


def test_load_controls_kind_alias_coerced(tmp_path):
    # "authentication" is not a valid Literal member but the model's
    # field_validator must coerce it to the canonical "auth".
    cfg = tmp_path / "controls.yaml"
    cfg.write_text(
        "- name: idp\n"
        "  kind: authentication\n",
        encoding="utf-8",
    )

    out = design_controls.load_controls(cfg)

    assert len(out) == 1
    assert out[0].kind == "auth"


def test_load_controls_unknown_kind_falls_back_to_other(tmp_path):
    cfg = tmp_path / "controls.yaml"
    cfg.write_text(
        "- name: mystery\n"
        "  kind: quantum-shield\n",
        encoding="utf-8",
    )

    out = design_controls.load_controls(cfg)

    assert len(out) == 1
    assert out[0].kind == "other"


def test_load_controls_accepts_str_path(tmp_path):
    cfg = tmp_path / "controls.yaml"
    cfg.write_text("- name: c1\n  kind: auth\n", encoding="utf-8")

    out = design_controls.load_controls(str(cfg))
    assert len(out) == 1
    assert out[0].name == "c1"


def test_load_controls_missing_file_returns_empty(tmp_path):
    out = design_controls.load_controls(tmp_path / "nope.yaml")
    assert out == []


def test_load_controls_empty_file_returns_empty(tmp_path):
    # yaml.safe_load("") is None -> `or {}` -> dict without "controls" key
    # -> ValueError -> degrade to [].
    cfg = tmp_path / "controls.yaml"
    cfg.write_text("", encoding="utf-8")

    out = design_controls.load_controls(cfg)
    assert out == []


def test_load_controls_mapping_without_controls_key_degrades(tmp_path, capsys):
    cfg = tmp_path / "controls.yaml"
    cfg.write_text("name: lonely\nkind: auth\n", encoding="utf-8")

    out = design_controls.load_controls(cfg)

    assert out == []
    assert "could not load controls file" in capsys.readouterr().err


def test_load_controls_invalid_yaml_degrades(tmp_path, capsys):
    cfg = tmp_path / "controls.yaml"
    cfg.write_text("name: [unbalanced\n  : broken", encoding="utf-8")

    out = design_controls.load_controls(cfg)

    assert out == []
    assert "could not load controls file" in capsys.readouterr().err


def test_load_controls_item_failing_validation_degrades(tmp_path, capsys):
    # missing required "name" -> validation raises -> degrade to [].
    cfg = tmp_path / "controls.yaml"
    cfg.write_text("- kind: auth\n", encoding="utf-8")

    out = design_controls.load_controls(cfg)

    assert out == []
    assert "could not load controls file" in capsys.readouterr().err


def test_load_controls_degrade_writes_errlog(tmp_path):
    cfg = tmp_path / "controls.yaml"
    cfg.write_text("name: x\nkind: auth\n", encoding="utf-8")

    out = design_controls.load_controls(cfg)

    assert out == []
    log_path = _errlog._path
    assert log_path.exists()
    record = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert record["stage"] == "inject.controls"
    assert record["unit"] == str(cfg)
