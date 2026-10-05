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

"""Unit tests for vvaharness.manifest.

Offline and deterministic: time, version lookup, git subprocess, and config
model loading are all monkeypatched so capture() produces stable output.
"""
import json
import types

import pytest

from vvaharness import manifest

# Helpers / fixtures

@pytest.fixture
def frozen_time(monkeypatch):
    """Make time.time() and datetime.now() deterministic inside manifest.

    time.time() advances by exactly 2.5 seconds between the two calls
    capture() makes (start, then end), so duration is predictable.
    """
    times = iter([1000.0, 1002.5])

    def fake_time():
        try:
            return next(times)
        except StopIteration:
            return 1002.5

    monkeypatch.setattr(manifest.time, "time", fake_time)

    class FakeDateTime:
        _vals = iter(["2026-01-01T00:00:00+00:00", "2026-01-01T00:00:02+00:00"])

        @classmethod
        def now(cls, tz=None):
            # Return an object whose isoformat() yields a fixed string.
            try:
                val = next(cls._vals)
            except StopIteration:
                val = "2026-01-01T00:00:02+00:00"
            return types.SimpleNamespace(isoformat=lambda v=val: v)

    monkeypatch.setattr(manifest, "datetime", FakeDateTime)
    return FakeDateTime


@pytest.fixture
def no_git(monkeypatch):
    """Stub out git SHA lookup to None by default (no --repo arg path)."""
    monkeypatch.setattr(manifest, "_git_sha", lambda args: None)


@pytest.fixture
def no_models(monkeypatch):
    """Stub model-role extraction to an empty dict by default."""
    monkeypatch.setattr(manifest, "_models", lambda cfg_path: {})


# capture() field / write behavior

def test_capture_yields_expected_fields(tmp_path, frozen_time, no_git, no_models):
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("k: v\n", encoding="utf-8")
    out = tmp_path / "manifest.json"
    args = ["scan", "--repo", "/x"]

    with manifest.capture(cfg, args, out=out) as m:
        # Inside the block: the seed fields should already be populated.
        assert m["tool"] == "vvaharness"
        # Version is sourced from package metadata (single source of truth), so
        # assert against the live value rather than a literal that can drift.
        from vvaharness import __version__ as _vvah_version
        assert m["version"] == _vvah_version
        assert m["argv"] == args
        assert m["config_profile"] == str(cfg)
        assert m["models"] == {}
        assert m["target_git_sha"] is None
        assert m["exit_code"] is None
        # The per-stage section is composed on the way out, not seeded.
        assert "stages" not in m
        assert m["started"] == "2026-01-01T00:00:00+00:00"
        # ended/duration not set until the context exits.
        assert "ended" not in m
        assert "duration_sec" not in m
        # A real scan sets exit_code; that's what authorises the write.
        m["exit_code"] = 0

    # After exit: ended + duration populated, file written.
    assert m["ended"] == "2026-01-01T00:00:02+00:00"
    assert m["duration_sec"] == 2.5
    assert out.exists()
    # …and the per-stage telemetry fields are present (empty run → no stages).
    assert m["stages"] == {}
    assert m["totals"]["total_tokens"] == 0
    assert m["pricing"] is None


def test_capture_writes_valid_json_matching_dict(tmp_path, frozen_time, no_git, no_models):
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("k: v\n", encoding="utf-8")
    out = tmp_path / "nested" / "manifest.json"
    out.parent.mkdir()

    with manifest.capture(cfg, ["scan"], out=out) as m:
        m["exit_code"] = 0

    written = json.loads(out.read_text(encoding="utf-8"))
    assert written == m
    assert written["tool"] == "vvaharness"
    assert written["duration_sec"] == 2.5


def test_capture_skips_write_when_scan_never_started(tmp_path, frozen_time,
                                                     no_git, no_models):
    """No manifest for a help screen / argparse error: if the body never set
    exit_code (the scan didn't start), capture() must not write a junk file."""
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("k: v\n", encoding="utf-8")
    out = tmp_path / "manifest.json"

    with manifest.capture(cfg, ["--help"], out=out):
        pass  # exit_code stays None — simulates argparse SystemExit / help

    assert not out.exists()


def test_capture_records_exit_code_set_by_caller(tmp_path, frozen_time, no_git, no_models):
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("x", encoding="utf-8")
    out = tmp_path / "m.json"

    with manifest.capture(cfg, ["scan"], out=out) as m:
        m["exit_code"] = 0

    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["exit_code"] == 0


def test_capture_writes_even_when_body_raises(tmp_path, frozen_time, no_git, no_models):
    """The finally block must persist the manifest even on exception."""
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("x", encoding="utf-8")
    out = tmp_path / "m.json"

    with pytest.raises(ValueError):
        with manifest.capture(cfg, ["scan"], out=out) as m:
            m["exit_code"] = 2
            raise ValueError("boom")

    assert out.exists()
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["exit_code"] == 2
    assert written["ended"] == "2026-01-01T00:00:02+00:00"


def test_capture_defaults_dest_to_cwd(tmp_path, monkeypatch, frozen_time, no_git, no_models):
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("x", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    with manifest.capture(cfg, ["scan"]) as m:  # no out= -> cwd/run_manifest_<ts>.json
        m["exit_code"] = 0

    dest = tmp_path / "run_manifest_20260101T000000Z.json"
    assert dest.exists()
    assert json.loads(dest.read_text(encoding="utf-8")) == m


def test_capture_default_dest_avoids_overwrite_same_second(
        tmp_path, monkeypatch, frozen_time, no_git, no_models):
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("x", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    first = tmp_path / "run_manifest_20260101T000000Z.json"
    first.write_text('{"sentinel": 1}', encoding="utf-8")

    with manifest.capture(cfg, ["scan"]) as m:
        m["exit_code"] = 0

    second = tmp_path / "run_manifest_20260101T000000Z_01.json"
    assert second.exists()
    assert json.loads(first.read_text(encoding="utf-8")) == {"sentinel": 1}
    assert json.loads(second.read_text(encoding="utf-8"))["exit_code"] == 0


def test_capture_write_failure_is_swallowed(tmp_path, monkeypatch, frozen_time,
                                             no_git, no_models, capsys):
    """An OSError writing the manifest must not propagate."""
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("x", encoding="utf-8")
    out = tmp_path / "m.json"

    def boom(self, *a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(manifest.Path, "write_text", boom)

    # Should not raise despite the write failing.
    with manifest.capture(cfg, ["scan"], out=out) as m:
        m["exit_code"] = 0

    assert not out.exists()
    err = capsys.readouterr().err
    assert "failed to write run manifest" in err


def test_capture_accepts_str_cfg_path(tmp_path, frozen_time, no_git, no_models):
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("x", encoding="utf-8")
    out = tmp_path / "m.json"

    with manifest.capture(str(cfg), ["scan"], out=out) as m:
        assert m["config_profile"] == str(cfg)


# per-stage telemetry section

def test_capture_records_stage_durations_and_tokens(tmp_path, frozen_time,
                                                    no_git, monkeypatch):
    """End-to-end: recorded stages + real TOKENS usage + a price table on disk
    land in the manifest with an exact per-stage dollar cost."""
    from vvaharness.util.stage_telemetry import STAGES
    from vvaharness.util.tokens import TOKENS

    monkeypatch.setattr(manifest, "_models",
                        lambda cfg_path: {"decompose": {"id": "model-a",
                                                        "via": "cli"}})
    pricing_file = tmp_path / "pricing.yaml"
    pricing_file.write_text(
        "models:\n  model-a:\n    input_per_mtok: 3.0\n"
        "    output_per_mtok: 15.0\n", encoding="utf-8")
    monkeypatch.setenv("VVAHARNESS_PRICING_FILE", str(pricing_file))

    STAGES.start("s3", "Step 3 — Decompose")
    STAGES.done("s3", duration_sec=41.2)
    STAGES.mark("s4", "cached")
    with TOKENS.phase("s3-decompose"):
        TOKENS.add({"input_tokens": 1_000_000, "output_tokens": 100_000})

    cfg = tmp_path / "profile.yaml"
    cfg.write_text("k: v\n", encoding="utf-8")
    out = tmp_path / "m.json"
    with manifest.capture(cfg, ["scan"], out=out) as m:
        m["exit_code"] = 0

    written = json.loads(out.read_text(encoding="utf-8"))
    s3 = written["stages"]["s3"]
    assert s3["label"] == "Step 3 — Decompose"
    assert s3["outcome"] == "completed" and s3["duration_sec"] == 41.2
    assert s3["model"] == "model-a"
    # 1 MTok input at $3 + 0.1 MTok output at $15 = $4.50
    assert s3["cost_usd"] == pytest.approx(4.5)
    assert s3["cost_estimated"] is False
    # A cached stage is reported with no duration and no spend.
    assert written["stages"]["s4"]["outcome"] == "cached"
    assert written["stages"]["s4"]["duration_sec"] is None
    assert written["totals"]["total_tokens"] == 1_100_000
    assert written["totals"]["cost_usd"] == pytest.approx(4.5)
    assert written["pricing"]["source"] == "env"
    assert written["pricing"]["file"] == str(pricing_file)
    assert written == m


def test_capture_reports_null_costs_without_a_price_table(tmp_path, frozen_time,
                                                          no_git, monkeypatch):
    from vvaharness.util.stage_telemetry import STAGES
    from vvaharness.util.tokens import TOKENS

    monkeypatch.delenv("VVAHARNESS_PRICING_FILE", raising=False)
    monkeypatch.setattr(manifest, "_models",
                        lambda cfg_path: {"chain": {"id": "model-a",
                                                    "via": "cli"}})
    STAGES.done("s8", duration_sec=1.0)
    with TOKENS.phase("s8-chain"):
        TOKENS.add({"input_tokens": 10, "output_tokens": 2})

    cfg = tmp_path / "profile.yaml"
    cfg.write_text("k: v\n", encoding="utf-8")
    out = tmp_path / "m.json"
    with manifest.capture(cfg, ["scan"], out=out) as m:
        m["exit_code"] = 0

    assert m["stages"]["s8"]["tokens"]["prompt"] == 10
    assert m["stages"]["s8"]["cost_usd"] is None
    assert m["totals"]["cost_usd"] is None
    assert m["pricing"] is None


def test_capture_survives_telemetry_failure(tmp_path, frozen_time, no_git,
                                            no_models, monkeypatch, capsys):
    """Telemetry is reporting: a failure must cost the section, not the file."""
    from vvaharness.util import stage_telemetry

    def boom():
        raise RuntimeError("recorder exploded")

    monkeypatch.setattr(stage_telemetry.STAGES, "snapshot", boom)
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("k: v\n", encoding="utf-8")
    out = tmp_path / "m.json"

    with manifest.capture(cfg, ["scan"], out=out) as m:
        m["exit_code"] = 0

    assert out.exists()
    assert "stages" not in m
    assert "per-stage telemetry unavailable" in capsys.readouterr().err


# _config_sha256

def test_config_sha256_missing_returns_none(tmp_path):
    assert manifest._config_sha256(tmp_path / "nope.yaml") is None


def test_config_sha256_matches_hashlib(tmp_path):
    import hashlib
    cfg = tmp_path / "profile.yaml"
    data = b"some config bytes\n"
    cfg.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    assert manifest._config_sha256(cfg) == expected


# _scrub_argv  (secret redaction before argv lands in run_manifest.json)

def test_scrub_argv_redacts_flag_value_space_form():
    """`--git-token VALUE` (value in the next token) must be masked to ***."""
    out = manifest._scrub_argv(["scan", "--git-token", "ghp_" + "B" * 36])
    assert out == ["scan", "--git-token", "***"]


def test_scrub_argv_redacts_inline_equals_form():
    """`--anthropic-api-key=VALUE` (inline =VALUE) must be masked to flag=***."""
    out = manifest._scrub_argv(["scan", "--anthropic-api-key=sk-secret123456"])
    assert out == ["scan", "--anthropic-api-key=***"]


def test_scrub_argv_preserves_non_secret_keep_clones_decoy():
    """`key` alone must NOT trigger redaction — `--keep-clones` is preserved
    (guards the _SECRET_FLAG_RX bare-`key` exclusion against regression)."""
    out = manifest._scrub_argv(["scan", "--keep-clones", "--repo", "/x"])
    assert out == ["scan", "--keep-clones", "--repo", "/x"]


def test_scrub_argv_masks_secret_shaped_value_regardless_of_flag():
    """Second (shape) pass: an inline-credential URL passed as any argument is
    scrubbed even though `--repo` is not a secret-named flag."""
    url = "https://user:hunter2pw@host/r"
    out = manifest._scrub_argv(["scan", "--repo", url])
    assert "hunter2pw" not in " ".join(out)
    # Scheme + username preserved; only the password component is masked.
    assert out[2].startswith("https://user:") and out[2].endswith("@host/r")


def test_scrub_argv_leaves_ordinary_args_unchanged():
    """No secrets present -> argv passes through verbatim (no false positives)."""
    args = ["scan", "--repo", "/path/to/repo", "--config", "profile.yaml"]
    assert manifest._scrub_argv(args) == args


def test_capture_persisted_argv_contains_no_secrets(tmp_path, frozen_time,
                                                    no_git, no_models):
    """End-to-end regression guard for the run_manifest secret-persistence
    finding: secrets in argv must not survive into the on-disk manifest."""
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("x", encoding="utf-8")
    out = tmp_path / "m.json"
    secret_flag = "ghp_" + "C" * 36
    args = ["scan", "--repo", "https://u:topsecretpw@h/r",
            "--git-token", secret_flag, "--anthropic-api-key=sk-live-987654321"]

    with manifest.capture(cfg, args, out=out) as m:
        m["exit_code"] = 0

    raw = out.read_text(encoding="utf-8")
    assert secret_flag not in raw
    assert "topsecretpw" not in raw
    assert "sk-live-987654321" not in raw
    # Structure is otherwise intact.
    assert m["argv"][0] == "scan" and "--repo" in m["argv"]


def test_capture_includes_real_config_sha(tmp_path, frozen_time, no_git, no_models):
    import hashlib
    cfg = tmp_path / "profile.yaml"
    data = b"k: v\n"
    cfg.write_bytes(data)
    out = tmp_path / "m.json"

    with manifest.capture(cfg, ["scan"], out=out) as m:
        assert m["config_sha256"] == hashlib.sha256(data).hexdigest()


def test_capture_config_sha_none_when_missing(tmp_path, frozen_time, no_git, no_models):
    cfg = tmp_path / "absent.yaml"  # never created
    out = tmp_path / "m.json"
    with manifest.capture(cfg, ["scan"], out=out) as m:
        assert m["config_sha256"] is None


# _git_sha (subprocess mocked)

def test_git_sha_none_without_repo_arg():
    assert manifest._git_sha(["scan", "--verbose"]) is None


def test_git_sha_space_separated_repo(tmp_path, monkeypatch):
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        captured["cwd"] = kw.get("cwd")
        return types.SimpleNamespace(stdout="deadbeef\n", returncode=0)

    monkeypatch.setattr(manifest.subprocess, "run", fake_run)
    sha = manifest._git_sha(["scan", "--repo", str(tmp_path)])
    assert sha == "deadbeef"
    # Hardened form: no `-C`; the repo is passed as cwd (resolved), so the value
    # is never in git's option position.
    assert captured["cmd"] == ["git", "rev-parse", "HEAD"]
    assert captured["cwd"] == str(tmp_path.resolve())


def test_git_sha_equals_form_repo(tmp_path, monkeypatch):
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        captured["cwd"] = kw.get("cwd")
        return types.SimpleNamespace(stdout="abc123\n", returncode=0)

    monkeypatch.setattr(manifest.subprocess, "run", fake_run)
    sha = manifest._git_sha([f"--repo={tmp_path}"])
    assert sha == "abc123"
    assert captured["cmd"] == ["git", "rev-parse", "HEAD"]
    assert captured["cwd"] == str(tmp_path.resolve())


def test_git_sha_empty_output_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(
        manifest.subprocess, "run",
        lambda *a, **k: types.SimpleNamespace(stdout="   \n", returncode=0),
    )
    assert manifest._git_sha(["--repo", str(tmp_path)]) is None


def test_git_sha_subprocess_exception_returns_none(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise OSError("git not found")

    monkeypatch.setattr(manifest.subprocess, "run", boom)
    assert manifest._git_sha(["--repo", str(tmp_path)]) is None


def test_git_sha_nonexistent_repo_returns_none_without_spawning(tmp_path, monkeypatch):
    spawned = {"called": False}

    def fake_run(*a, **k):
        spawned["called"] = True
        return types.SimpleNamespace(stdout="x\n", returncode=0)

    monkeypatch.setattr(manifest.subprocess, "run", fake_run)
    missing = tmp_path / "does-not-exist"
    assert manifest._git_sha(["--repo", str(missing)]) is None
    assert spawned["called"] is False        # rejected before any git spawn


def test_git_sha_leading_dash_repo_returns_none_without_spawning(monkeypatch):
    # The reported option-injection payload: a leading-dash --repo value. It is
    # not a real directory, so it is rejected before git is ever invoked (and it
    # would be passed via cwd, never as a git option, even if it existed).
    spawned = {"called": False}

    def fake_run(*a, **k):
        spawned["called"] = True
        return types.SimpleNamespace(stdout="x\n", returncode=0)

    monkeypatch.setattr(manifest.subprocess, "run", fake_run)
    assert manifest._git_sha(["--repo", "--git-dir=/tmp/evil/.git"]) is None
    assert spawned["called"] is False


def test_capture_uses_git_sha(tmp_path, frozen_time, no_models, monkeypatch):
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("x", encoding="utf-8")
    out = tmp_path / "m.json"
    monkeypatch.setattr(
        manifest.subprocess, "run",
        lambda *a, **k: types.SimpleNamespace(stdout="feedface\n", returncode=0),
    )
    with manifest.capture(cfg, ["scan", "--repo", str(tmp_path)], out=out) as m:
        assert m["target_git_sha"] == "feedface"


# _models (config loader mocked)

def _patch_config(monkeypatch, models_obj):
    """Install a fake vvaharness.config whose load() yields *models_obj*.

    `manifest._models` does `from vvaharness import config`, which resolves
    to the `config` attribute already bound on the package object once any
    prior test has imported the real module. Patching only sys.modules is
    therefore insufficient when the suite runs together; patch the package
    attribute (auto-reverted by monkeypatch) so the import sees the fake.
    """
    # Pre-import so _models' lazy validate_role import resolves from the module
    # cache instead of executing against the fake vvaharness.config below.
    import vvaharness.validation.config.validate_role  # noqa: F401, PLC0415
    fake_cfg = types.SimpleNamespace(models=models_obj)
    fake_config_mod = types.SimpleNamespace(load=lambda p: fake_cfg)
    monkeypatch.setattr(__import__("vvaharness"), "config", fake_config_mod,
                        raising=False)
    monkeypatch.setitem(__import__("sys").modules, "vvaharness.config",
                        fake_config_mod)


def test_models_extracts_roles(monkeypatch, tmp_path):
    role = types.SimpleNamespace(id="model-x", via="sdk")
    models_obj = types.SimpleNamespace(
        autoexclude=role,
        preprocess=None,
        threatmodel=types.SimpleNamespace(id="model-y", via="cli"),
    )
    _patch_config(monkeypatch, models_obj)

    roles = manifest._models(tmp_path / "cfg.yaml")
    # provider is null when the profile pins none. resolved_route follows the
    # TRANSPORT: sdk and cli are hard-wired to Anthropic (anthropic.Anthropic
    # client / the `claude` binary), so even these non-claude-named ids — e.g.
    # a corporate-gateway alias — are honestly recorded as the anthropic route.
    assert roles["autoexclude"] == {"id": "model-x", "via": "sdk",
                                    "provider": None,
                                    "resolved_route": "anthropic",
                                    "resolved_transport": None,
                                    "use_responses_api": None}
    assert roles["threatmodel"] == {"id": "model-y", "via": "cli",
                                    "provider": None,
                                    "resolved_route": "anthropic",
                                    "resolved_transport": None,
                                    "use_responses_api": None}
    # None roles are skipped entirely.
    assert "preprocess" not in roles


def test_models_records_post_scan_roles(monkeypatch, tmp_path):
    """remediate and validate can spend real money, so the manifest must name
    their models too. validate is spelled as a nested `orchestrator` role."""
    models_obj = types.SimpleNamespace(
        deepdive=types.SimpleNamespace(id="model-dd", via="cli"),
        remediate=types.SimpleNamespace(id="model-rem", via="deepagents",
                                        provider="anthropic"),
        validate=types.SimpleNamespace(
            orchestrator=types.SimpleNamespace(id="model-val",
                                               via="deepagents")),
    )
    _patch_config(monkeypatch, models_obj)

    roles = manifest._models(tmp_path / "cfg.yaml")

    # deepagents picks its vendor per model: an explicit provider is recorded
    # verbatim and decides the route (here beating the non-claude model name);
    # without one the model name decides (model-val has no "claude" → openai).
    assert roles["remediate"] == {"id": "model-rem", "via": "deepagents",
                                  "provider": "anthropic",
                                  "resolved_route": "anthropic",
                                  "resolved_transport": None,
                                  "use_responses_api": None}
    assert roles["validate"] == {"id": "model-val", "via": "deepagents",
                                 "provider": None,
                                 "resolved_route": "openai",
                                 "resolved_transport": "responses",
                                 "use_responses_api": None}
    # cli is a fixed transport (the `claude` binary), so the non-claude model
    # name is irrelevant to the route.
    assert roles["deepdive"] == {"id": "model-dd", "via": "cli",
                                 "provider": None,
                                 "resolved_route": "anthropic",
                                 "resolved_transport": None,
                                 "use_responses_api": None}


def test_models_resolved_route_anthropic_from_model_name(monkeypatch, tmp_path):
    """deepagents with no provider pinned: the claude-named model decides the route."""
    models_obj = types.SimpleNamespace(
        threatmodel=types.SimpleNamespace(id="claude-opus-5", via="deepagents"),
    )
    _patch_config(monkeypatch, models_obj)

    roles = manifest._models(tmp_path / "cfg.yaml")
    assert roles["threatmodel"] == {"id": "claude-opus-5", "via": "deepagents",
                                    "provider": None,
                                    "resolved_route": "anthropic",
                                    "resolved_transport": None,
                                    "use_responses_api": None}


def test_models_explicit_provider_beats_model_name(monkeypatch, tmp_path):
    """On deepagents a pinned provider wins over the model-name heuristic —
    that is exactly the case where two runs with identical {id, via} hit
    different vendors, which recording provider + resolved_route exists to
    make reproducible."""
    models_obj = types.SimpleNamespace(
        dedup=types.SimpleNamespace(id="claude-compatible-proxy", via="deepagents",
                                    provider="openai"),
        chain=types.SimpleNamespace(id="gpt-5", via="openai", provider="openai"),
    )
    _patch_config(monkeypatch, models_obj)

    roles = manifest._models(tmp_path / "cfg.yaml")
    assert roles["dedup"] == {"id": "claude-compatible-proxy", "via": "deepagents",
                              "provider": "openai",
                              "resolved_route": "openai",
                              "resolved_transport": "responses",
                              "use_responses_api": None}
    assert roles["chain"] == {"id": "gpt-5", "via": "openai",
                              "provider": "openai",
                              "resolved_route": "openai",
                              "resolved_transport": None,
                              "use_responses_api": None}


def test_models_resolved_route_follows_via_not_model_name(monkeypatch, tmp_path):
    """The fixed transports decide the route; the model name is irrelevant.

    The two directions that a name-only heuristic gets wrong:
    a gateway alias without "claude" on via:sdk still hits the Anthropic API,
    and a claude-named model on via:openai still hits the OpenAI-compatible
    endpoint (full.yaml legitimately ships claude-named ids on other vias).
    """
    models_obj = types.SimpleNamespace(
        preprocess=types.SimpleNamespace(id="sonnet-4-6-gw-alias", via="sdk"),
        verify=types.SimpleNamespace(id="claude-opus-4-7", via="openai"),
        deepdive=types.SimpleNamespace(id="claude-opus-4-7", via="cli"),
        chain=types.SimpleNamespace(id="gpt-5", via="openai"),
    )
    _patch_config(monkeypatch, models_obj)

    roles = manifest._models(tmp_path / "cfg.yaml")
    assert roles["preprocess"]["resolved_route"] == "anthropic"
    assert roles["verify"]["resolved_route"] == "openai"
    assert roles["deepdive"]["resolved_route"] == "anthropic"
    assert roles["chain"]["resolved_route"] == "openai"
    # Even an explicit provider cannot re-route a fixed transport: it is
    # recorded verbatim but the via still decides the route.
    models_obj.verify.provider = "anthropic"
    roles = manifest._models(tmp_path / "cfg.yaml")
    assert roles["verify"] == {"id": "claude-opus-4-7", "via": "openai",
                               "provider": "anthropic",
                               "resolved_route": "openai",
                               "resolved_transport": None,
                               "use_responses_api": None}


def test_models_unknown_via_records_null_route(monkeypatch, tmp_path):
    """An unrecognised via yields resolved_route null, never a guessed vendor.

    Null is the manifest's convention for not-determinable (target_git_sha,
    config_local_sha256, provider); a confidently wrong vendor in the audit
    record would be the same defect this field was fixed for.
    """
    models_obj = types.SimpleNamespace(
        threatmodel=types.SimpleNamespace(id="claude-opus-5", via="grpc-sidecar"),
    )
    _patch_config(monkeypatch, models_obj)

    roles = manifest._models(tmp_path / "cfg.yaml")
    assert roles["threatmodel"] == {"id": "claude-opus-5", "via": "grpc-sidecar",
                                    "provider": None,
                                    "resolved_route": None,
                                    "resolved_transport": None,
                                    "use_responses_api": None}


def test_effective_scan_controls_include_cache_panel_and_input_hashes(tmp_path):
    import hashlib

    cve = tmp_path / "cves.json"
    cve.write_text('{"items": []}\n', encoding="utf-8")
    cfg = tmp_path / "profile.yaml"
    cfg.write_text(
        "cache_markers: 'on'\n"
        "cache_route: anthropic\n"
        "models:\n"
        "  remediate: {id: rem-model, via: deepagents, provider: anthropic}\n"
        "  validate:\n"
        "    orchestrator: {id: val-model, via: deepagents, provider: anthropic}\n"
        "    security_architect: {id: architect-model}\n"
        "    penetration_tester: {id: tester-model}\n"
        "    cross_repo_analyzer: {id: cross-repo-model}\n"
        "inject:\n"
        "  cve_file: ./cves.json\n",
        encoding="utf-8",
    )

    controls = manifest._effective_scan_controls(cfg)

    assert controls["cache"] == {
        "cache_markers": "on",
        "cache_route": "anthropic",
        "cache_min_block_tokens": None,
    }
    assert controls["validation_panel"]["orchestrator"] == {
        "id": "val-model", "via": "deepagents", "provider": "anthropic",
        "resolved_route": "anthropic",
    }
    # Personas inherit the orchestrator's route; a bare id never records "cli".
    assert controls["validation_panel"]["security_architect"] == {
        "id": "architect-model", "via": "deepagents", "provider": "anthropic",
        "resolved_route": "anthropic",
    }
    assert controls["remediation_model"] == {
        "id": "rem-model", "via": "deepagents", "provider": "anthropic"
    }
    assert controls["input_hashes"]["cve_file"] == {
        "path": "cves.json",
        "sha256": hashlib.sha256(cve.read_bytes()).hexdigest(),
    }


@pytest.mark.parametrize("enabled", [False, True])
def test_effective_scan_controls_include_catchall_deduct_lens_coverage(
        tmp_path, enabled):
    cfg = tmp_path / "profile.yaml"
    cfg.write_text(
        "models: {}\n"
        "step3:\n"
        f"  catchall_deduct_lens_coverage: {str(enabled).lower()}\n",
        encoding="utf-8",
    )

    controls = manifest._effective_scan_controls(cfg)

    assert controls["step3"]["catchall_deduct_lens_coverage"] is enabled


def test_panel_persona_declared_route_is_ignored(tmp_path):
    """A persona-level via/provider is dead config — the panel runs as
    subagents inside the orchestrator's session — so the manifest records the
    inherited route, not the declared one."""
    cfg = tmp_path / "profile.yaml"
    cfg.write_text(
        "models:\n"
        "  validate:\n"
        "    orchestrator: {id: val-model, via: deepagents, provider: anthropic}\n"
        "    security_architect: {id: architect-model, via: cli}\n",
        encoding="utf-8",
    )

    controls = manifest._effective_scan_controls(cfg)

    assert controls["validation_panel"]["security_architect"] == {
        "id": "architect-model", "via": "deepagents", "provider": "anthropic",
        "resolved_route": "anthropic",
    }


def test_panel_orchestrator_legacy_openai_via_records_normalized_route(tmp_path):
    # Legacy via:openai runs the panel on deepagents with the openai provider;
    # the manifest records that normalized route, not the raw spelling.
    cfg = tmp_path / "profile.yaml"
    cfg.write_text(
        "models:\n"
        "  validate:\n"
        "    orchestrator: {id: gpt-5.5, via: openai}\n",
        encoding="utf-8",
    )

    controls = manifest._effective_scan_controls(cfg)

    assert controls["validation_panel"]["orchestrator"] == {
        "id": "gpt-5.5", "via": "deepagents", "provider": "openai",
        "resolved_route": "openai",
    }


def test_models_validate_role_normalizes_legacy_openai_via(monkeypatch, tmp_path):
    # models.validate goes through the same normalizer as validation_panel, so
    # the two manifest sections can never disagree about the panel route.
    models_obj = types.SimpleNamespace(
        validate=types.SimpleNamespace(
            orchestrator=types.SimpleNamespace(id="gpt-5.5", via="openai")),
    )
    _patch_config(monkeypatch, models_obj)

    roles = manifest._models(tmp_path / "cfg.yaml")
    assert roles["validate"] == {"id": "gpt-5.5", "via": "deepagents",
                                 "provider": "openai",
                                 "resolved_route": "openai",
                                 "resolved_transport": "responses",
                                 "use_responses_api": None}


def test_panel_without_orchestrator_records_ids_only(tmp_path):
    # No orchestrator means validation cannot run and no route is derivable.
    cfg = tmp_path / "profile.yaml"
    cfg.write_text(
        "models:\n"
        "  validate:\n"
        "    security_architect: {id: architect-model, via: cli}\n",
        encoding="utf-8",
    )

    controls = manifest._effective_scan_controls(cfg)

    assert controls["validation_panel"] == {
        "security_architect": {"id": "architect-model"},
    }


def test_models_via_defaults_to_cli(monkeypatch, tmp_path):
    # A role object lacking a `via` attribute — or carrying an explicit
    # `via: null` — defaults to "cli", mirroring registry.resolve(); the cli
    # transport drives the `claude` binary, hence the anthropic route.
    class RoleNoVia:
        id = "only-id"

    models_obj = types.SimpleNamespace(
        deepdive=RoleNoVia(),
        verify=types.SimpleNamespace(id="null-via", via=None),
    )
    # Ensure other role names are absent -> getattr returns None.
    _patch_config(monkeypatch, models_obj)

    roles = manifest._models(tmp_path / "cfg.yaml")
    assert roles["deepdive"] == {"id": "only-id", "via": "cli",
                                 "provider": None,
                                 "resolved_route": "anthropic",
                                 "resolved_transport": None,
                                 "use_responses_api": None}
    assert roles["verify"] == {"id": "null-via", "via": "cli",
                               "provider": None,
                               "resolved_route": "anthropic",
                               "resolved_transport": None,
                               "use_responses_api": None}


def test_models_resolved_transport_records_the_responses_default(
        monkeypatch, tmp_path):
    """A deepagents role on the OpenAI branch is configured onto Responses."""
    models_obj = types.SimpleNamespace(
        deepdive=types.SimpleNamespace(id="gpt-5.5", via="deepagents",
                                       provider="openai"),
    )
    _patch_config(monkeypatch, models_obj)

    roles = manifest._models(tmp_path / "cfg.yaml")
    assert roles["deepdive"]["resolved_transport"] == "responses"
    assert roles["deepdive"]["use_responses_api"] is None


def test_models_resolved_transport_honours_the_config_pin(monkeypatch, tmp_path):
    """use_responses_api: false records the Chat Completions pin, and the raw knob."""
    models_obj = types.SimpleNamespace(
        deepdive=types.SimpleNamespace(id="gpt-5.5", via="deepagents",
                                       provider="openai",
                                       use_responses_api=False),
    )
    _patch_config(monkeypatch, models_obj)

    roles = manifest._models(tmp_path / "cfg.yaml")
    assert roles["deepdive"]["resolved_transport"] == "chat_completions"
    assert roles["deepdive"]["use_responses_api"] is False


def test_models_resolved_transport_is_null_off_the_openai_branch(
        monkeypatch, tmp_path):
    """No transport exists on the Anthropic route or the fixed transports."""
    models_obj = types.SimpleNamespace(
        remediate=types.SimpleNamespace(id="claude-opus-5", via="deepagents"),
        deepdive=types.SimpleNamespace(id="gpt-5.5", via="sdk"),
    )
    _patch_config(monkeypatch, models_obj)

    roles = manifest._models(tmp_path / "cfg.yaml")
    assert roles["remediate"]["resolved_transport"] is None
    assert roles["deepdive"]["resolved_transport"] is None


def test_model_spec_records_the_transport_knob():
    """_effective_scan_controls' model spec carries a boolean use_responses_api."""
    pinned = types.SimpleNamespace(id="gpt-5.5", via="deepagents",
                                   provider="openai", use_responses_api=False)
    unpinned = types.SimpleNamespace(id="gpt-5.5", via="deepagents")
    assert manifest._model_spec(pinned)["use_responses_api"] is False
    assert "use_responses_api" not in manifest._model_spec(unpinned)


def test_models_load_failure_returns_empty(monkeypatch, tmp_path, capsys):
    def boom(p):
        raise RuntimeError("bad config")

    fake_config_mod = types.SimpleNamespace(load=boom)
    monkeypatch.setattr(__import__("vvaharness"), "config", fake_config_mod,
                        raising=False)
    monkeypatch.setitem(__import__("sys").modules, "vvaharness.config",
                        fake_config_mod)

    assert manifest._models(tmp_path / "cfg.yaml") == {}
    assert "could not load model roles" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# counters dump
# ---------------------------------------------------------------------------
# The report renders only counters named in a hand-maintained whitelist in
# util/metrics.py, and that whitelist rots: every stage counter added since it
# was written was bumped at runtime and then discarded, reaching neither the
# report nor the manifest. Counters that measured real coverage loss — dropped
# reflection facts, whole files evicted on a scan error, threat-model parse
# repairs — were invisible for exactly that reason. The manifest is the
# engineer-facing surface, so it takes the whole snapshot and needs no
# maintenance.

def test_capture_dumps_all_counters_including_unwhitelisted(
        tmp_path, frozen_time, no_git, no_models):
    from vvaharness.util.counters import COUNTERS

    COUNTERS.reset_all()
    # One counter the report whitelist knows, and two it does not.
    COUNTERS.bump("s2_threats_raw", 7)
    COUNTERS.bump("s0_reflection_facts_dropped", 3)
    COUNTERS.bump("s0_files_dropped_scan_error")
    COUNTERS.note("s3_output_shape", "ids")

    cfg = tmp_path / "profile.yaml"
    cfg.write_text("k: v\n", encoding="utf-8")
    out = tmp_path / "manifest.json"
    try:
        with manifest.capture(cfg, ["scan"], out=out) as m:
            m["exit_code"] = 0
    finally:
        COUNTERS.reset_all()

    counters = m["counters"]
    assert counters["s2_threats_raw"] == 7
    assert counters["s0_reflection_facts_dropped"] == 3
    assert counters["s0_files_dropped_scan_error"] == 1
    # note() strings ride along in the same dict.
    assert counters["s3_output_shape"] == "ids"
    # Sorted for stable diffing between runs.
    assert list(counters) == sorted(counters)
    # And it survives the JSON round trip that actually reaches disk.
    import json
    assert json.loads(out.read_text(encoding="utf-8"))["counters"] == counters


def test_capture_omits_counters_key_when_nothing_was_counted(
        tmp_path, frozen_time, no_git, no_models):
    # An absent key beats `"counters": {}` — it keeps "nothing was measured"
    # distinguishable from "measured and all zero".
    from vvaharness.util.counters import COUNTERS

    COUNTERS.reset_all()
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("k: v\n", encoding="utf-8")
    out = tmp_path / "manifest.json"

    with manifest.capture(cfg, ["scan"], out=out) as m:
        m["exit_code"] = 0

    assert "counters" not in m


def test_counters_dump_survives_a_batch_reset(tmp_path, frozen_time, no_git,
                                              no_models):
    """batch.py calls COUNTERS.reset() per repo, but this manifest covers the
    whole CLI invocation — so a plain snapshot() would report only the last
    repo's tallies while presenting itself as the run's totals. An engineer
    reading s0_files_dropped_scan_error: 0 would conclude nothing was dropped.
    """
    from vvaharness.util.counters import COUNTERS

    COUNTERS.reset_all()
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("k: v\n", encoding="utf-8")
    out = tmp_path / "manifest.json"

    with manifest.capture(cfg, ["scan"], out=out) as m:
        COUNTERS.bump("s0_files_dropped_scan_error", 4)   # repo 1
        COUNTERS.note("s2_repo_kinds", "web-api")
        COUNTERS.reset()                                   # batch boundary
        COUNTERS.bump("s0_files_dropped_scan_error", 3)   # repo 2
        COUNTERS.note("s2_repo_kinds", "batch-etl")
        m["exit_code"] = 0

    counters = m["counters"]
    assert counters["s0_files_dropped_scan_error"] == 7, \
        "counts must sum across the batch, not report only the last repo"
    # Notes keep last-writer-wins, matching note()'s own contract.
    assert counters["s2_repo_kinds"] == "batch-etl"


# ---------------------------------------------------------------------------
# remediation/validation rollup
# ---------------------------------------------------------------------------
# s11 records a counts-only rollup of the case records it judged; the manifest
# carries the invocation-wide totals so a machine reader can tell "remediated
# and validated nothing" apart from "never validated" without re-globbing the
# target checkout.


def _record_one_case(repo, decision):
    """Put one judged FindingCase on disk under *repo* and record it."""
    from vvaharness.models import (
        Finding, FindingCase, Remediation, RemediationKind, Verdict,
    )
    from vvaharness.orchestrator import case_rollup
    from vvaharness.orchestrator.artifacts import CASE_DIR_NAME, CASE_FILE_NAME

    case = FindingCase(
        case_id="F-1",
        finding=Finding(title="t", file="app/x.py", line_start=3,
                        vuln_class="injection", severity="high",
                        case_id="F-1", cvss_score=7.5),
    ).with_attempt(
        Remediation(kind=RemediationKind.EDITS_APPLIED, summary="s",
                    files_touched=("app/x.py",), diff="x")
    ).with_verdict(Verdict(decision=decision, rationale="r"))
    sub = repo / CASE_DIR_NAME / "01_finding"
    sub.mkdir(parents=True)
    case.write(sub / CASE_FILE_NAME)
    case_rollup.record(repo)


def test_capture_records_the_remediation_rollup(tmp_path, frozen_time, no_git,
                                                no_models):
    from vvaharness.models import Decision

    _record_one_case(tmp_path / "repo", Decision.NOT_FIXED)

    cfg = tmp_path / "profile.yaml"
    cfg.write_text("k: v\n", encoding="utf-8")
    out = tmp_path / "manifest.json"
    with manifest.capture(cfg, ["scan"], out=out) as m:
        m["exit_code"] = 0

    assert m["remediation"] == {"cases": 1, "states": {"failed": 1},
                                "decisions": {"not_fixed": 1}}
    # And it survives the JSON round trip that actually reaches disk.
    assert json.loads(out.read_text(encoding="utf-8"))["remediation"] == \
        m["remediation"]


def test_capture_omits_remediation_when_nothing_was_recorded(
        tmp_path, frozen_time, no_git, no_models):
    # An absent key beats `"remediation": {}` — it keeps "S11 never ran" (a
    # --stop-after s10 run, a disabled step_validate, a preflight-disabled
    # stage) distinguishable from "validated and everything came back zero".
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("k: v\n", encoding="utf-8")
    out = tmp_path / "manifest.json"

    with manifest.capture(cfg, ["scan"], out=out) as m:
        m["exit_code"] = 0

    assert "remediation" not in m


def test_capture_survives_a_rollup_failure(tmp_path, frozen_time, no_git,
                                           no_models, monkeypatch):
    """Like telemetry, the rollup is reporting: a failure must cost the field,
    not the file."""
    from vvaharness.orchestrator import case_rollup

    def boom():
        raise RuntimeError("rollup exploded")

    monkeypatch.setattr(case_rollup, "totals", boom)
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("k: v\n", encoding="utf-8")
    out = tmp_path / "m.json"

    with manifest.capture(cfg, ["scan"], out=out) as m:
        m["exit_code"] = 0

    assert out.exists()
    assert "remediation" not in m


# ---------------------------------------------------------------------------
# S10 provenance backend label (audit attribution, same integrity family as
# the manifest's models section). Lives here because the engine_model tests'
# natural home, tests/test_remediation_agent_remediate.py, is owned by the
# remediation suite; this needs only a bare config namespace.
# ---------------------------------------------------------------------------

def _remediate_cfg(model_id, via, provider=None):
    return types.SimpleNamespace(models=types.SimpleNamespace(
        remediate=types.SimpleNamespace(id=model_id, via=via,
                                        provider=provider)))


def test_s10_provenance_is_left_untouched_by_this_branch():
    """S10/S11 are deliberately OUT OF SCOPE for this branch.

    An S10 `via: deepagents` run does execute on the harness family
    (plugin_runner._invoke branches to _invoke_deepagents), so `llm:deepagents`
    is arguably a misattribution — and this branch briefly relabelled it to
    `harness:deepagents`. That was reverted on purpose: `engine_model`'s pair is
    hashed into S10 resume checkpoint keys by `runner.step_key_of`, so
    relabelling silently invalidates every pre-upgrade `--resume` row. Fixing
    the label is a change to remediation behaviour and belongs in a branch that
    owns S10, with its own migration note. This test pins the non-change so the
    relabel cannot creep back in unnoticed.
    """
    from vvaharness.remediation_agent.plugin_runner.run import engine_model

    assert engine_model(_remediate_cfg("claude-opus-5", "deepagents")) == \
        ("claude-opus-5", "llm:deepagents")


def test_s10_llm_registry_vias_keep_the_llm_prefix():
    """cli/sdk remediate runs go through the llm registry's agentic() and must
    keep their genuine llm:* attribution — the harness relabel is conditional
    on the deepagents branch, not blanket."""
    from vvaharness.remediation_agent.plugin_runner.run import engine_model

    assert engine_model(_remediate_cfg("claude-opus-5", "sdk")) == \
        ("claude-opus-5", "llm:sdk")
    assert engine_model(_remediate_cfg("claude-opus-5", "cli")) == \
        ("claude-opus-5", "llm:cli")



# ── the EV collection and EV's model roles ───────────────────────────────────
#
# The collection comes from EV_API_COLLECTION rather than argv, so the captured argv no
# longer records which one a run verified against — the manifest has to name it itself.

def test_the_ev_collection_is_pinned_by_path_and_hash(tmp_path, monkeypatch):
    """Path plus digest, for the same reason the profile gets both: the path alone does not
    pin the contents a report's EV stamps were produced against."""
    import hashlib

    col = tmp_path / "collection.json"
    col.write_bytes(b'{"openapi": "3.0.0", "paths": {}}')
    monkeypatch.setenv("EV_API_COLLECTION", str(col))
    cfg = tmp_path / "config.yaml"
    cfg.write_text("models: {}\n")

    with manifest.capture(cfg, ["scan"], out=tmp_path / "m.json") as m:
        assert m["ev_api_collection"] == str(col)
        assert m["ev_api_collection_sha256"] == hashlib.sha256(col.read_bytes()).hexdigest()


def test_no_ev_collection_records_null_rather_than_omitting_the_field(tmp_path):
    """A SAST-only run still carries the keys, so a reader can tell "not configured" from
    "this manifest predates the field"."""
    cfg = tmp_path / "config.yaml"
    cfg.write_text("models: {}\n")
    with manifest.capture(cfg, ["scan"], out=tmp_path / "m.json") as m:
        assert m["ev_api_collection"] is None
        assert m["ev_api_collection_sha256"] is None


def test_a_configured_but_missing_collection_still_records_its_path(tmp_path, monkeypatch):
    """The path is what was asked for, so it is recorded either way; the absent digest is
    what says the file could not be read."""
    monkeypatch.setenv("EV_API_COLLECTION", str(tmp_path / "gone.json"))
    cfg = tmp_path / "config.yaml"
    cfg.write_text("models: {}\n")
    with manifest.capture(cfg, ["scan"], out=tmp_path / "m.json") as m:
        assert m["ev_api_collection"] == str(tmp_path / "gone.json")
        assert m["ev_api_collection_sha256"] is None


def test_ev_model_roles_are_recorded_under_their_dotted_names(tmp_path):
    """EV's roles are nested under models.exploit_verification, so the top-level loop
    misses them — and the judge is the confirmation authority, so which model held it
    belongs in the record."""
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "models:\n"
        "  verify: {id: model-a, via: sdk}\n"
        "  exploit_verification:\n"
        "    judge:    {id: model-j, via: cli}\n"
        "    attacker: {id: model-t, via: sdk}\n")
    roles = manifest._models(cfg)
    judge, attacker = roles["exploit_verification.judge"], roles["exploit_verification.attacker"]
    assert (judge["id"], judge["via"]) == ("model-j", "cli")
    assert (attacker["id"], attacker["via"]) == ("model-t", "sdk")
    # Same RECORD SHAPE as a top-level role, asserted by comparing key sets rather than
    # by restating the fields: the EV block builds its entries separately from the loop
    # over _MODEL_ROLES, so a field added to one and not the other is exactly the drift
    # worth catching, and it would otherwise leave EV roles quietly less auditable.
    assert set(judge) == set(roles["verify"]) and set(attacker) == set(roles["verify"])
    # ...and derived the same way: both these roles are via: sdk/cli, which resolve to
    # the same vendor route, so a divergence here means the EV block computed it itself.
    assert attacker["resolved_route"] == roles["verify"]["resolved_route"]
    # Absent EV sub-roles are omitted, not recorded as null: they are optional by design.
    assert "exploit_verification.classify" not in roles


def test_manifest_covers_every_top_level_model_role():
    """The manifest and the preflight keep their own role tuples, so a role added to one
    and not the other leaves the manifest silently under-reporting which models a run
    used. The one legitimate difference is exploit_verification: the preflight expands it
    generically via _SUB_ROLES, while the manifest records its nested roles in a separate
    block under dotted names (asserted by the test above)."""
    from vvaharness.orchestrator import config_paths
    assert (set(config_paths._MODEL_ROLES) - set(manifest._MODEL_ROLES)
            == {"exploit_verification"})
    # Symmetric: a role the manifest records that the preflight never probes would mean a
    # model the manifest claims for the run and no credential check covers.
    assert not set(manifest._MODEL_ROLES) - set(config_paths._MODEL_ROLES)
