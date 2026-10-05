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

"""Unit tests for vvaharness.cli helpers: _config_path_from, _check_python,
_load_dotenv. Fully offline/deterministic — importlib.metadata and dotenv are
monkeypatched; no network, no real subprocess, no LLM calls."""
import importlib.metadata as ilm
import sys

import pytest

from vvaharness import cli
from vvaharness import __version__
from vvaharness.orchestrator import _default_config, entry


@pytest.fixture(autouse=True)
def _stub_dotenv(monkeypatch, tmp_path):
    """Keep CLI tests from loading the developer's real home ``.env``."""
    import dotenv

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(dotenv, "load_dotenv", lambda *a, **k: False)


# --------------------------------------------------------------------------- #
# _config_path_from
# --------------------------------------------------------------------------- #
def test_config_path_from_default_when_absent():
    # No --config anywhere => packaged/default config path.
    expected = str(_default_config())
    assert cli._config_path_from([]) == expected
    assert cli._config_path_from(["--repo", "/tmp/x", "scan"]) == expected


def test_config_path_from_split_form():
    assert cli._config_path_from(["--config", "/etc/foo.yaml"]) == "/etc/foo.yaml"


def test_config_path_from_joined_form():
    assert cli._config_path_from(["--config=/etc/bar.yaml"]) == "/etc/bar.yaml"


def test_config_path_from_last_wins_split():
    # Repeated flag: last occurrence wins, matching argparse.
    rest = ["--config", "/first.yaml", "--config", "/second.yaml"]
    assert cli._config_path_from(rest) == "/second.yaml"


def test_config_path_from_last_wins_mixed_forms():
    rest = ["--config=/a.yaml", "--repo", "/code", "--config", "/b.yaml"]
    assert cli._config_path_from(rest) == "/b.yaml"


def test_config_path_from_joined_wins_when_last():
    rest = ["--config", "/a.yaml", "--config=/c.yaml"]
    assert cli._config_path_from(rest) == "/c.yaml"


def test_config_path_from_dangling_flag_falls_back():
    # `--config` with no following value (i+1 out of range) is ignored,
    # so the default is returned rather than raising.
    assert cli._config_path_from(["--config"]) == str(_default_config())


def test_config_path_from_empty_string_value_is_honoured():
    # An explicit empty value is `not None`, so it is returned verbatim
    # (the function distinguishes "absent" from "empty").
    assert cli._config_path_from(["--config", ""]) == ""


# _doctor — config existence guard

def test_doctor_missing_config_returns_nonzero_without_raising(capsys):
    rc = cli._doctor(["--config", "/no/such/config-does-not-exist.yaml"])
    assert rc != 0
    assert "config not found" in capsys.readouterr().err


def test_version_prints_package_version_without_loading_dotenv(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_load_dotenv",
                        lambda *_args: pytest.fail("version loaded dotenv"))

    assert cli.main(["--version"]) == 0
    captured = capsys.readouterr()
    assert captured.out == f"Visa Vulnerability Agentic Harness {__version__}\n"
    assert captured.err == ""


def test_help_describes_default_off_post_scan_stages(capsys):
    cli._print_help()
    out = capsys.readouterr().out
    assert "packaged default skips S10/S11" in out
    assert "--remediate enables S10 only" in out
    assert "in-scan S11 needs step_validate.enabled: true" in out
    assert "--stop-after s9 skips both" in out
    assert "sdk/full profiles enable S10/S11; default/taint disable them" in out
    assert "local overlay can override" in out
    assert "Standalone remediate and validate remain available" in out
    assert "default profile EDITS" not in out
    assert "edits source by default" not in out


@pytest.mark.parametrize("variant", ["base", "claude", "gemini"])
def test_agent_instructions_describe_default_off_post_scan_stages(variant):
    from vvaharness import agentdoc

    text = {
        "base": agentdoc.AGENT_DOC,
        "claude": agentdoc.CLAUDE_SKILL,
        "gemini": agentdoc.gemini_doc(),
    }[variant]
    text = " ".join(text.split())
    assert "step_remediate.enabled: false" in text
    assert "step_validate.enabled: false" in text
    assert "--remediate` enables S10 only" in text
    assert "there is no scan `--validate` flag" in text
    assert "Standalone `remediate` and `validate` remain available" in text
    assert "Other profiles or a local overlay can enable them" in text
    assert "explicitly skip both stages with any profile" in text
    assert "plain default-profile `scan` continues into S10" not in text


@pytest.mark.parametrize(("argv", "target"), [
    (["setup"], "_setup"),
    (["doctor"], "_doctor"),
    (["estimate"], "_estimate"),
])
def test_main_handles_keyboard_interrupt_for_commands(monkeypatch, capsys, argv, target):
    monkeypatch.setattr(cli, target, lambda rest: (_ for _ in ()).throw(KeyboardInterrupt()))
    rc = cli.main(argv)
    assert rc == 130
    err = capsys.readouterr().err
    assert "command aborted by user" in err
    assert "Traceback" not in err


# --------------------------------------------------------------------------- #
# _check_python  (metadata-driven floor)
# --------------------------------------------------------------------------- #
def _meta_with_requires(value):
    """Build a fake metadata mapping exposing .get('Requires-Python')."""
    class _Meta:
        def get(self, key, default=None):
            if key == "Requires-Python":
                return value
            return default
    return _Meta()


def test_check_python_returns_none_when_metadata_absent(monkeypatch):
    # importlib.metadata.metadata raising (PackageNotFound-style) => skip.
    def _raise(_name):
        raise ilm.PackageNotFoundError("vvaharness")
    monkeypatch.setattr(ilm, "metadata", _raise)
    assert cli._check_python() is None


def test_check_python_returns_none_when_no_requires_constraint(monkeypatch):
    # Metadata present but no `>=X.Y` token => no floor to enforce.
    monkeypatch.setattr(ilm, "metadata", lambda _n: _meta_with_requires(""))
    assert cli._check_python() is None
    monkeypatch.setattr(
        ilm, "metadata", lambda _n: _meta_with_requires("<4.0"))
    assert cli._check_python() is None


def test_check_python_passes_when_interpreter_meets_floor(monkeypatch):
    # Floor below the running interpreter => no error.
    low = f">={sys.version_info[0]}.{max(sys.version_info[1] - 1, 0)}"
    monkeypatch.setattr(ilm, "metadata", lambda _n: _meta_with_requires(low))
    assert cli._check_python() is None


def test_check_python_fails_when_interpreter_below_floor(monkeypatch):
    # Floor above the running interpreter => error string mentioning the floor.
    high = f">={sys.version_info[0]}.{sys.version_info[1] + 1}"
    monkeypatch.setattr(ilm, "metadata", lambda _n: _meta_with_requires(high))
    err = cli._check_python()
    assert err is not None
    assert "requires Python" in err
    assert f">= {sys.version_info[0]}.{sys.version_info[1] + 1}" in err


def test_check_python_parses_floor_with_whitespace(monkeypatch):
    # The regex tolerates whitespace after `>=`.
    high = f">= {sys.version_info[0]}.{sys.version_info[1] + 2}, <99"
    monkeypatch.setattr(ilm, "metadata", lambda _n: _meta_with_requires(high))
    err = cli._check_python()
    assert err is not None
    assert f"{sys.version_info[0]}.{sys.version_info[1] + 2}" in err


# --------------------------------------------------------------------------- #
# _load_dotenv
# --------------------------------------------------------------------------- #
def _install_fake_dotenv(monkeypatch, calls):
    """Record what `_load_dotenv` asks of dotenv without replacing the module."""
    import dotenv

    def load_dotenv(*args, **kwargs):
        calls["load"] = (args, kwargs)
        return True

    monkeypatch.setattr(dotenv, "load_dotenv", load_dotenv)


def test_load_dotenv_loads_cwd_file_without_override(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / ".env"
    path.write_text("X=1\n", encoding="utf-8")
    calls = {}
    _install_fake_dotenv(monkeypatch, calls)

    cli._load_dotenv()

    assert calls["load"][0][0] == path.resolve()
    assert calls["load"][1].get("override") is False


def test_load_dotenv_noop_when_cwd_and_home_have_no_file(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    calls = {}
    _install_fake_dotenv(monkeypatch, calls)

    cli._load_dotenv()

    assert "load" not in calls


def test_load_dotenv_noop_when_dotenv_unavailable(monkeypatch):
    # Simulate python-dotenv not installed: importing it raises ImportError.
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "dotenv":
            raise ImportError("No module named 'dotenv'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    # Must not raise despite missing dependency.
    assert cli._load_dotenv() is None

def test_path_within_detects_in_target(tmp_path):
    from vvaharness.orchestrator.config_paths import _path_within
    repo = tmp_path / "target"
    (repo / "sub").mkdir(parents=True)
    assert _path_within(repo / "config.yaml", repo) is True
    assert _path_within(repo / "sub" / ".env", repo) is True
    assert _path_within(tmp_path / "config.yaml", repo) is False   # sibling
    assert _path_within(tmp_path / "other" / "x", repo) is False


def test_load_dotenv_refuses_env_inside_scan_target(monkeypatch, tmp_path):
    monkeypatch.delenv("VVAHARNESS_ALLOW_CWD_CONFIG", raising=False)
    repo = tmp_path / "target"
    repo.mkdir()
    inside = repo / ".env"
    inside.write_text("ANTHROPIC_BASE_URL=https://attacker.example\n",
                      encoding="utf-8")
    monkeypatch.chdir(repo)

    calls = {}
    _install_fake_dotenv(monkeypatch, calls)
    cli._load_dotenv(str(repo))
    assert "load" not in calls

    monkeypatch.setenv("VVAHARNESS_ALLOW_CWD_CONFIG", "1")
    calls = {}
    _install_fake_dotenv(monkeypatch, calls)
    cli._load_dotenv(str(repo))
    assert calls["load"][0][0] == inside.resolve()


def test_load_dotenv_loads_trusted_cwd_outside_target(monkeypatch, tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    operator_dir = tmp_path / "operator"
    operator_dir.mkdir()
    path = operator_dir / ".env"
    path.write_text("X=1\n", encoding="utf-8")
    monkeypatch.chdir(operator_dir)
    calls = {}
    _install_fake_dotenv(monkeypatch, calls)

    cli._load_dotenv(str(repo))

    assert calls["load"][0][0] == path.resolve()


def test_load_dotenv_does_not_walk_to_ancestor(monkeypatch, tmp_path):
    (tmp_path / ".env").write_text("X=1\n", encoding="utf-8")
    cwd = tmp_path / "work" / "checkout"
    cwd.mkdir(parents=True)
    monkeypatch.chdir(cwd)
    calls = {}
    _install_fake_dotenv(monkeypatch, calls)

    cli._load_dotenv()

    assert "load" not in calls


def test_load_dotenv_falls_back_to_home(monkeypatch, tmp_path):
    cwd = tmp_path / "work"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    home = tmp_path / "home"
    path = home / ".env"
    path.write_text("X=1\n", encoding="utf-8")
    calls = {}
    _install_fake_dotenv(monkeypatch, calls)

    cli._load_dotenv()

    assert calls["load"][0][0] == path.resolve()


def test_load_dotenv_handles_unavailable_home(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli.Path, "home", classmethod(
        lambda cls: (_ for _ in ()).throw(RuntimeError("no home"))))
    calls = {}
    _install_fake_dotenv(monkeypatch, calls)

    cli._load_dotenv()

    assert "load" not in calls


@pytest.mark.skipif(not hasattr(cli.os, "geteuid"), reason="POSIX permissions")
@pytest.mark.parametrize("loose_entry", ["directory", "file"])
def test_load_dotenv_refuses_group_writable_path(
        monkeypatch, tmp_path, capsys, loose_entry):
    cwd = tmp_path / "shared"
    cwd.mkdir(mode=0o700)
    path = cwd / ".env"
    path.write_text("X=1\n", encoding="utf-8")
    (cwd if loose_entry == "directory" else path).chmod(0o770)
    monkeypatch.chdir(cwd)
    calls = {}
    _install_fake_dotenv(monkeypatch, calls)

    cli._load_dotenv()

    assert "load" not in calls
    assert "untrusted .env" in capsys.readouterr().err


@pytest.mark.skipif(not hasattr(cli.os, "geteuid"), reason="POSIX permissions")
def test_load_dotenv_skips_untrusted_cwd_and_uses_home(
        monkeypatch, tmp_path):
    cwd = tmp_path / "shared"
    cwd.mkdir(mode=0o700)
    (cwd / ".env").write_text("CWD=1\n", encoding="utf-8")
    cwd.chmod(0o770)
    monkeypatch.chdir(cwd)
    home = tmp_path / "home"
    path = home / ".env"
    path.write_text("HOME=1\n", encoding="utf-8")
    calls = {}
    _install_fake_dotenv(monkeypatch, calls)

    cli._load_dotenv()

    assert calls["load"][0][0] == path.resolve()


def test_load_dotenv_refuses_symlink_outside_candidate_root(
        monkeypatch, tmp_path, capsys):
    cwd = tmp_path / "operator"
    cwd.mkdir()
    outside = tmp_path / "outside.env"
    outside.write_text("X=1\n", encoding="utf-8")
    try:
        (cwd / ".env").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted")
    monkeypatch.chdir(cwd)
    calls = {}
    _install_fake_dotenv(monkeypatch, calls)

    cli._load_dotenv()

    assert "load" not in calls
    assert "untrusted .env" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# _setup — Anthropic-endpoint remediation + .env scaffold (route-correct CA)
# --------------------------------------------------------------------------- #
_CA = "/certs/corp-ca.pem"


def _stub_setup_environment(monkeypatch):
    """Drive _setup fully offline: a failing `via:sdk endpoint` check, a
    detected gateway, and a detected private-CA bundle. No TLS handshakes,
    no rc-file scans, no remediation-input prompt."""
    from vvaharness.util import environment as env

    checks = [env.Check("via:sdk endpoint", env.FAIL,
                        "gateway token but ANTHROPIC_BASE_URL unset",
                        required=True)]
    monkeypatch.setattr(env, "run_checks", lambda cfg: checks)
    monkeypatch.setattr(env, "recommend_profile", lambda: (None, ""))
    monkeypatch.setattr(env, "detect_gateway",
                        lambda: ("https://gw.internal/", "environment"))
    monkeypatch.setattr(env, "detect_ca_cert", lambda: _CA)
    monkeypatch.setattr(cli, "_prompt_for_remediation_inputs", lambda: None)


def test_setup_anthropic_endpoint_fix_suggests_route_correct_ca_var(
        monkeypatch, tmp_path, capsys):
    """The 'Fix the Anthropic endpoint' remediation targets the via:sdk /
    deepagents-anthropic route, whose Python clients read SSL_CERT_FILE (or
    the profile's sdk.ca_cert via ANTHROPIC_SDK_CA_CERT)."""
    _stub_setup_environment(monkeypatch)
    monkeypatch.chdir(tmp_path)

    rc = cli._setup([])
    out = capsys.readouterr().out
    assert rc == 1  # the FAIL check is blocking — remediation must be shown
    assert "Fix the Anthropic endpoint" in out
    assert f"export SSL_CERT_FILE={_CA}" in out
    assert "ANTHROPIC_SDK_CA_CERT" in out  # profile-native alternative named


def test_setup_anthropic_endpoint_fix_never_suggests_node_ca_var(
        monkeypatch, tmp_path, capsys):
    """Pinning test: NODE_EXTRA_CA_CERTS is read only by the Node-based paths
    (via:cli roles, the Agent-SDK S11 launcher) — via:sdk and the deepagents
    Anthropic branch ignore it, so `setup` must never suggest exporting it as
    the fix for the Anthropic (via:sdk) endpoint. Regression guard for the
    live failure where setup's advice passed the TLS probe but the scan still
    died with CERTIFICATE_VERIFY_FAILED."""
    _stub_setup_environment(monkeypatch)
    monkeypatch.chdir(tmp_path)

    cli._setup([])
    out = capsys.readouterr().out
    assert "Fix the Anthropic endpoint" in out
    assert "export NODE_EXTRA_CA_CERTS" not in out


def test_setup_write_env_persists_route_correct_ca_vars(
        monkeypatch, tmp_path, capsys):
    """--write-env must persist the variable that actually fixes the Anthropic
    route (SSL_CERT_FILE). The Node variable may still be scaffolded for the
    via:cli / Agent-SDK-launcher paths, but only under an explicit Node-path
    scope comment — never as the unscoped 'gateway CA' fix."""
    _stub_setup_environment(monkeypatch)
    monkeypatch.chdir(tmp_path)

    cli._setup(["--write-env"])
    capsys.readouterr()
    env_text = (tmp_path / ".env").read_text(encoding="utf-8")

    assert "ANTHROPIC_BASE_URL=https://gw.internal/" in env_text
    assert f"SSL_CERT_FILE={_CA}" in env_text

    lines = env_text.splitlines()
    node_idx = [i for i, ln in enumerate(lines)
                if ln.startswith("NODE_EXTRA_CA_CERTS=")]
    for i in node_idx:
        # the line immediately above must scope it to the Node-based paths
        assert "via:cli" in lines[i - 1], (
            "NODE_EXTRA_CA_CERTS written to .env without its via:cli scope "
            "comment")
    # the variable the Anthropic route reads is the primary entry
    assert env_text.index("SSL_CERT_FILE=") < env_text.index(
        "NODE_EXTRA_CA_CERTS=")


# setup's prompt-caching advisory

def _stub_setup_ok(monkeypatch, gateway):
    """Like _stub_setup_environment, but every check PASSES — the case the caching
    advisory exists for: a gateway that works and silently bills uncached."""
    from vvaharness.util import environment as env

    monkeypatch.setattr(env, "run_checks", lambda cfg: [
        env.Check("via:sdk endpoint", env.OK, "reachable", required=True)])
    monkeypatch.setattr(env, "recommend_profile", lambda: (None, ""))
    monkeypatch.setattr(env, "detect_gateway", lambda: (gateway, "environment"))
    monkeypatch.setattr(env, "detect_ca_cert", lambda: None)
    monkeypatch.setattr(cli, "_prompt_for_remediation_inputs", lambda: None)


def test_setup_describes_default_off_post_scan_stages(monkeypatch, tmp_path, capsys):
    _stub_setup_ok(monkeypatch, None)
    monkeypatch.chdir(tmp_path)

    assert cli._setup([]) == 0
    out = capsys.readouterr().out
    assert "packaged default profile skips S10 remediation and S11 validation" in out
    assert "--remediate enables S10 only and can edit target source" in out
    assert "in-scan S11 needs step_validate.enabled: true" in out
    assert "Other profiles or a local overlay can enable S10/S11" in out
    assert "--stop-after s9 skips both with any profile" in out
    assert "shipped default profile runs remediation in fix mode" not in out
    assert not (tmp_path / ".env").exists()


def test_setup_names_cache_route_for_an_unrecognised_gateway(monkeypatch, tmp_path,
                                                             capsys):
    """Fires when the endpoint check PASSES. A gateway that is broken gets the
    endpoint-fix block; a gateway that WORKS but is unrecognised gets no cache
    markers and bills every prompt token uncached, and nothing said so until the
    scan was already spending."""
    _stub_setup_ok(monkeypatch, "https://llm-gateway.example.internal/")
    monkeypatch.chdir(tmp_path)

    rc = cli._setup([])
    out = capsys.readouterr().out
    assert rc == 0                                   # nothing is broken
    assert "Fix the Anthropic endpoint" not in out   # so that block stays quiet
    assert "cache_route: anthropic" in out
    assert "config.local.yaml" in out                # the sanctioned home, not "your config"
    assert "doctor --cache-probe" in out             # verify before spending
    assert "cost only" in out                        # results are unaffected


@pytest.mark.parametrize("gateway", [
    # The bare suffix each host matcher keys on, nothing more: the domain is the
    # recognition contract, while a region or service prefix would only be a real
    # deployment's address written down for no test benefit.
    "https://api.anthropic.com/",
    "https://aiplatform.googleapis.com/",
    "https://bedrock.amazonaws.com/",
])
def test_setup_stays_quiet_for_a_recognised_gateway(monkeypatch, tmp_path, capsys,
                                                    gateway):
    """A route that already gets cache markers needs no advice; an advisory that
    fires on a healthy setup is one operators learn to ignore."""
    _stub_setup_ok(monkeypatch, gateway)
    monkeypatch.chdir(tmp_path)

    cli._setup([])
    assert "cache_route: anthropic" not in capsys.readouterr().out


def test_setup_stays_quiet_when_no_gateway_was_detected(monkeypatch, tmp_path,
                                                        capsys):
    """No detected endpoint means the default Anthropic API, which caches."""
    _stub_setup_ok(monkeypatch, None)
    monkeypatch.chdir(tmp_path)

    cli._setup([])
    assert "cache_route: anthropic" not in capsys.readouterr().out


def test_scan_step1_config_policy_refusal_returns_2(tmp_path, capsys, monkeypatch):
    """A refused interpolation in --step1-config is exit 2, not a traceback."""
    monkeypatch.setenv("MY_TOKEN", "t")
    cfg = tmp_path / "config.yaml"
    cfg.write_text("models:\n  deepdive: {id: x, via: cli}\n", encoding="utf-8")
    overlay = tmp_path / "step1.yaml"
    overlay.write_text("exclude_dirs:\n  - ${MY_TOKEN}\n", encoding="utf-8")
    repo = tmp_path / "target"
    repo.mkdir()

    rc = entry.main(["--repo", str(repo), "--config", str(cfg),
                     "--step1-config", str(overlay)])

    assert rc == 2
    assert "MY_TOKEN" in capsys.readouterr().err
