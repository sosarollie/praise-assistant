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

"""The environment readiness engine behind `vvaharness setup` / `doctor`."""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from vvaharness import cli
from vvaharness.remediation_agent import rule_paths
from vvaharness.util import environment as env
from vvaharness.util.environment import FAIL, OK, WARN


def _clear_anthropic(monkeypatch):
    for v in ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(v, raising=False)


def test_gateway_jwt_without_base_url_is_blocking(monkeypatch):
    _clear_anthropic(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "eyJhbGciOiJI.fake.jwt")  # JWT shape
    c = env._gateway_check()
    assert c.status == FAIL
    assert c.required is True
    assert "ANTHROPIC_BASE_URL" in c.detail


def test_gateway_ok_when_base_url_set(monkeypatch):
    _clear_anthropic(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "eyJhbGciOiJI.fake.jwt")  # JWT shape
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://api.example/")
    c = env._gateway_check()
    assert c.status == OK
    assert "api.example" in c.detail


def test_gateway_ok_with_real_key_no_base_url(monkeypatch):
    _clear_anthropic(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-realkey")
    assert env._gateway_check().status == OK


def test_gateway_fail_private_ca_hint_is_route_correct(monkeypatch):
    """The via:sdk endpoint FAIL must name a CA source via:sdk actually reads.

    via:sdk (anthropic-SDK/httpx) honours SSL_CERT_FILE or sdk.ca_cert and
    NEVER reads NODE_EXTRA_CA_CERTS — recommending the Node variable here sent
    operators down a dead end (probe green, scan still
    CERTIFICATE_VERIFY_FAILED). Pin the corrected advice so it cannot regress.
    """
    _clear_anthropic(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "eyJhbGciOiJI.fake.jwt")  # JWT shape
    c = env._gateway_check()
    assert c.status == FAIL
    assert "SSL_CERT_FILE" in c.detail
    assert "sdk.ca_cert" in c.detail
    assert "NODE_EXTRA_CA_CERTS" not in c.detail


def test_tls_check_fail_hint_names_route_correct_variables(monkeypatch):
    """On SSLCertVerificationError the generic TLS check must lead with
    SSL_CERT_FILE (honoured by via:sdk and via:deepagents) and confine
    NODE_EXTRA_CA_CERTS to via:cli — never recommend exporting the Node
    variable as the fix for every route."""
    import ssl as _ssl

    def _raise(*a, **k):
        raise _ssl.SSLCertVerificationError("boom")

    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    monkeypatch.setattr(env.socket, "create_connection", _raise)

    # With a detected bundle: the export line must target SSL_CERT_FILE.
    monkeypatch.setattr(env, "detect_ca_cert", lambda: "/tmp/ca.pem")
    c = env.tls_check()
    assert c.status == FAIL
    assert "export SSL_CERT_FILE=/tmp/ca.pem" in c.detail
    assert "export NODE_EXTRA_CA_CERTS" not in c.detail
    assert "via:cli" in c.detail  # the Node variable is scoped to via:cli

    # Without a bundle: same variable priority in the generic advice.
    monkeypatch.setattr(env, "detect_ca_cert", lambda: None)
    c = env.tls_check()
    assert c.status == FAIL
    assert "SSL_CERT_FILE" in c.detail
    assert "via:cli" in c.detail


def test_tls_check_ok_via_bundle_scopes_node_variable(monkeypatch, tmp_path):
    """A handshake that only succeeded via NODE_EXTRA_CA_CERTS proves reach for
    via:cli alone — the OK detail must say via:sdk/deepagents-Anthropic still
    need SSL_CERT_FILE or sdk.ca_cert (the live false-green trap)."""
    ca = tmp_path / "ca.pem"
    ca.write_text("dummy", encoding="utf-8")
    monkeypatch.setenv("NODE_EXTRA_CA_CERTS", str(ca))
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)

    class _Sock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Ctx:
        def wrap_socket(self, sock, server_hostname=None):
            return _Sock()

    monkeypatch.setattr(env.socket, "create_connection",
                        lambda *a, **k: _Sock())
    monkeypatch.setattr(env.ssl, "create_default_context",
                        lambda cafile=None: _Ctx())
    c = env.tls_check()
    assert c.status == OK
    assert "NODE_EXTRA_CA_CERTS" in c.detail
    assert "SSL_CERT_FILE" in c.detail  # names what via:sdk/deepagents need


def test_credential_checks_presence_only(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret-value-123")
    checks = env.credential_checks()
    openai = next(c for c in checks if c.name == "cred: OPENAI_API_KEY")
    assert openai.status == OK
    assert openai.detail == "set"               # never the value
    assert "secret" not in openai.detail


def test_required_deps_present():
    deps = {c.name: c for c in env.dep_checks()}
    assert deps["dep: pydantic"].status == OK
    assert deps["dep: anthropic"].status == OK


def test_dep_checks_warn_when_tree_sitter_missing(monkeypatch):
    real_find_spec = env.importlib.util.find_spec

    def fake_find_spec(name):
        if name in {"tree_sitter", "tree_sitter_language_pack"}:
            return None
        return real_find_spec(name)

    monkeypatch.setattr(env.importlib.util, "find_spec", fake_find_spec)
    deps = {c.name: c for c in env.dep_checks()}

    ts = deps["dep: tree-sitter"]
    assert ts.status == WARN
    assert "degraded taint coverage" in ts.detail

    tsp = deps["dep: tree-sitter-language-pack"]
    assert tsp.status == WARN
    assert "AST plugins unavailable" in tsp.detail


def test_python_check_ok_on_current_interpreter():
    assert env.python_check().status == OK


# anthropic_version_check: the ceiling is read from our own metadata, so the
# tests supply that metadata rather than depending on how this checkout was
# installed (a source-tree run has no vvaharness distribution metadata at all).

def _fake_anthropic_env(monkeypatch, *, installed, declared="anthropic<1.0,>=0.125.0"):
    # NB the default `declared` puts the ceiling FIRST, because that is what
    # packaging actually emits: it normalises a two-sided requirement and
    # reorders the clauses (verified against the installed langchain-anthropic,
    # whose Requires-Dist reads "anthropic<1.0.0,>=0.120.0"). Asserting on the
    # hand-authored pyproject order would test a shape that never reaches the
    # code in a built install.
    real_version = env.importlib.metadata.version

    def fake_version(name):
        if name != "anthropic":
            return real_version(name)
        if installed is None:
            raise env.importlib.metadata.PackageNotFoundError(name)
        return installed

    real_requires = env.importlib.metadata.requires

    def fake_requires(name):
        # Delegate for anything else: this patches the stdlib module globally
        # for the test's duration, so an incidental lookup (a pytest plugin, an
        # entry point) must not fail the test for an unrelated reason.
        if name != "vvaharness":
            return real_requires(name)
        if declared is None:
            raise env.importlib.metadata.PackageNotFoundError(name)
        return ["pydantic>=2.13.5", declared, "langchain-anthropic>=1.7.0"]

    monkeypatch.setattr(env.importlib.metadata, "version", fake_version)
    monkeypatch.setattr(env.importlib.metadata, "requires", fake_requires)


@pytest.mark.parametrize("declared", [
    "anthropic<1.0,>=0.125.0",   # what packaging normalises the pin to
    "anthropic>=0.125.0,<1.0",   # what pyproject.toml declares by hand
])
def test_anthropic_version_check_ok_when_in_range(monkeypatch, declared):
    """Clause ORDER must not matter: the detail has to name the ceiling either
    way, since that string is what tells an operator the pin is in force."""
    _fake_anthropic_env(monkeypatch, installed="0.125.0", declared=declared)
    c = env.anthropic_version_check()
    assert c.status == OK and not c.required
    assert "<1.0" in c.detail


def test_anthropic_version_check_fails_on_1x(monkeypatch):
    """The whole point of the row: a pin cannot fix an already-built venv that
    someone upgraded in place, so doctor has to say so."""
    _fake_anthropic_env(monkeypatch, installed="1.2.0")
    c = env.anthropic_version_check()
    assert c.status == FAIL and c.required
    # The detail must stay actionable: the remedy and the reason.
    assert "anthropic<1" in c.detail
    assert "temperature" in c.detail


def test_anthropic_version_check_ok_without_version_metadata(monkeypatch):
    """`dep: anthropic` already blocks when the package cannot be imported, and
    it probes importability while this row needs .dist-info — so a vendored or
    `pip install --target` anthropic reaches here importable but metadata-less.
    Must degrade quietly instead of contradicting the row above."""
    _fake_anthropic_env(monkeypatch, installed=None)
    c = env.anthropic_version_check()
    assert c.status == OK and not c.required
    assert "no version metadata" in c.detail


@pytest.mark.parametrize("declared, installed", [
    # A ceiling inside the SAME major must not reject the versions it allows:
    # a major-only comparison read this as 0 < 0 and hard-blocked a compliant
    # environment with the unsatisfiable remedy `pip install 'anthropic<0'`.
    ("anthropic<0.200,>=0.124.0", "0.124.0"),
    ("anthropic<1.5,>=1.2", "1.3.0"),
])
def test_anthropic_version_check_ok_for_compliant_two_sided_bounds(
        monkeypatch, declared, installed):
    _fake_anthropic_env(monkeypatch, installed=installed, declared=declared)
    c = env.anthropic_version_check()
    assert c.status == OK and not c.required, c.detail


def test_anthropic_version_check_ignores_a_pep440_epoch(monkeypatch):
    """`_release` drops the epoch, so `1!0.5.0` compares as `0.5.0` and passes a
    `<1.0` ceiling.

    Recorded as a known limit rather than as correct behaviour: under PEP 440 the
    epoch dominates ordering, so `1!0.5.0` does NOT satisfy `<1.0` and a stricter
    check would FAIL it. Deliberate — an epoch on `anthropic` is hypothetical, and
    a readiness row that fails open is the right trade against one that
    mis-blocks. If anthropic ever ships an epoch, this is the case to revisit."""
    _fake_anthropic_env(monkeypatch, installed="1!0.5.0",
                        declared="anthropic<1.0,>=0.124.0")
    c = env.anthropic_version_check()
    assert c.status == OK and not c.required


def test_anthropic_version_check_degrades_without_metadata(monkeypatch):
    """No distribution metadata (a source-tree run) means no declared ceiling
    to compare against: report OK, never raise out of a readiness check."""
    _fake_anthropic_env(monkeypatch, installed="1.2.0", declared=None)
    c = env.anthropic_version_check()
    assert c.status == OK and not c.required


def test_run_checks_reports_anthropic_version_after_the_dep_rows(monkeypatch,
                                                                tmp_path):
    monkeypatch.chdir(tmp_path)
    # Keep this offline: tls_check does a real handshake.
    monkeypatch.setattr(env, "tls_check",
                        lambda: env.Check("TLS / CA cert", OK, "stub"))
    cfg = tmp_path / "config.yaml"
    cfg.write_text("models:\n  deepdive: {id: x, via: cli}\n", encoding="utf-8")
    names = [c.name for c in env.run_checks(cfg)]
    # Adjacency to `dep: anthropic` rather than to whatever _DEPS lists last:
    # the two rows must read together, but appending an unrelated optional dep
    # must not fail a test about the anthropic row.
    assert "anthropic version" in names
    assert names.index("anthropic version") > names.index("dep: anthropic")


def test_sdk_profile_flags_missing_key(monkeypatch, tmp_path):
    # Clear ALL Anthropic creds, not just the SDK key — the sole-sdk profile
    # accepts ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN as a fallback, so leaving
    # those set (as a dev/CI shell often does) would mask the missing-key path.
    _clear_anthropic(monkeypatch)
    monkeypatch.delenv("ANTHROPIC_SDK_API_KEY", raising=False)
    cfg = tmp_path / "p.yaml"
    cfg.write_text("models:\n  deepdive: {id: x, via: sdk}\n", encoding="utf-8")
    checks = env.config_check(cfg)
    blocking = [c for c in checks if c.status == FAIL and c.required]
    assert any("ANTHROPIC_SDK_API_KEY" in c.detail for c in blocking)


def test_missing_config_is_blocking(tmp_path):
    checks = env.config_check(tmp_path / "nope.yaml")
    assert checks[0].status == FAIL and checks[0].required


def test_summarize_counts():
    checks = [env.Check("a", OK, ""), env.Check("b", WARN, ""),
              env.Check("c", FAIL, "", required=True),
              env.Check("d", FAIL, "", required=False)]
    n_ok, n_warn, n_block = env.summarize(checks)
    assert (n_ok, n_warn, n_block) == (1, 1, 1)


def test_remediation_inputs_missing_is_blocking(monkeypatch, tmp_path):
    monkeypatch.setattr(rule_paths, "candidate_inputs_dirs",
                        lambda _package_file: (tmp_path,))
    check = env.remediation_inputs_check()
    assert check.status == FAIL
    assert check.required is True
    assert "interactive `vvaharness setup`" in check.detail


def test_setup_prompt_persists_valid_inputs_dir(monkeypatch, tmp_path, capsys):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    for name in rule_paths.RULE_FILES:
        (inputs / name).write_text("schema_version: '1.0'\n", encoding="utf-8")
    settings = tmp_path / "settings.json"
    missing_dir = tmp_path / "missing"
    monkeypatch.setenv("VVAHARNESS_SETTINGS_FILE", str(settings))

    def candidates(_package_file):
        configured = rule_paths.configured_inputs_dir()
        return (missing_dir,) + ((configured,) if configured else ())
    monkeypatch.setattr(rule_paths, "candidate_inputs_dirs", candidates)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: str(inputs))

    cli._prompt_for_remediation_inputs()

    assert rule_paths.configured_inputs_dir() == inputs.resolve()
    assert "saved remediation inputs directory" in capsys.readouterr().out


def test_setup_command_blocks_on_gateway_gap(monkeypatch, tmp_path, capsys):
    _clear_anthropic(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "eyJhbGciOiJI.fake.jwt")  # JWT shape
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "sdk.yaml"
    cfg.write_text("models:\n  deepdive: {id: x, via: sdk}\n", encoding="utf-8")
    rc = cli.main(["setup", "--config", str(cfg)])
    out = capsys.readouterr().out
    assert "setup" in out
    assert "via:sdk endpoint" in out
    # gateway gap is blocking → non-zero, "Not ready"
    assert rc == 1
    assert "Not ready" in out


@pytest.mark.parametrize("alias", ["setup", "init"])
def test_setup_and_init_are_aliases(alias, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "p.yaml"
    cfg.write_text("models:\n  deepdive: {id: x, via: cli}\n", encoding="utf-8")
    # both must dispatch to the wizard (don't assert exit code — env-dependent)
    rc = cli.main([alias, "--config", str(cfg)])
    assert rc in (0, 1)


def test_detect_gateway_from_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://gw.example/")
    url, src = env.detect_gateway()
    assert url == "https://gw.example/" and src == "environment"


def test_detect_gateway_from_rc_file(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    monkeypatch.setattr(env.Path, "home", lambda: tmp_path)
    (tmp_path / ".zshrc").write_text(
        '#export ANTHROPIC_BASE_URL="https://ai.example/"\n', encoding="utf-8")
    url, src = env.detect_gateway()
    assert url == "https://ai.example/" and src == "~/.zshrc"


def test_recommend_default_when_jwt_and_claude(monkeypatch):
    # JWT gateway token + the claude CLI present = Claude Code auth → the
    # CLI-first default profile (every role via: cli).
    monkeypatch.delenv("ANTHROPIC_SDK_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "eybc.def.ghi")
    monkeypatch.setattr(env.shutil, "which", lambda c: "/usr/bin/claude" if c == "claude" else None)
    prof, _ = env.recommend_profile()
    assert prof == "default"


def test_recommend_sdk_when_only_sdk_key(monkeypatch, tmp_path):
    # An SDK key but NO Claude Code auth: sdk.yaml is the drop-in all-SDK
    # profile (every role via: sdk), so it is the right recommendation.
    monkeypatch.setattr(env.Path, "home", lambda: tmp_path)   # no on-disk CLI login
    monkeypatch.setattr(env.shutil, "which", lambda c: None)  # no claude on PATH
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-x")
    assert env.recommend_profile()[0] == "sdk"


def test_claude_agent_uses_claude_json_login(monkeypatch, tmp_path):
    monkeypatch.setattr(env.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(env.shutil, "which", lambda c: "/usr/bin/claude" if c == "claude" else None)
    (tmp_path / ".claude.json").write_text('{"oauthAccount":{"emailAddress":"u@example.test"}}', encoding="utf-8")

    checks = env.agent_checks()
    claude = next(c for c in checks if c.name == "agent: Claude Code")
    assert claude.status == OK
    assert "installed and logged in" in claude.detail


def test_copilot_replaces_aider_in_agent_checks(monkeypatch):
    monkeypatch.setattr(env.shutil, "which", lambda c: "/usr/bin/copilot" if c == "copilot" else None)
    checks = env.agent_checks()
    names = [c.name for c in checks]
    assert "agent: GitHub Copilot CLI" in names
    assert "agent: Aider" not in names
    copilot = next(c for c in checks if c.name == "agent: GitHub Copilot CLI")
    assert copilot.status == OK
    assert copilot.detail == "copilot ✓ (via:cli) — installed"


def test_dotenv_check_detects_current_dir(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("X=1\n", encoding="utf-8")
    check = env.dotenv_check()
    assert check.status == OK
    assert check.name == ".env"
    assert check.detail == ".env found"


def test_dotenv_check_ignores_ancestor_and_reports_home(monkeypatch, tmp_path):
    (tmp_path / ".env").write_text("ANCESTOR=1\n", encoding="utf-8")
    cwd = tmp_path / "work" / "checkout"
    cwd.mkdir(parents=True)
    home = tmp_path / "home"
    home.mkdir()
    home_env = home / ".env"
    home_env.write_text("HOME=1\n", encoding="utf-8")
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(cli.Path, "home", classmethod(lambda cls: home))

    check = env.dotenv_check()

    assert check.status == OK
    assert check.detail == f"{home_env.resolve()} found"


def test_dotenv_check_survives_unavailable_cwd(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    home_env = home / ".env"
    home_env.write_text("HOME=1\n", encoding="utf-8")
    monkeypatch.setattr(cli.Path, "cwd", classmethod(
        lambda cls: (_ for _ in ()).throw(OSError("cwd unavailable"))))
    monkeypatch.setattr(cli.Path, "home", classmethod(lambda cls: home))

    check = env.dotenv_check()

    assert check.status == OK
    assert check.detail == f"{home_env.resolve()} found"


@pytest.mark.skipif(not hasattr(cli.os, "geteuid"), reason="POSIX permissions")
def test_dotenv_check_reports_ignored_untrusted_candidate(
        monkeypatch, tmp_path):
    cwd = tmp_path / "shared"
    cwd.mkdir(mode=0o700)
    (cwd / ".env").write_text("X=1\n", encoding="utf-8")
    cwd.chmod(0o770)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(cli.Path, "home", classmethod(lambda cls: home))

    check = env.dotenv_check()

    assert check.status == WARN
    assert "ignored untrusted file" in check.detail
    assert str(cwd / ".env") in check.detail


def _overlay_cfg(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("models:\n  deepdive: {id: x, via: cli}\n", encoding="utf-8")
    return cfg


def test_overlay_check_absent_is_ok(tmp_path):
    c = env.overlay_check(_overlay_cfg(tmp_path))
    assert c.status == OK
    assert "not found" in c.detail


def test_overlay_check_skipped_via_env(tmp_path, monkeypatch):
    monkeypatch.setenv("VVAHARNESS_NO_LOCAL_CONFIG", "1")
    cfg = _overlay_cfg(tmp_path)
    (tmp_path / "config.local.yaml").write_text("flag: 1\n", encoding="utf-8")
    c = env.overlay_check(cfg)
    assert c.status == OK
    assert "skipped" in c.detail and "VVAHARNESS_NO_LOCAL_CONFIG" in c.detail


def test_overlay_check_trusted_reports_leaf_keys_and_hosts(tmp_path):
    cfg = _overlay_cfg(tmp_path)
    local = tmp_path / "config.local.yaml"
    local.write_text("sdk:\n  base_url: https://gw.example/v1\n", encoding="utf-8")
    local.chmod(0o600)
    c = env.overlay_check(cfg)
    assert c.status == OK
    assert "sdk.base_url" in c.detail
    assert "gw.example" in c.detail


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX permissions")
def test_overlay_check_untrusted_fails_with_remedy(tmp_path):
    cfg = _overlay_cfg(tmp_path)
    local = tmp_path / "config.local.yaml"
    local.write_text("flag: 1\n", encoding="utf-8")
    local.chmod(0o666)
    c = env.overlay_check(cfg)
    assert c.status == FAIL
    assert c.required is True
    assert "chmod" in c.detail and "VVAHARNESS_NO_LOCAL_CONFIG" in c.detail


def test_run_checks_places_dotenv_after_config(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "config.yaml"
    cfg.write_text("models:\n  deepdive: {id: x, via: cli}\n", encoding="utf-8")
    names = [c.name for c in env.run_checks(cfg)]
    assert names[names.index("config") + 1] == ".env"


def _has(checks, name):
    return any(c.name == name for c in checks)


def test_remediate_validate_absent_when_flags_off(tmp_path):
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  deepdive: {id: x, via: cli}\n"
        "  remediate: {id: x, via: cli}\n"
        "  validate:\n    orchestrator: {id: x, via: cli}\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    assert not _has(checks, "step10: remediate")
    assert not _has(checks, "step11: validate")


def test_remediate_flag_on_with_cli_backend_ok(monkeypatch, tmp_path):
    monkeypatch.setattr(env.shutil, "which", lambda c: "/usr/bin/claude")
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  deepdive: {id: x, via: cli}\n"
        "  remediate: {id: x, via: cli}\n"
        "step_remediate:\n  enabled: true\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    c = next(c for c in checks if c.name == "step10: remediate")
    assert c.status == OK


def test_remediate_flag_on_missing_cli_warns_not_blocking(monkeypatch, tmp_path):
    monkeypatch.setattr(env.shutil, "which", lambda c: None)
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  deepdive: {id: x, via: sdk}\n"
        "  remediate: {id: x, via: cli}\n"
        "step_remediate:\n  enabled: true\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    c = next(c for c in checks if c.name == "step10: remediate")
    assert c.status == WARN and c.required is False


def test_deepagents_remediation_requires_provider_credential(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  remediate: {id: gpt-5.5, via: deepagents, provider: openai}\n"
        "step_remediate:\n  enabled: true\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    c = next(c for c in checks if c.name == "step10: remediate")
    assert c.status == WARN
    assert "OPENAI_API_KEY" in c.detail


def test_deepagents_remediation_accepts_openai_credential(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  remediate: {id: gpt-5.5, via: deepagents}\n"
        "step_remediate:\n  enabled: true\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    c = next(c for c in checks if c.name == "step10: remediate")
    assert c.status == OK
    active = next(c for c in checks if c.name == "active backends")
    assert "deepagents" in active.detail


@pytest.mark.parametrize("role", ["nonexistent-role"])
def test_deepagents_excluded_role_is_invalid(role, monkeypatch, tmp_path):
    """The gate is scoped to DEEPAGENTS_ROLES: a role outside the set stays
    rejected, and the message names the supported set (derived from the
    frozenset, so it can never drift from the gate again). Every shipped role
    is now admitted, so the offender is injected through _iter_model_roles —
    an unknown models key in YAML is never yielded by the fixed role walk."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(
        env, "_iter_model_roles",
        lambda _cfg: [(role, SimpleNamespace(id="gpt-5.5", via="deepagents"))],
    )
    cfg = tmp_path / "p.yaml"
    cfg.write_text("models: {}\n", encoding="utf-8")
    checks = env.config_check(cfg)
    invalid = next(c for c in checks if c.name == "via:deepagents roles")
    assert invalid.status == FAIL
    assert invalid.required is True
    assert role in invalid.detail
    for member in sorted(env.DEEPAGENTS_ROLES):
        assert member in invalid.detail


def test_all_deepagents_roles_pass_config_gate(monkeypatch, tmp_path):
    """Every widened role is accepted by the doctor gate (graph_annotate is
    included here because llm mode makes it active)."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://gw.example/")
    lines = "".join(
        f"  {r}: {{id: claude-x, via: deepagents}}\n"
        for r in sorted(env.DEEPAGENTS_ROLES) if r != "validate")
    cfg = tmp_path / "p.yaml"
    cfg.write_text(f"models:\n{lines}step0:\n  callgraph_detection: llm\n",
                   encoding="utf-8")
    checks = env.config_check(cfg)
    assert not _has(checks, "via:deepagents roles")


def test_detection_deepagents_credential_gap_blocks(monkeypatch, tmp_path):
    """§7.4: a credential gap on a DETECTION deepagents role is a blocking
    FAIL in doctor's static pass — the twin of preflight's fatal abort."""
    for v in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  threatmodel: {id: claude-x, via: deepagents}\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    c = next(c for c in checks if c.name == "via:deepagents claude-x")
    assert c.status == FAIL
    assert c.required is True
    assert "ANTHROPIC" in c.detail and "threatmodel" in c.detail


def test_post_scan_deepagents_credential_gap_warns(monkeypatch, tmp_path):
    """A gap confined to S10/S11 stays advisory: the scan's own gates skip
    the stage, so doctor must not block detection over it."""
    for v in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  remediate: {id: claude-x, via: deepagents}\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    c = next(c for c in checks if c.name == "via:deepagents claude-x")
    assert c.status == WARN
    assert c.required is False


def test_deepagents_anthropic_gateway_gap_blocks(monkeypatch, tmp_path):
    """§7.4: a deepagents-Anthropic profile with a JWT-shaped
    ANTHROPIC_API_KEY and no base URL must hit the gateway FAIL in the static
    pass — previously that check ran only when a via:sdk role was present."""
    _clear_anthropic(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "eyJhbGciOiJI.fake.jwt")  # JWT shape
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  threatmodel: {id: claude-x, via: deepagents}\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    gw = next(c for c in checks if c.name == "via:deepagents endpoint")
    assert gw.status == FAIL
    assert gw.required is True
    assert "ANTHROPIC_BASE_URL" in gw.detail


def test_deepagents_openai_route_skips_gateway_check(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  threatmodel: {id: gpt-5.5, via: deepagents}\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    assert not _has(checks, "via:deepagents endpoint")


def test_graph_annotate_skipped_in_rules_mode(monkeypatch, tmp_path):
    """§14.5 guard, doctor side: taint.yaml's shape (graph_annotate configured
    but callgraph_detection: rules) contributes no backend and no credential
    check, because the model is never called at runtime."""
    for v in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setattr(env.shutil, "which", lambda c: "/usr/bin/claude")
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n"
        "  graph_annotate: {id: claude-x, via: deepagents}\n"
        "  deepdive: {id: m, via: cli}\n"
        "step0:\n  callgraph_detection: rules\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    active = next(c for c in checks if c.name == "active backends")
    assert "deepagents" not in active.detail
    assert not _has(checks, "via:deepagents claude-x")


def test_graph_annotate_checked_in_llm_mode(monkeypatch, tmp_path):
    for v in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setattr(env.shutil, "which", lambda c: "/usr/bin/claude")
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n"
        "  graph_annotate: {id: claude-x, via: deepagents}\n"
        "  deepdive: {id: m, via: cli}\n"
        "step0:\n  callgraph_detection: llm\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    active = next(c for c in checks if c.name == "active backends")
    assert "deepagents" in active.detail
    c = next(c for c in checks if c.name == "via:deepagents claude-x")
    assert c.status == FAIL and c.required is True  # detection role, no cred


def test_role_resolution_is_one_definition():
    """§7.5/§19.1: doctor resolves roles through the same _iter_model_roles
    preflight uses — no local role-list copy and no hand-rolled validate
    unwrap that could drift from scan again."""
    from vvaharness.orchestrator import config_paths
    assert env._iter_model_roles is config_paths._iter_model_roles
    assert "graph_annotate" in config_paths._MODEL_ROLES
    assert "callgraph_creation" in config_paths._MODEL_ROLES


def test_config_check_sdk_fallback_kept_with_deepagents(monkeypatch, tmp_path):
    """sdk_sole, doctor site: {sdk, deepagents} keeps the ANTHROPIC_API_KEY
    fallback for the via:sdk credential."""
    _clear_anthropic(monkeypatch)
    monkeypatch.delenv("ANTHROPIC_SDK_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-shared")
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n"
        "  deepdive: {id: claude-a, via: sdk}\n"
        "  threatmodel: {id: claude-b, via: deepagents}\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    cred = next(c for c in checks if c.name == "via:sdk credential")
    assert cred.status == OK
    assert "fallback" in cred.detail
    assert not [c for c in checks if c.status == FAIL and c.required]


def test_config_check_sdk_fallback_refused_with_cli(monkeypatch, tmp_path):
    """sdk_sole, doctor site: {sdk, cli} still refuses the fallback."""
    _clear_anthropic(monkeypatch)
    monkeypatch.delenv("ANTHROPIC_SDK_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-shared")
    monkeypatch.setattr(env.shutil, "which", lambda c: "/usr/bin/claude")
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n"
        "  deepdive: {id: claude-a, via: sdk}\n"
        "  verify: {id: claude-b, via: cli}\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    cred = next(c for c in checks if c.name == "via:sdk credential")
    assert cred.status == FAIL and cred.required is True


def test_config_check_unwraps_validate_no_phantom_cli(monkeypatch, tmp_path):
    """§19.1 regression: the raw `validate` wrapper node has no .via, so the
    old hand-rolled walk injected a phantom `cli` backend, flipping sdk_sole
    off and making doctor demand a credential preflight does not. Doctor must
    report exactly the backends the roles actually use."""
    _clear_anthropic(monkeypatch)
    monkeypatch.delenv("ANTHROPIC_SDK_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-shared")
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n"
        "  deepdive: {id: claude-a, via: sdk}\n"
        "  remediate: {id: claude-b, via: deepagents, provider: anthropic}\n"
        "  validate:\n"
        "    orchestrator: {id: claude-c, via: deepagents, provider: anthropic}\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    active = next(c for c in checks if c.name == "active backends")
    assert active.detail == "deepagents, sdk"          # no phantom `cli`
    # default.yaml's documented shape: one ANTHROPIC_API_KEY runs everything.
    cred = next(c for c in checks if c.name == "via:sdk credential")
    assert cred.status == OK and "fallback" in cred.detail
    assert not [c for c in checks if c.status == FAIL and c.required]


def test_config_check_gap_confined_to_post_scan_is_advisory(monkeypatch, tmp_path):
    """With validate unwrapped, its real via reaches the plain backend checks;
    a gap confined to S10/S11 must stay advisory (preflight parity: the scan
    skips the stage instead of aborting)."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(env.shutil, "which", lambda c: "/usr/bin/claude")
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  deepdive: {id: x, via: cli}\n"
        "  validate:\n    orchestrator: {id: x, via: openai}\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    c = next(c for c in checks if c.name == "via:openai credential")
    assert c.status == WARN and c.required is False
    assert "validate" in c.detail and "skipped" in c.detail


def test_deepagents_detection_role_accepts_config_api_key(monkeypatch, tmp_path):
    """§7.7/§19.1: the runtime exports cfg.sdk.api_key as ANTHROPIC_API_KEY
    for a deepagents-Anthropic role (credential_env_overrides), so doctor must
    accept a profile-bound key — an sdk.yaml user's ANTHROPIC_SDK_API_KEY,
    resolved through `sdk.api_key: ${ANTHROPIC_SDK_API_KEY}`, is a valid
    credential for a deepagents detection role."""
    _clear_anthropic(monkeypatch)
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "sdk:\n  api_key: sk-ant-from-config\n"
        "models:\n  threatmodel: {id: claude-x, via: deepagents, provider: anthropic}\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    c = next(c for c in checks if c.name == "via:deepagents claude-x")
    assert c.status == OK
    assert not [c for c in checks if c.status == FAIL and c.required]
    assert all("sk-ant-from-config" not in c.detail for c in checks)  # presence only


def test_deepagents_openai_route_accepts_config_api_key(monkeypatch, tmp_path):
    """The OpenAI-compatible route mirrors it: cfg.openai.api_key is what the
    runtime exports as OPENAI_API_KEY, so it satisfies the check."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "openai:\n  api_key: sk-oa-from-config\n"
        "models:\n  threatmodel: {id: gpt-5.5, via: deepagents, provider: openai}\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    c = next(c for c in checks if c.name == "via:deepagents gpt-5.5")
    assert c.status == OK
    assert not [c for c in checks if c.status == FAIL and c.required]


def test_deepagents_detection_role_fatal_without_config_or_env(monkeypatch, tmp_path):
    """Still fatal when NEITHER the config nor the environment supplies the
    credential — a false OK here would start a scan that cannot run."""
    _clear_anthropic(monkeypatch)
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  threatmodel: {id: claude-x, via: deepagents, provider: anthropic}\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    c = next(c for c in checks if c.name == "via:deepagents claude-x")
    assert c.status == FAIL and c.required is True


def test_deepagents_s1_roles_are_valid(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n"
        "  autoexclude: {id: claude-x, via: deepagents}\n"
        "  preprocess:  {id: claude-x, via: deepagents}\n",
        encoding="utf-8",
    )
    checks = env.config_check(cfg)
    assert not any(c.name == "via:deepagents roles" for c in checks)
    active = next(c for c in checks if c.name == "active backends")
    assert "deepagents" in active.detail


def test_validate_flag_on_rejects_openai_backend(monkeypatch, tmp_path):
    # Clear the ambient credential: this asserts the MISSING-credential WARN,
    # which a developer/CI shell exporting OPENAI_API_KEY would otherwise mask
    # (same environment-dependence class as the §19.3 test fixes).
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(env.shutil, "which", lambda c: "/usr/bin/claude")
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  deepdive: {id: x, via: cli}\n"
        "  validate:\n    orchestrator: {id: x, via: openai}\n"
        "step_validate:\n  enabled: true\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    c = next(c for c in checks if c.name == "step11: validate")
    assert c.status == WARN
    assert "openai" in c.detail


def test_validate_flag_warns_when_sdk_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(env.shutil, "which", lambda c: "/usr/bin/claude")
    monkeypatch.setattr(env.importlib.util, "find_spec", lambda m: None)
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  deepdive: {id: x, via: cli}\n"
        "  validate:\n    orchestrator: {id: x, via: cli}\n"
        "step_validate:\n  enabled: true\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    sdk = next(c for c in checks if c.name == "step11: claude_agent_sdk")
    assert sdk.status == WARN and "claude_agent_sdk" in sdk.detail


# LangSmith tracing egress guard — langsmith_tracing_check()

_TRACING_ENVS = ("LANGSMITH_TRACING_V2", "LANGCHAIN_TRACING_V2",
                 "LANGSMITH_TRACING", "LANGCHAIN_TRACING",
                 "LANGSMITH_API_KEY", "LANGCHAIN_API_KEY")


def _clear_tracing(monkeypatch):
    for v in _TRACING_ENVS:
        monkeypatch.delenv(v, raising=False)


def test_langsmith_tracing_quiet_when_unset(monkeypatch):
    _clear_tracing(monkeypatch)
    c = env.langsmith_tracing_check()
    assert c.status == OK
    assert "disabled" in c.detail


@pytest.mark.parametrize("var", ["LANGSMITH_TRACING_V2", "LANGCHAIN_TRACING_V2",
                                 "LANGSMITH_TRACING", "LANGCHAIN_TRACING"])
def test_langsmith_tracing_gate_variable_warns(var, monkeypatch):
    """Any of the four gate variables langsmith 0.11.1 consults (TRACING_V2
    then TRACING, LANGSMITH_ then LANGCHAIN_ namespace) set to the exact
    string "true" enables tracing — the check must name the variable and the
    payload (repository source), and stay advisory (WARN, never blocking)."""
    _clear_tracing(monkeypatch)
    monkeypatch.setenv(var, "true")
    c = env.langsmith_tracing_check()
    assert c.status == WARN
    assert c.required is False
    assert var in c.detail
    assert "repository source" in c.detail
    assert "Unset" in c.detail


def test_langsmith_tracing_non_true_value_is_quiet(monkeypatch):
    """langsmith/utils.py:142 compares against the exact string "true" — a
    "1"/"True" value does NOT enable tracing, so warning on it would be a
    false alarm."""
    _clear_tracing(monkeypatch)
    monkeypatch.setenv("LANGSMITH_TRACING", "1")
    assert env.langsmith_tracing_check().status == OK
    monkeypatch.setenv("LANGSMITH_TRACING", "True")
    assert env.langsmith_tracing_check().status == OK


def test_langsmith_tracing_v2_false_beats_legacy_true(monkeypatch):
    """Precedence parity with langsmith.utils.get_env_var: a non-empty
    TRACING_V2 value wins outright, so TRACING_V2=false + TRACING=true is
    DISABLED — warning here would be a false alarm."""
    _clear_tracing(monkeypatch)
    monkeypatch.setenv("LANGSMITH_TRACING_V2", "false")
    monkeypatch.setenv("LANGCHAIN_TRACING", "true")
    assert env.langsmith_tracing_check().status == OK


def test_langsmith_namespace_beats_langchain_namespace(monkeypatch):
    """Within one lookup the LANGSMITH_ namespace is consulted first
    (langsmith/utils.py:437-441): LANGSMITH_TRACING_V2=false masks
    LANGCHAIN_TRACING_V2=true."""
    _clear_tracing(monkeypatch)
    monkeypatch.setenv("LANGSMITH_TRACING_V2", "false")
    monkeypatch.setenv("LANGCHAIN_TRACING_V2", "true")
    assert env.langsmith_tracing_check().status == OK


def test_langsmith_tracing_reports_api_key_presence_only(monkeypatch):
    """The upload credential is reported by presence only — never any part of
    the value, per this module's no-values rule."""
    _clear_tracing(monkeypatch)
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    monkeypatch.setenv("LANGSMITH_API_KEY", "lsv2_pt_supersecretvalue123")
    c = env.langsmith_tracing_check()
    assert c.status == WARN
    assert "LANGSMITH_API_KEY is also set" in c.detail
    assert "supersecret" not in c.detail
    assert "lsv2" not in c.detail


def test_langsmith_tracing_without_key_still_warns(monkeypatch):
    """No API key does NOT mean no egress: langsmith still POSTs the run
    payload and merely gets a 401 back, so the check must keep warning."""
    _clear_tracing(monkeypatch)
    monkeypatch.setenv("LANGCHAIN_TRACING_V2", "true")
    c = env.langsmith_tracing_check()
    assert c.status == WARN
    assert "still transmitted" in c.detail


def test_run_checks_includes_langsmith_tracing(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    # Keep this offline: tls_check does a real handshake.
    monkeypatch.setattr(env, "tls_check",
                        lambda: env.Check("TLS / CA cert", OK, "stub"))
    cfg = tmp_path / "p.yaml"
    cfg.write_text("models:\n  deepdive: {id: x, via: cli}\n", encoding="utf-8")
    names = [c.name for c in env.run_checks(cfg)]
    assert "LangSmith tracing" in names


def test_optin_step_issues_never_block_scan(monkeypatch, tmp_path):
    # Even with both opt-in steps misconfigured, summarize() must report zero
    # blocking issues — the core scan is unaffected, so doctor's live probe runs.
    monkeypatch.setattr(env.shutil, "which", lambda c: "/usr/bin/claude")
    monkeypatch.setattr(env.importlib.util, "find_spec", lambda m: None)
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "models:\n  deepdive: {id: x, via: cli}\n"
        "  validate:\n    orchestrator: {id: x, via: openai}\n"
        "step_remediate:\n  enabled: true\n"
        "step_validate:\n  enabled: true\n",
        encoding="utf-8")
    checks = env.config_check(cfg)
    _ok, _warn, n_blocking = env.summarize(checks)
    assert n_blocking == 0
