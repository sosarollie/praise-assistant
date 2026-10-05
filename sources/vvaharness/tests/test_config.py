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

"""Unit tests for vvaharness.config: env expansion, Config wrapper,
deep/append/replace merges, load() with local override, and step1 overlay."""
import os

import pytest

from vvaharness.config import (
    Config,
    ConfigPolicyError,
    _append_merge,
    _deep_merge,
    _expand,
    _replace_merge,
    apply_step1_overlay,
    load,
)
from vvaharness.config.constants import is_secret_var_name


# _expand : ${VAR} and ${VAR:-default}
def test_expand_unset_no_default_becomes_empty(monkeypatch):
    monkeypatch.delenv("MY_UNSET_VAR", raising=False)
    assert _expand("x=${MY_UNSET_VAR}") == "x="


def test_expand_unset_with_default_uses_default(monkeypatch):
    monkeypatch.delenv("MY_UNSET_VAR", raising=False)
    assert _expand("${MY_UNSET_VAR:-fallback}") == "fallback"


def test_expand_empty_string_value_uses_default(monkeypatch):
    # POSIX :- semantics: set-but-empty also triggers the default.
    monkeypatch.setenv("MY_EMPTY_VAR", "")
    assert _expand("${MY_EMPTY_VAR:-fallback}") == "fallback"


def test_expand_set_value_wins_over_default(monkeypatch):
    monkeypatch.setenv("MY_SET_VAR", "realval")
    assert _expand("${MY_SET_VAR:-fallback}") == "realval"


def test_expand_set_value_no_default(monkeypatch):
    monkeypatch.setenv("MY_SET_VAR", "realval")
    assert _expand("pre-${MY_SET_VAR}-post") == "pre-realval-post"


def test_expand_recurses_into_dict_and_list(monkeypatch):
    monkeypatch.setenv("A_VAR", "AA")
    monkeypatch.delenv("B_VAR", raising=False)
    src = {
        "key": "${A_VAR}",
        "lst": ["${A_VAR}", "${B_VAR:-bb}"],
        "nested": {"inner": "${B_VAR}"},
    }
    out = _expand(src)
    assert out == {
        "key": "AA",
        "lst": ["AA", "bb"],
        "nested": {"inner": ""},
    }


def test_expand_passes_through_non_str_scalars():
    assert _expand(7) == 7
    assert _expand(None) is None
    assert _expand(True) is True


# Config wrapper
def test_config_attr_access():
    c = Config({"model": "opus", "n": 3})
    assert c.model == "opus"
    assert c.n == 3


def test_config_getitem_access():
    c = Config({"model": "opus"})
    assert c["model"] == "opus"


def test_config_nested_dict_wraps():
    c = Config({"models": {"deepdive": "x"}})
    nested = c.models
    assert isinstance(nested, Config)
    assert nested.deepdive == "x"


def test_config_attribute_error_on_missing():
    c = Config({"present": 1})
    with pytest.raises(AttributeError):
        _ = c.missing


def test_config_getitem_keyerror_on_missing():
    c = Config({"present": 1})
    with pytest.raises(KeyError):
        _ = c["missing"]


def test_config_repr_roundtrips_data():
    c = Config({"a": 1})
    assert repr(c) == "Config({'a': 1})"


def test_config_list_value_not_wrapped():
    c = Config({"items": [1, 2, 3]})
    assert c.items == [1, 2, 3]


# _deep_merge
def test_deep_merge_recurses_and_overrides():
    base = {"a": {"x": 1, "y": 2}, "b": 10}
    over = {"a": {"y": 99, "z": 3}, "c": 20}
    out = _deep_merge(base, over)
    assert out == {"a": {"x": 1, "y": 99, "z": 3}, "b": 10, "c": 20}
    # base must not be mutated
    assert base == {"a": {"x": 1, "y": 2}, "b": 10}


def test_deep_merge_scalar_replaces_dict():
    base = {"a": {"x": 1}}
    over = {"a": "scalar"}
    assert _deep_merge(base, over) == {"a": "scalar"}


# load()
def test_load_basic(tmp_path, monkeypatch):
    monkeypatch.delenv("LOAD_VAR", raising=False)
    p = tmp_path / "config.yaml"
    p.write_text("models:\n  deepdive: ${LOAD_VAR:-defmodel}\nn: 5\n", encoding="utf-8")
    c = load(p)
    assert isinstance(c, Config)
    assert c.models.deepdive == "defmodel"
    assert c.n == 5


def test_load_local_override(tmp_path):
    base = tmp_path / "config.yaml"
    base.write_text("models:\n  deepdive: base\n  triage: keepme\nflag: 1\n", encoding="utf-8")
    local = tmp_path / "config.local.yaml"
    local.write_text("models:\n  deepdive: overridden\nflag: 2\n", encoding="utf-8")
    c = load(base)
    assert c.models.deepdive == "overridden"  # local wins
    assert c.models.triage == "keepme"        # untouched key preserved
    assert c.flag == 2


def test_load_empty_file_is_empty_mapping(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("# only a comment\n", encoding="utf-8")
    c = load(p)
    assert isinstance(c, Config)
    with pytest.raises(AttributeError):
        _ = c.anything


def test_load_non_mapping_raises(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load(p)


def test_load_local_non_mapping_raises(tmp_path):
    base = tmp_path / "config.yaml"
    base.write_text("a: 1\n", encoding="utf-8")
    local = tmp_path / "config.local.yaml"
    local.write_text("- nope\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load(base)


def test_load_local_override_logs_overridden_keys(tmp_path, capsys):
    # The overlay merge must be VISIBLE: log the file + the top-level keys it
    # overrides (it can change model routing / base_url / TLS / tool perms).
    base = tmp_path / "config.yaml"
    base.write_text("models:\n  deepdive: base\nsdk:\n  base_url: x\n", encoding="utf-8")
    local = tmp_path / "config.local.yaml"
    local.write_text("models:\n  deepdive: overridden\nsdk:\n  base_url: y\n", encoding="utf-8")
    c = load(base)
    assert c.models.deepdive == "overridden"          # merge still happens
    err = capsys.readouterr().err
    assert "config overlay" in err and "applied" in err
    assert "models" in err and "sdk" in err            # overridden keys surfaced


def test_load_no_local_config_skips_merge(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VVAHARNESS_NO_LOCAL_CONFIG", "1")
    base = tmp_path / "config.yaml"
    base.write_text("models:\n  deepdive: base\n", encoding="utf-8")
    local = tmp_path / "config.local.yaml"
    local.write_text("models:\n  deepdive: overridden\n", encoding="utf-8")
    c = load(base)
    assert c.models.deepdive == "base"                 # overlay NOT applied
    err = capsys.readouterr().err
    assert "SKIPPED" in err and "VVAHARNESS_NO_LOCAL_CONFIG" in err


def test_load_overlay_log_deduped(tmp_path, capsys):
    # load() runs several times per process; the overlay line logs once per path.
    base = tmp_path / "config.yaml"
    base.write_text("a: 1\n", encoding="utf-8")
    (tmp_path / "config.local.yaml").write_text("a: 2\n", encoding="utf-8")
    load(base)
    load(base)
    assert capsys.readouterr().err.count("config overlay") == 1


# _replace_merge / _append_merge
def test_replace_merge_list_replaces():
    base = {"exts": [".py", ".js"], "nested": {"a": 1, "b": 2}}
    over = {"exts": [".go"], "nested": {"b": 9}}
    out = _replace_merge(base, over)
    assert out["exts"] == [".go"]           # list replaced, not appended
    assert out["nested"] == {"a": 1, "b": 9}  # dict still recurses


def test_append_merge_top_level_lists_append_dedup():
    base = {"exclude_dirs": ["node_modules", "dist"]}
    over = {"exclude_dirs": ["dist", "build"]}
    out = _append_merge(base, over)
    # existing entries kept, new appended, duplicates not re-added
    assert out["exclude_dirs"] == ["node_modules", "dist", "build"]


def test_append_merge_nested_dict_uses_replace():
    base = {"config_dedup": {"exts": [".py", ".js"]}}
    over = {"config_dedup": {"exts": [".go"]}}
    out = _append_merge(base, over)
    # nested list switches to replace semantics
    assert out["config_dedup"]["exts"] == [".go"]


def test_append_merge_scalar_replaces():
    base = {"limit": 5}
    over = {"limit": 9}
    assert _append_merge(base, over)["limit"] == 9


# interpolation policy: secret-named vars only into credential keys
def test_secret_var_refused_outside_credential_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-secret")
    p = tmp_path / "config.yaml"
    p.write_text("sdk:\n  base_url: https://x/${ANTHROPIC_SDK_API_KEY}/\n",
                 encoding="utf-8")
    with pytest.raises(ConfigPolicyError) as ei:
        load(p)
    msg = str(ei.value)
    assert "sdk.base_url" in msg
    assert "ANTHROPIC_SDK_API_KEY" in msg
    assert "sdk.api_key" in msg  # the rule and remedy are in the error itself


def test_secret_var_refused_even_when_unset(tmp_path, monkeypatch):
    # Refusal is by variable NAME, so profiles fail the same way everywhere.
    monkeypatch.delenv("ANTHROPIC_SDK_API_KEY", raising=False)
    p = tmp_path / "config.yaml"
    p.write_text("sdk:\n  base_url: https://x/${ANTHROPIC_SDK_API_KEY}/\n",
                 encoding="utf-8")
    with pytest.raises(ConfigPolicyError):
        load(p)


def test_secret_var_allowed_into_credential_key(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-secret")
    p = tmp_path / "config.yaml"
    p.write_text("sdk:\n  api_key: ${ANTHROPIC_SDK_API_KEY}\n", encoding="utf-8")
    assert load(p).sdk.api_key == "sk-secret"


def test_non_secret_var_expands_anywhere(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_GATEWAY", "https://gw.example/v1")
    p = tmp_path / "config.yaml"
    p.write_text("sdk:\n  base_url: ${MY_GATEWAY}\n", encoding="utf-8")
    assert load(p).sdk.base_url == "https://gw.example/v1"


def test_is_secret_var_name_segment_matching():
    assert is_secret_var_name("OAUTH") is True
    assert is_secret_var_name("MY_AUTH_COOKIE") is True
    assert is_secret_var_name("GIT_AUTHOR_NAME") is False
    assert is_secret_var_name("VERIFY_SSL") is False


def test_oauth_var_refused_outside_credential_keys(monkeypatch):
    monkeypatch.setenv("OAUTH", "v")
    with pytest.raises(ConfigPolicyError):
        _expand({"models": {"deepdive": "${OAUTH}"}})


def test_git_author_name_expands(monkeypatch):
    monkeypatch.setenv("GIT_AUTHOR_NAME", "me")
    out = _expand({"models": {"note": "${GIT_AUTHOR_NAME}"}})
    assert out == {"models": {"note": "me"}}


def test_policy_applies_to_overlay_values(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-secret")
    base = tmp_path / "config.yaml"
    base.write_text("sdk:\n  base_url: https://good.example/\n", encoding="utf-8")
    local = tmp_path / "config.local.yaml"
    local.write_text("sdk:\n  base_url: https://x/${ANTHROPIC_SDK_API_KEY}/\n",
                     encoding="utf-8")
    with pytest.raises(ConfigPolicyError, match=r"sdk\.base_url"):
        load(base)


# overlay trust check (POSIX ownership/mode)
@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX permissions")
def test_overlay_owned_0600_loads(tmp_path):
    base = tmp_path / "config.yaml"
    base.write_text("flag: 1\n", encoding="utf-8")
    local = tmp_path / "config.local.yaml"
    local.write_text("flag: 2\n", encoding="utf-8")
    local.chmod(0o600)
    assert load(base).flag == 2


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX permissions")
@pytest.mark.parametrize("mode", [0o660, 0o666])
def test_overlay_group_or_world_writable_refused(tmp_path, mode):
    base = tmp_path / "config.yaml"
    base.write_text("flag: 1\n", encoding="utf-8")
    local = tmp_path / "config.local.yaml"
    local.write_text("flag: 2\n", encoding="utf-8")
    local.chmod(mode)
    with pytest.raises(ConfigPolicyError) as ei:
        load(base)
    msg = str(ei.value)
    assert "chmod" in msg and "VVAHARNESS_NO_LOCAL_CONFIG" in msg


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX permissions")
def test_untrusted_overlay_still_skippable_via_env(tmp_path, monkeypatch):
    monkeypatch.setenv("VVAHARNESS_NO_LOCAL_CONFIG", "1")
    base = tmp_path / "config.yaml"
    base.write_text("flag: 1\n", encoding="utf-8")
    local = tmp_path / "config.local.yaml"
    local.write_text("flag: 2\n", encoding="utf-8")
    local.chmod(0o666)
    assert load(base).flag == 1  # skipped, not refused


# overlay banner value classes
def test_banner_endpoint_prints_host_not_full_url(tmp_path, capsys):
    base = tmp_path / "config.yaml"
    base.write_text("sdk:\n  base_url: https://good.example/\n", encoding="utf-8")
    local = tmp_path / "config.local.yaml"
    local.write_text("sdk:\n  base_url: https://attacker.example/v1/deep\n",
                     encoding="utf-8")
    load(base)
    err = capsys.readouterr().err
    assert "sdk.base_url -> attacker.example" in err
    assert "/v1/deep" not in err


def test_banner_credential_prints_presence_never_value(tmp_path, capsys):
    base = tmp_path / "config.yaml"
    base.write_text("sdk:\n  api_key: old\n", encoding="utf-8")
    local = tmp_path / "config.local.yaml"
    local.write_text("sdk:\n  api_key: supersecretvalue\n", encoding="utf-8")
    load(base)
    err = capsys.readouterr().err
    assert "sdk.api_key (set)" in err
    assert "supersecretvalue" not in err


def test_banner_tls_key_prints_resolved_value(tmp_path, capsys):
    base = tmp_path / "config.yaml"
    base.write_text("sdk:\n  verify_ssl: true\n", encoding="utf-8")
    local = tmp_path / "config.local.yaml"
    local.write_text("sdk:\n  verify_ssl: false\n", encoding="utf-8")
    load(base)
    assert "sdk.verify_ssl=False" in capsys.readouterr().err


def test_banner_plain_key_prints_path_only(tmp_path, capsys):
    base = tmp_path / "config.yaml"
    base.write_text("models:\n  deepdive: old\n", encoding="utf-8")
    local = tmp_path / "config.local.yaml"
    local.write_text("models:\n  deepdive: newmodel\n", encoding="utf-8")
    load(base)
    err = capsys.readouterr().err
    assert "models.deepdive" in err
    assert "newmodel" not in err


def test_banner_values_are_post_expansion(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("MY_GATEWAY", "https://gw.example/api")
    base = tmp_path / "config.yaml"
    base.write_text("sdk:\n  base_url: https://good.example/\n", encoding="utf-8")
    local = tmp_path / "config.local.yaml"
    local.write_text("sdk:\n  base_url: ${MY_GATEWAY}\n", encoding="utf-8")
    load(base)
    err = capsys.readouterr().err
    assert "sdk.base_url -> gw.example" in err
    assert "${MY_GATEWAY}" not in err


# apply_step1_overlay
def test_apply_step1_overlay_missing_file_returns_false(tmp_path):
    c = Config({"step1": {"exclude_dirs": ["a"]}})
    out, applied = apply_step1_overlay(c, tmp_path / "nope.yaml")
    assert applied is False
    assert out is c
    assert c._data["step1"]["exclude_dirs"] == ["a"]  # unchanged


def test_apply_step1_overlay_bare_key_appends_lists(tmp_path):
    c = Config({"step1": {"exclude_dirs": ["base_dir"]}})
    f = tmp_path / "step1.yaml"
    f.write_text("exclude_dirs:\n  - extra_dir\n", encoding="utf-8")
    out, applied = apply_step1_overlay(c, f)
    assert applied is True
    assert out._data["step1"]["exclude_dirs"] == ["base_dir", "extra_dir"]


def test_apply_step1_overlay_step1_wrapper_unwrapped(tmp_path):
    c = Config({"step1": {"exclude_dirs": ["base_dir"]}})
    f = tmp_path / "step1.yaml"
    f.write_text("step1:\n  exclude_dirs:\n    - wrapped_dir\n", encoding="utf-8")
    out, applied = apply_step1_overlay(c, f)
    assert applied is True
    # wrapper unwrapped, so the key landed at step1.exclude_dirs (not step1.step1)
    assert out._data["step1"]["exclude_dirs"] == ["base_dir", "wrapped_dir"]
    assert "step1" not in out._data["step1"]


def test_apply_step1_overlay_nested_replace(tmp_path):
    c = Config({"step1": {"config_dedup": {"exts": [".py", ".js"]}}})
    f = tmp_path / "step1.yaml"
    f.write_text("config_dedup:\n  exts:\n    - .go\n", encoding="utf-8")
    out, applied = apply_step1_overlay(c, f)
    assert applied is True
    # nested list replaced outright
    assert out._data["step1"]["config_dedup"]["exts"] == [".go"]


def test_apply_step1_overlay_expands_env(tmp_path, monkeypatch):
    monkeypatch.setenv("OVERLAY_DIR", "expanded_dir")
    c = Config({"step1": {"exclude_dirs": ["base_dir"]}})
    f = tmp_path / "step1.yaml"
    f.write_text("exclude_dirs:\n  - ${OVERLAY_DIR}\n", encoding="utf-8")
    out, applied = apply_step1_overlay(c, f)
    assert applied is True
    assert "expanded_dir" in out._data["step1"]["exclude_dirs"]


def test_apply_step1_overlay_expand_false_leaves_placeholders_literal(tmp_path, monkeypatch):
    monkeypatch.setenv("OVERLAY_DIR", "expanded_dir")
    c = Config({"step1": {}})
    f = tmp_path / "step1.yaml"
    f.write_text("exclude_dirs:\n  - ${OVERLAY_DIR}\n", encoding="utf-8")
    out, applied = apply_step1_overlay(c, f, expand=False)
    assert applied is True
    assert out._data["step1"]["exclude_dirs"] == ["${OVERLAY_DIR}"]


def test_apply_step1_overlay_expand_true_enforces_policy(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "t")
    c = Config({"step1": {}})
    f = tmp_path / "step1.yaml"
    f.write_text("exclude_dirs:\n  - ${MY_TOKEN}\n", encoding="utf-8")
    with pytest.raises(ConfigPolicyError):
        apply_step1_overlay(c, f)


def test_apply_step1_overlay_no_existing_step1(tmp_path):
    c = Config({})  # no step1 key at all
    f = tmp_path / "step1.yaml"
    f.write_text("exclude_dirs:\n  - only_dir\n", encoding="utf-8")
    out, applied = apply_step1_overlay(c, f)
    assert applied is True
    assert out._data["step1"]["exclude_dirs"] == ["only_dir"]


def test_apply_step1_overlay_non_mapping_raises(tmp_path):
    c = Config({"step1": {}})
    f = tmp_path / "step1.yaml"
    f.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(ValueError):
        apply_step1_overlay(c, f)
