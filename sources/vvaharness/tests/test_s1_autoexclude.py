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

"""Unit tests for s1_autoexclude pure helpers (_extract_yaml, _norm_list,
_erases_language) and the run() language-wide exclusion veto."""
from types import SimpleNamespace

import pytest
import yaml

from vvaharness.pipeline.stages.s1_autoexclude import (
    _erases_language, _extract_yaml, _norm_list, run)
from vvaharness.report.redact import redact

# _extract_yaml

def test_extract_yaml_fenced_block():
    text = (
        "Here is my answer:\n"
        "```yaml\n"
        "exclude_dirs:\n"
        "  - generated\n"
        "  - samples\n"
        "```\n"
        "trailing chatter that must be ignored"
    )
    assert _extract_yaml(text) == {"exclude_dirs": ["generated", "samples"]}


def test_extract_yaml_yml_fence_label():
    text = "```yml\nexclude_exts:\n  - .min.js\n```"
    assert _extract_yaml(text) == {"exclude_exts": [".min.js"]}


def test_extract_yaml_unlabeled_fence():
    # Fence with no language label still matches the (?:yaml|yml)? optional group.
    text = "```\nmax_file_kb: 2048\n```"
    assert _extract_yaml(text) == {"max_file_kb": 2048}


def test_extract_yaml_no_fence_parses_whole_text():
    # No fence at all -> parse the entire text as YAML.
    text = "exclude_dirs:\n  - vendored\n"
    assert _extract_yaml(text) == {"exclude_dirs": ["vendored"]}


def test_extract_yaml_step1_wrapper_unwrapped():
    text = (
        "```yaml\n"
        "step1:\n"
        "  exclude_dirs:\n"
        "    - docs\n"
        "  max_file_kb: 512\n"
        "```"
    )
    # The sole top-level key "step1" should be unwrapped.
    assert _extract_yaml(text) == {"exclude_dirs": ["docs"], "max_file_kb": 512}


def test_extract_yaml_step1_wrapper_only_unwrapped_when_sole_key():
    # step1 present but NOT the only key -> left as-is (no unwrap).
    text = (
        "```yaml\n"
        "step1:\n"
        "  exclude_dirs:\n"
        "    - docs\n"
        "other: 1\n"
        "```"
    )
    result = _extract_yaml(text)
    assert set(result) == {"step1", "other"}
    assert result["step1"] == {"exclude_dirs": ["docs"]}


def test_extract_yaml_step1_wrapper_not_unwrapped_when_value_not_dict():
    text = "```yaml\nstep1: just-a-string\n```"
    # set(data) == {"step1"} but value is not a dict, so no unwrap.
    assert _extract_yaml(text) == {"step1": "just-a-string"}


def test_extract_yaml_malformed_returns_empty(capsys):
    # Unbalanced bracket / bad indentation -> YAMLError -> empty overlay.
    text = "```yaml\nexclude_dirs: [unclosed, list\n  - bad: : indent\n```"
    assert _extract_yaml(text) == {}
    err = capsys.readouterr().err
    assert "auto-step1" in err
    assert "empty overlay" in err


def test_extract_yaml_parse_error_never_leaks_secret_fragment_to_stderr(capsys):
    """REGRESSION: the YAMLError fallback printed str(e) — which echoes the
    offending input line verbatim — to stderr with no redaction, so model
    output could carry a credential to stderr unmasked. The fix is
    redact(str(e))[:200]; the WRONG order, redact(str(e)[:200]), bisects a
    secret that straddles the cut so the surviving prefix matches no
    redaction pattern. This test's geometry is tuned so the key straddles
    index 200 of the raw str(e) with >=12 chars on the kept side, making the
    window sweep below fail for BOTH the no-redact and the slice-first bug.
    """
    _CUT = 200  # mirrors the [:200] cap in _extract_yaml's YAMLError handler

    # Canonical 20-char AWS access key id (AKIA + 16). A shorter stand-in
    # would NOT match redact()'s AWS-KEY pattern and the test would pass for
    # the wrong reason — assert redactability up front.
    secret = "AKIAIOSFODNN7EXAMPLE"
    assert secret not in redact(secret)

    # Space-separated filler around the key: glued padding would defeat the
    # AWS-KEY pattern's \b word boundary, so the key would never redact even
    # in correct code. Line 1's unclosed flow sequence forces a parser error
    # whose problem mark quotes line 2 — the line carrying the key.
    blob = f"k: [unclosed\nn: {secret} tail words"
    text = f"```yaml\n{blob}\n```"

    # Vacuity guard: prove the secret really reaches the raw error string AND
    # straddles the cut, with a >=12-char fragment surviving a slice-first
    # bug. If a PyYAML message-format change moves the offsets, this fails
    # loudly instead of letting the sweep below pass vacuously.
    with pytest.raises(yaml.YAMLError) as excinfo:
        yaml.safe_load(blob)
    raw = str(excinfo.value)
    idx = raw.find(secret)
    assert idx != -1, "secret never reached the YAMLError text — re-tune blob"
    assert idx < _CUT < idx + len(secret), (
        f"secret at {idx} does not straddle the [:{_CUT}] cut — re-tune blob")
    assert _CUT - idx >= 12, (
        "kept-side fragment shorter than the 12-char sweep window — re-tune")

    assert _extract_yaml(text) == {}
    err = capsys.readouterr().err
    assert "empty overlay" in err  # the YAMLError fallback really ran

    # No 12-char window of the raw key may survive anywhere in stderr.
    for j in range(len(secret) - 11):
        assert secret[j:j + 12] not in err, (
            f"unredacted key fragment {secret[j:j + 12]!r} leaked to stderr")


def test_extract_yaml_empty_block_returns_empty_dict():
    # safe_load(None/"") -> falls back to {}.
    assert _extract_yaml("```yaml\n\n```") == {}


def test_extract_yaml_non_dict_scalar_returns_empty_dict():
    # A bare scalar parses fine but is not a dict -> coerced to {}.
    assert _extract_yaml("just a plain sentence with no mapping") == {}


def test_extract_yaml_list_top_level_returns_empty_dict():
    text = "```yaml\n- a\n- b\n```"
    # A top-level list is valid YAML but not a dict.
    assert _extract_yaml(text) == {}


def test_extract_yaml_case_insensitive_fence_label():
    text = "```YAML\nmax_file_kb: 64\n```"
    assert _extract_yaml(text) == {"max_file_kb": 64}


# _norm_list

def test_norm_list_none_and_empty():
    assert _norm_list(None) == []
    assert _norm_list([]) == []
    assert _norm_list("") == []


def test_norm_list_string_coerced_to_single_element():
    assert _norm_list("Generated") == ["Generated"]


def test_norm_list_dedup_preserves_first_order():
    assert _norm_list(["a", "b", "a", "c", "b"]) == ["a", "b", "c"]


def test_norm_list_lowercasing():
    assert _norm_list(["Foo", "BAR"], lower=True) == ["foo", "bar"]


def test_norm_list_no_lowercasing_by_default():
    assert _norm_list(["Foo", "BAR"]) == ["Foo", "BAR"]


def test_norm_list_strips_surrounding_whitespace():
    assert _norm_list(["  spaced  ", "\tx\t"]) == ["spaced", "x"]


def test_norm_list_strips_leading_and_trailing_slashes():
    # .strip("/\\") removes both forward and backslashes from both ends.
    assert _norm_list(["/foo/", "\\bar\\", "//baz//"]) == ["foo", "bar", "baz"]


def test_norm_list_does_not_strip_interior_slashes():
    assert _norm_list(["tools/codegen"]) == ["tools/codegen"]


def test_norm_list_skips_non_string_elements():
    assert _norm_list(["keep", 123, None, {"x": 1}, "also"]) == ["keep", "also"]


def test_norm_list_drops_elements_that_become_empty_after_strip():
    # "/" strips down to "" and is dropped; whitespace-only too.
    assert _norm_list(["/", "  ", "\\\\", "real"]) == ["real"]


def test_norm_list_dedup_after_lowercasing_collapses_case_variants():
    # Foo and FOO both lower to "foo" -> deduped to one.
    assert _norm_list(["Foo", "FOO", "foo"], lower=True) == ["foo"]


def test_norm_list_strip_then_dedup():
    # "/x/" and "x" both normalize to "x".
    assert _norm_list(["/x/", "x"]) == ["x"]


# --------------------------------------------------------------------------
# _erases_language
# --------------------------------------------------------------------------

def test_erases_language_bare_extension():
    assert _erases_language(".pug") == ".pug"
    assert _erases_language(".hbs") == ".hbs"
    assert _erases_language(".ts") == ".ts"


def test_erases_language_repo_wide_glob():
    assert _erases_language("**/*.pug") == ".pug"
    assert _erases_language("*.hbs") == ".hbs"


def test_erases_language_compound_suffix_passes():
    # Compound suffixes are not EXT_TO_LANG keys — the prompt invites them.
    assert _erases_language(".pb.go") is None
    assert _erases_language(".min.js") is None
    assert _erases_language(".spec.ts") is None
    assert _erases_language("**/*.spec.ts") is None
    assert _erases_language("**/*.g.dart") is None


def test_erases_language_path_scoped_glob_passes():
    # Path-scoped globs narrow a directory, not a language repo-wide.
    assert _erases_language("rsn/**") is None
    assert _erases_language("frontend/dist/**") is None
    assert _erases_language("docs/**/*.hbs") is None


def test_erases_language_unknown_extension_passes():
    assert _erases_language(".zzzz") is None
    assert _erases_language("**/*.zzzz") is None


def test_erases_language_case_insensitive():
    assert _erases_language(".PUG") == ".pug"
    assert _erases_language("**/*.HBS") == ".hbs"


# --------------------------------------------------------------------------
# run() — language-wide model-overlay veto
# --------------------------------------------------------------------------

def _cfg(**step1_extra):
    # Minimal cfg stand-in: _exclusion_sets / run() read everything through
    # getattr with defaults, so missing attributes are fine.
    return SimpleNamespace(
        step1=SimpleNamespace(**step1_extra),
        models=SimpleNamespace(autoexclude=None, preprocess="stub-model"),
    )


def _run_with_reply(tmp_path, monkeypatch, reply, cfg=None):
    (tmp_path / "repo").mkdir(exist_ok=True)
    monkeypatch.setattr(
        "vvaharness.backends.llm.deepagents.dispatch_prompt",
        lambda *a, **k: reply)
    out = run(tmp_path / "repo", cfg or _cfg(), out_path=tmp_path / "overlay.yaml")
    return yaml.safe_load(out.read_text(encoding="utf-8"))


def test_run_vetoes_language_wide_model_exclusions(tmp_path, monkeypatch, capsys):
    reply = (
        "```yaml\n"
        "exclude_exts:\n"
        "  - .pug\n"
        "  - .pb.go\n"
        "exclude_globs:\n"
        "  - '**/*.hbs'\n"
        "  - '**/*.g.dart'\n"
        "  - rsn/**\n"
        "```"
    )
    overlay = _run_with_reply(tmp_path, monkeypatch, reply)
    # Bare language-wide entries vetoed; compound / path-scoped survive.
    assert overlay["exclude_exts"] == [".pb.go"]
    assert overlay["exclude_globs"] == ["**/*.g.dart", "rsn/**"]


def test_run_veto_warn_names_offenders(tmp_path, monkeypatch, capsys):
    reply = "```yaml\nexclude_exts: ['.pug']\nexclude_globs: ['**/*.hbs']\n```"
    _run_with_reply(tmp_path, monkeypatch, reply)
    err = capsys.readouterr().err
    assert "WARN: vetoed language-wide exclusions" in err
    assert ".pug" in err
    assert "**/*.hbs" in err


def test_run_normal_overlay_unchanged(tmp_path, monkeypatch, capsys):
    # Regression guard: an overlay with no language-wide entries passes
    # through untouched and emits no veto WARN.
    reply = (
        "```yaml\n"
        "exclude_dirs: [generated, samples]\n"
        "exclude_exts: ['.pb.go']\n"
        "exclude_globs: ['tools/codegen/**']\n"
        "max_file_kb: 2048\n"
        "```"
    )
    overlay = _run_with_reply(tmp_path, monkeypatch, reply)
    assert overlay["exclude_dirs"] == ["generated", "samples"]
    assert overlay["exclude_exts"] == [".pb.go"]
    assert overlay["exclude_globs"] == ["tools/codegen/**"]
    assert overlay["max_file_kb"] == 2048
    assert "vetoed" not in capsys.readouterr().err


def test_run_config_language_exclusion_still_honoured(tmp_path, monkeypatch, capsys):
    # An operator exclusion of a language extension lives in cfg.step1 (or an
    # operator overlay merged into it) and never passes through the model
    # sanitizer — the veto must not disturb it.
    from vvaharness.pipeline.stages.s1_preprocess import _exclusion_sets

    cfg = _cfg(exclude_exts=[".pug"])
    reply = "```yaml\nexclude_exts: ['.pug']\n```"
    overlay = _run_with_reply(tmp_path, monkeypatch, reply, cfg=cfg)
    # The model's duplicate of an already-excluded ext is dropped (as before,
    # not vetoed), and the operator's exclusion survives run() untouched.
    assert overlay["exclude_exts"] == []
    assert "vetoed" not in capsys.readouterr().err
    _, exts, _ = _exclusion_sets(cfg)
    assert ".pug" in exts


def test_run_empty_model_reply_writes_empty_overlay(tmp_path, monkeypatch, capsys):
    # Behaviour preserved when the model proposes nothing.
    overlay = _run_with_reply(tmp_path, monkeypatch, "```yaml\n\n```")
    assert overlay == {"exclude_dirs": [], "exclude_exts": [],
                       "exclude_globs": []}
    assert "vetoed" not in capsys.readouterr().err


# --------------------------------------------------------------------------
# §9.4 contract preservation: the fenced-YAML reply survives the
# `via: deepagents` route end-to-end.
#
# Unlike the tests above, this does NOT stub dispatch_prompt(): the harness is
# faked at the module's own `get_harness` seam (the pattern of
# tests/test_backend_deepagents.py), so the call really flows
# s1_autoexclude.run() -> _deepagents.dispatch_prompt() (via resolution) ->
# _deepagents.prompt() (option building) -> run_oneshot() -> the fake harness,
# and the raw result text comes back through the whole route into
# _extract_yaml. The assertion is on the PARSED overlay written to disk, not
# the raw string: a transport that forced structured output, wrapped the reply
# in JSON, or stripped the ```yaml fence would produce an empty overlay (the
# stage degrades silently) and the exclusion assertions below would fail.
# --------------------------------------------------------------------------

def test_run_parses_fenced_yaml_through_deepagents_route(tmp_path, monkeypatch):
    from pathlib import Path

    from vvaharness.backends.harness import OneShotResult, ToolPolicy
    from vvaharness.backends.llm import deepagents as _deepagents

    # A realistic reply: chatter around a fenced YAML block, exactly as the
    # user prompt requests ("Return ONLY a fenced YAML block ...").
    reply = (
        "Based on the survey, here are conservative additional exclusions:\n"
        "```yaml\n"
        "exclude_dirs:\n"
        "  - generated\n"
        "  - samples\n"
        "exclude_exts:\n"
        "  - .pb.go\n"
        "exclude_globs:\n"
        "  - tools/codegen/**\n"
        "max_file_kb: 2048\n"
        "```\n"
    )

    class _OneShotHarness:
        """Fake harness recording run_oneshot invocations."""

        def __init__(self):
            self.calls = []

        async def run_oneshot(self, prompt, options):
            self.calls.append((prompt, options))
            return OneShotResult(result_text=reply)

    fake = _OneShotHarness()
    monkeypatch.setattr(_deepagents, "get_harness", lambda _via: fake)

    (tmp_path / "repo").mkdir()
    cfg = SimpleNamespace(
        step1=SimpleNamespace(),
        models=SimpleNamespace(
            autoexclude=SimpleNamespace(id="claude-sonnet-4-6", via="deepagents"),
            preprocess="stub-model",
        ),
    )
    out = run(tmp_path / "repo", cfg, out_path=tmp_path / "overlay.yaml")
    overlay = yaml.safe_load(out.read_text(encoding="utf-8"))

    # The fake harness was really invoked — the deepagents route ran.
    assert fake.calls, "dispatch_prompt() never reached the deepagents harness"
    prompt_sent, options = fake.calls[0]
    assert "ADDITIONAL scan exclusions" in prompt_sent
    # The stage's routing decisions arrived on the options DTO intact.
    assert options.cwd == Path(str(tmp_path / "repo"))
    assert options.graph_name == "s1-autoexclude"
    assert options.tool_policy == ToolPolicy()

    # The PARSED overlay, not the raw text: the fenced YAML round-tripped.
    assert overlay["exclude_dirs"] == ["generated", "samples"]
    assert overlay["exclude_exts"] == [".pb.go"]
    assert overlay["exclude_globs"] == ["tools/codegen/**"]
    assert overlay["max_file_kb"] == 2048


# --------------------------------------------------------------------------
# VVAH-E003 floors: run() scopes stage-appropriate min_chars AND min_tokens
# around its dispatch, because a legitimately short (~120-150 char, ~31-46
# output-token) YAML overlay tripped the global 150-char floor in live
# testing and straddles the global 30-token floor — a spurious WARN + errlog
# entry, and at 3 consecutive a DegenerateResponseError that scan.py degrades
# to silently dropping the exclusion overlay. The backends call
# check_response_quality(stage=tag, output_tokens=<provider usage>) with no
# min_chars, so the fake dispatch below does exactly that, simulating any of
# the four routes.
# --------------------------------------------------------------------------

# A valid, short overlay reply: correct answer, yet under the 150-char global
# floor — the exact live-testing misfire.
_SHORT_VALID_REPLY = (
    "```yaml\n"
    "exclude_dirs:\n"
    "  - samples\n"
    "exclude_exts:\n"
    "  - .pb.go\n"
    "exclude_globs:\n"
    "  - tools/codegen/**\n"
    "```"
)
assert len(_SHORT_VALID_REPLY.strip()) < 150   # test is load-bearing
# Measured output-token count for a reply of this shape (~3.1 chars/token):
# under the global 30-token floor, above the stage's 10-token floor.
_SHORT_VALID_TOKENS = 25
assert 10 <= _SHORT_VALID_TOKENS < 30          # test is load-bearing


def _run_with_quality_checked_reply(tmp_path, monkeypatch, reply,
                                    output_tokens=None):
    """Stub dispatch_prompt with a fake that does what every backend does:
    run the reply through check_response_quality(stage=tag, output_tokens=…)
    with NO explicit min_chars, then return it."""
    from vvaharness.util.response_quality import check_response_quality

    def fake_dispatch(user_prompt, *, tag=None, **k):
        check_response_quality(reply.strip(), stage=tag or "",
                               output_tokens=output_tokens)
        return reply

    (tmp_path / "repo").mkdir(exist_ok=True)
    monkeypatch.setattr(
        "vvaharness.backends.llm.deepagents.dispatch_prompt", fake_dispatch)
    out = run(tmp_path / "repo", _cfg(), out_path=tmp_path / "overlay.yaml")
    return yaml.safe_load(out.read_text(encoding="utf-8"))


def test_run_short_valid_overlay_passes_quality_gate(tmp_path, monkeypatch,
                                                     capsys):
    """A valid short overlay must pass silently on BOTH floors: its char
    count is under the global 150 and its token count under the global 30."""
    overlay = _run_with_quality_checked_reply(
        tmp_path, monkeypatch, _SHORT_VALID_REPLY,
        output_tokens=_SHORT_VALID_TOKENS)
    err = capsys.readouterr().err
    assert "VVAH-E003" not in err, (
        "a valid short overlay must not be flagged degenerate — the stage "
        "floors were not applied around dispatch")
    # And the overlay round-tripped normally.
    assert overlay["exclude_dirs"] == ["samples"]
    assert overlay["exclude_exts"] == [".pb.go"]


def test_run_truly_degenerate_reply_still_flagged(tmp_path, monkeypatch,
                                                  capsys):
    """The stage floors are lower, not disabled: an empty/one-word reply
    still trips VVAH-E003 inside the stage scope."""
    _run_with_quality_checked_reply(tmp_path, monkeypatch, "ok",
                                    output_tokens=1)
    assert "VVAH-E003" in capsys.readouterr().err


def test_stage_floor_is_scoped_to_the_dispatch(tmp_path, monkeypatch, capsys):
    """After run() returns, the global floors are back in force for the same
    stage tag on BOTH axes — the override must not leak process-wide."""
    from vvaharness.util.response_quality import check_response_quality

    _run_with_quality_checked_reply(tmp_path, monkeypatch, _SHORT_VALID_REPLY,
                                    output_tokens=_SHORT_VALID_TOKENS)
    capsys.readouterr()
    # Char axis: the short-but-valid reply trips the restored 150-char floor.
    check_response_quality(_SHORT_VALID_REPLY.strip(), stage="s1 autoexclude")
    assert "VVAH-E003" in capsys.readouterr().err
    # Token axis: long-enough text with the same sub-30 token count trips the
    # restored 30-token floor.
    check_response_quality("x" * 200, stage="s1 autoexclude",
                           output_tokens=_SHORT_VALID_TOKENS)
    err = capsys.readouterr().err
    assert "VVAH-E003" in err and "token" in err


def test_explicit_min_chars_beats_stage_floor(capsys):
    """An explicitly caller-passed min_chars wins over an active override."""
    from vvaharness.util.response_quality import (check_response_quality,
                                                  stage_floors)

    with stage_floors("s1 autoexclude", min_chars=40, min_tokens=10):
        check_response_quality(_SHORT_VALID_REPLY.strip(),
                               stage="s1 autoexclude", min_chars=200)
    assert "VVAH-E003" in capsys.readouterr().err


def test_escalation_still_works_under_stage_floors():
    """3 consecutive genuinely degenerate replies inside the stage scope
    still escalate to DegenerateResponseError."""
    from vvaharness.backends.harness.models import DegenerateResponseError
    from vvaharness.util.response_quality import (check_response_quality,
                                                  stage_floors)

    with stage_floors("s1 autoexclude", min_chars=40, min_tokens=10):
        check_response_quality("ok", stage="s1 autoexclude", output_tokens=1)
        check_response_quality("ok", stage="s1 autoexclude", output_tokens=1)
        with pytest.raises(DegenerateResponseError):
            check_response_quality("ok", stage="s1 autoexclude",
                                   output_tokens=1)


# An overlay that empties the scope must be discarded. 'ext_copy'
# not 'vendor' for the bulk dir — 'vendor' is a built-in exclusion.

_SOURCE = ("src/app.py", "src/util.py", "lib/core.py", "web/index.js",
           "api/handler.go")


def _tree(root, n_bulk=3):
    """Populate a repo with production source plus a bulk checked-in copy."""
    for rel in _SOURCE + tuple(f"ext_copy/dep{i}.py" for i in range(n_bulk)):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x = 1\n", encoding="utf-8")
    return root


def _run_on_tree(tmp_path, monkeypatch, reply, cfg=None, n_bulk=3):
    repo = _tree(tmp_path / "repo", n_bulk)
    monkeypatch.setattr(
        "vvaharness.backends.llm.deepagents.dispatch_prompt",
        lambda *a, **k: reply)
    out = run(repo, cfg or _cfg(), out_path=tmp_path / "overlay.yaml")
    return yaml.safe_load(out.read_text(encoding="utf-8"))


@pytest.mark.parametrize("pattern", ["**/*", "*", "**", "**/*.*", "*/**",
                                     "**/**"])
def test_run_discards_overlay_that_empties_the_scope(tmp_path, monkeypatch,
                                                     capsys, pattern):
    # All bypass _erases_language and match every path ('*' spans '/').
    overlay = _run_on_tree(tmp_path, monkeypatch,
                           f"```yaml\nexclude_globs: ['{pattern}']\n```")
    assert overlay["exclude_globs"] == []
    err = capsys.readouterr().err
    assert "WARN: overlay would empty the scope" in err
    assert "DISCARDING" in err


def test_dot_slash_globstar_is_not_treated_as_repo_erasing(tmp_path,
                                                           monkeypatch,
                                                           capsys):
    # './**' matches nothing under fnmatch, so it empties nothing.
    overlay = _run_on_tree(tmp_path, monkeypatch,
                           "```yaml\nexclude_globs: ['./**']\n```")
    assert overlay["exclude_globs"] == ["./**"]
    assert "would empty the scope" not in capsys.readouterr().err


def test_run_discards_dir_only_overlay_that_empties_the_scope(tmp_path,
                                                             monkeypatch,
                                                             capsys):
    # exclude_dirs never reaches the veto — a second route to an empty scope.
    reply = "```yaml\nexclude_dirs: [src, lib, web, api, ext_copy]\n```"
    overlay = _run_on_tree(tmp_path, monkeypatch, reply)
    assert overlay["exclude_dirs"] == []
    assert "WARN: overlay would empty the scope" in capsys.readouterr().err


def test_discarded_overlay_is_recorded_as_degrading(tmp_path, monkeypatch):
    # Unmarked: a model that tried to delete the repo must flip scan health.
    seen = []
    monkeypatch.setattr("vvaharness.pipeline.stages.s1_autoexclude._errlog.log",
                        lambda *a, **k: seen.append((a, k)))
    _run_on_tree(tmp_path, monkeypatch,
                 "```yaml\nexclude_globs: ['**/*']\n```")
    assert len(seen) == 1
    assert seen[0][1]["reason"] == "s1_autoexclude_empty_scope"
    assert "recovered" not in seen[0][1]


def test_run_applies_aggressive_but_non_empty_overlay(tmp_path, monkeypatch,
                                                      capsys):
    # A vendor-heavy repo legitimately drops most files: warn, never reject.
    reply = ("```yaml\nexclude_globs: ['ext_copy/**', 'src/**', 'lib/**', "
             "'web/**']\n```")
    overlay = _run_on_tree(tmp_path, monkeypatch, reply, n_bulk=40)
    assert overlay["exclude_globs"] == ["ext_copy/**", "src/**", "lib/**",
                                        "web/**"]
    err = capsys.readouterr().err
    assert "WARN: overlay is aggressive" in err
    assert "would empty the scope" not in err


def test_run_normal_overlay_on_populated_tree_emits_no_scope_warning(
        tmp_path, monkeypatch, capsys):
    overlay = _run_on_tree(tmp_path, monkeypatch,
                           "```yaml\nexclude_dirs: [ext_copy]\n```")
    assert overlay["exclude_dirs"] == ["ext_copy"]
    err = capsys.readouterr().err
    assert "would empty the scope" not in err
    assert "overlay is aggressive" not in err


def test_scope_guard_is_inert_on_an_empty_repo(tmp_path, monkeypatch, capsys):
    # Nothing to protect: an already-empty tree is not an emptied scope.
    overlay = _run_with_reply(tmp_path, monkeypatch,
                              "```yaml\nexclude_globs: ['**/*']\n```")
    assert overlay["exclude_globs"] == ["**/*"]
    assert "would empty the scope" not in capsys.readouterr().err


def _big_tree(root, n=4, size=3000):
    """Files large enough that lowering max_file_kb alone empties the scope."""
    for i in range(n):
        p = root / "src" / f"m{i}.py"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("# pad\n" * (size // 6), encoding="utf-8")
    return root


def test_run_discards_overlay_that_empties_the_scope_by_size(tmp_path,
                                                             monkeypatch,
                                                             capsys):
    # max_file_kb shrinks scope as surely as a glob, and _survey never had a size filter at all.
    _big_tree(tmp_path / "repo")
    monkeypatch.setattr(
        "vvaharness.backends.llm.deepagents.dispatch_prompt",
        lambda *a, **k: "```yaml\nmax_file_kb: 1\n```")
    out = run(tmp_path / "repo", _cfg(max_file_kb=1024),
              out_path=tmp_path / "overlay.yaml")
    overlay = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert "max_file_kb" not in overlay
    assert "WARN: overlay would empty the scope" in capsys.readouterr().err


def test_run_keeps_a_max_file_kb_raise(tmp_path, monkeypatch, capsys):
    # Raising the limit widens scope; it must never trip the guard.
    overlay = _run_on_tree(tmp_path, monkeypatch,
                           "```yaml\nmax_file_kb: 2048\n```")
    assert overlay["max_file_kb"] == 2048
    err = capsys.readouterr().err
    assert "would empty the scope" not in err
    assert "overlay is aggressive" not in err
