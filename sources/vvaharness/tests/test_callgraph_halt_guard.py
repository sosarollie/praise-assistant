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

"""
Consumer tests for the callgraph engine's halt guard, plus the VVAH-E003
floors on its ``s0 callgraph-annotate`` dispatch.

The halt guard — ``callgraph_engine.run()``'s ``if is_halt_error(e): raise``
inside the llm-detection ``except Exception`` — previously had NO consumer
test: deleting it left the whole suite green, because the annotator tests
only call ``detect_specs`` directly and never make it raise, and the s0 tests
never reach the guard. These tests drive ``run()`` itself in llm detection
mode:

* VVAH-E001 (authentication) and VVAH-E002 (proxy/TLS) must PROPAGATE.
  Degrading them means silently downgrading an llm-detection scan to rules
  mode and spending the rest of the run on a dead credential.
* An ordinary exception must NOT propagate — the engine falls back to rules
  mode exactly as it always did.

The error instances are built from ``vvaharness.backends.harness.models``,
the module the backends actually raise. ``is_halt_error`` compares classes by
identity, so a duplicate hierarchy (a real, since-fixed merge accident — see
``backends/harness/contract/errors.py``) turns the guard into a silent no-op;
the propagation test fails in that world too, which is the point of driving
it with the real classes.
"""

from types import SimpleNamespace

import pytest

from vvaharness.backends.harness import models
from vvaharness.pipeline.stages import callgraph_engine as engine
from vvaharness.pipeline.stages.callgraph_engine import _annotator as ann
from vvaharness.pipeline.stages.callgraph_engine._scan import (
    FileIndex,
    ObservedCall,
)
from vvaharness.pipeline.stages.s0_seed import SeedPackage
from vvaharness.util import response_quality


@pytest.fixture(autouse=True)
def _isolated_quality_state(monkeypatch, tmp_path):
    # check_response_quality keeps a process-global per-tag consecutive
    # counter: a warning left behind by one test would raise the count the
    # next test observes. And its warning path appends to the errlog module
    # singleton, which defaults to ./pipeline-errors.jsonl — redirect it so a
    # test never writes into the working tree.
    response_quality.reset_counters()
    monkeypatch.setattr(response_quality._errlog, "_path",
                        tmp_path / "errors.jsonl")
    yield
    response_quality.reset_counters()


def _observed_index():
    fi = FileIndex(file="app.py", language="python", imports={}, functions=[])
    fi.observed_calls = [ObservedCall(
        file="app.py", line=3, language="python", receiver="request",
        resolved_receiver="request", method="get", containing_fn="handler",
        snippet="request.get(x)")]
    return fi


def _llm_cfg():
    return SimpleNamespace(
        step0=SimpleNamespace(
            callgraph_detection="llm",
            callgraph=SimpleNamespace(llm=SimpleNamespace(
                max_candidates=400, max_batch_candidates=150,
                min_source_confidence=0.75, min_sink_confidence=0.75,
                max_tokens=16000, failure_mode="empty",
                heuristic_supplement=False, min_sources=0, min_sinks=0,
                max_heuristic_specs=0, self_consistency=1)),
        ),
        models=SimpleNamespace(graph_annotate=SimpleNamespace(id="m", via="sdk")),
    )


# ── the halt guard ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("halt_cls,halt_exc", [
    (models.AuthenticationError,
     models.AuthenticationError("credentials rejected",
                                status_code=401, backend="sdk")),
    (models.ProxyError,
     models.ProxyError("TLS handshake failed", backend="sdk")),
])
def test_halt_errors_propagate_out_of_run(monkeypatch, tmp_path,
                                          halt_cls, halt_exc):
    """VVAH-E001/E002 raised inside llm detection must escape run()."""
    monkeypatch.setattr(engine, "_scan_repo",
                        lambda *a, **kw: [_observed_index()])

    def raise_halt(*a, **kw):
        raise halt_exc

    monkeypatch.setattr(engine, "detect_specs", raise_halt)
    with pytest.raises(halt_cls):
        engine.run(str(tmp_path), _llm_cfg(), in_scope=set(), langs=["python"])


def test_ordinary_failure_degrades_to_rules_mode(monkeypatch, tmp_path, capsys):
    """The twin: a plain RuntimeError must NOT propagate.

    Anything that is not a halt error keeps the engine's original contract —
    log the failure and fall back to the configured rules YAML so the scan
    continues. A guard rewritten as a bare re-raise would fail here.
    """
    monkeypatch.setattr(engine, "_scan_repo",
                        lambda *a, **kw: [_observed_index()])

    def raise_runtime(*a, **kw):
        raise RuntimeError("provider hiccup")

    monkeypatch.setattr(engine, "detect_specs", raise_runtime)
    pkg = engine.run(str(tmp_path), _llm_cfg(), in_scope=set(),
                     langs=["python"])
    assert isinstance(pkg, SeedPackage)
    err = capsys.readouterr().err
    assert "falling back to configured rules YAML" in err


# ── the s0 callgraph-annotate floors ─────────────────────────────────────────
# The annotate reply is compact JSON, and a final batch holding a single
# all-none candidate answers in 86 chars / ~31 tokens — under the global
# 150-char / 30-token VVAH-E003 floors, which are sized for prose stages.
# _annotator scopes stage_floors around its dispatch so that a correct short
# reply is not flagged (and, at 3 consecutive trips, not DROPPED as a sample).
# The fake below applies the SAME gate every shipped route applies —
# check_response_quality(text.strip(), stage=tag, output_tokens=...), with
# stage=tag verbatim (sdk/openai/cli/deepagents all do) — so these tests
# observe the override exactly where the backends would.

_ALL_NONE_REPLY = ('{"results":[{"id":"c1","role":"none","confidence":0.9,'
                   '"cwe":"CWE-20","kind":"other"}]}')


def _quality_gated_backend(reply: str, output_tokens: int):
    def fake(user_prompt, *, tag=None, **kw):
        response_quality.check_response_quality(
            reply.strip(), stage=tag or "", output_tokens=output_tokens)
        return reply
    return fake


def test_valid_all_none_reply_passes_the_annotate_floors(monkeypatch, capsys):
    monkeypatch.setattr(
        ann._deepagents, "dispatch_prompt",
        _quality_gated_backend(_ALL_NONE_REPLY, output_tokens=27))
    srcs, sinks, _ = ann.detect_specs(
        [_observed_index()], ["python"], _llm_cfg(),
        repo_root="/nonexistent-repo")
    # role=none classifies nothing — a fully valid outcome, not degeneracy.
    assert srcs == [] and sinks == []
    # The observable is the VVAH-E003 warning line: a floor failure warns to
    # stderr and returns the text, so asserting on the parsed result alone
    # could never catch a misfire.
    assert "VVAH-E003" not in capsys.readouterr().err


def test_empty_reply_still_trips_the_floor(monkeypatch, capsys):
    """Guards the floors against being lowered to nothing: an empty body must
    still be flagged even with the stage override active."""
    monkeypatch.setattr(ann._deepagents, "dispatch_prompt",
                        _quality_gated_backend("", output_tokens=0))
    srcs, sinks, _ = ann.detect_specs(
        [_observed_index()], ["python"], _llm_cfg(),
        repo_root="/nonexistent-repo")
    assert srcs == [] and sinks == []
    assert "VVAH-E003" in capsys.readouterr().err
