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

"""The ``prompt()`` stub contract.

``PromptStub`` is a drop-in replacement for ``vvaharness.backends.llm.registry.prompt``
that returns canned, per-stage JSON instead of calling a real model, records
every call it receives, and can be told to raise instead of returning.

Import form matters. A module that does
``from vvaharness.backends.llm.registry import prompt`` at load time binds
the NAME ``prompt`` into its OWN namespace; patching
``vvaharness.backends.llm.registry.prompt`` after that import has already
happened does nothing to that module's calls — it already holds its own
reference to the original function. No stage binds the name any more, so the
``stub_prompt`` fixture in ``conftest.py`` patches ONE location:

    vvaharness.backends.llm.registry.prompt     (the origin — covers every
                                                   stage that routes through
                                                   ``_deepagents.dispatch_prompt``,
                                                   which resolves
                                                   ``registry.prompt`` at
                                                   call time on the legacy
                                                   non-deepagents branch:
                                                   s1_autoexclude, s2, s3,
                                                   s4_deepdive, s7_dedup,
                                                   s8_chain)

``s1_autoexclude``, ``s7_dedup``, ``s8_chain`` and finally ``s4_deepdive``
used to bind ``prompt`` at module load time and needed their own patches. All
have since migrated to ``from vvaharness.backends.llm import deepagents as
_deepagents`` and call ``_deepagents.dispatch_prompt``, so patching the
origin above DOES reach them now. The one remaining caller that still binds
``prompt`` at module load time — OUT OF SCOPE, unreachable by the patch
above — is:

    vvaharness.rules.generic_pack                      (`:40`)

Also out of scope: the callers that never call ``prompt()`` at all —
``s1_preprocess`` and ``s6_verify`` route through
``_deepagents.dispatch_agentic`` (imports at `s1_preprocess.py:39` /
`s6_verify.py:36`), reached by patching
``vvaharness.backends.llm.registry.agentic`` (call-time resolution on the
legacy branch, same as ``prompt`` above). The one caller that still binds
``agentic`` at module load time — needing its own patch of that module's
bound name — is the remediation plugin runner
(`plugin_runner/__init__.py:38`). The autouse network kill in
``conftest.py`` is the only thing standing between an unpatched caller and a
real backend, and it does not cover the one backend that shells out to a
subprocess.

Callers that import ``prompt`` INSIDE a function body (``probe_backends``,
`~preflight.py:579`; ``_call_and_diff``, `~preflight.py:1043`) resolve the
name from ``registry`` at call time, so patching the origin above does
cover them (the in-function ``agentic`` import in ``_probe_agentic_roles``,
`~preflight.py:423`, is call-time-resolved the same way).
"""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any


def _default_s2_response() -> str:
    return json.dumps({
        "system_context": "Stub system context from the offline prompt stub.",
        "assets": [{"name": "primary-asset", "sensitivity": "high"}],
        "trust_boundaries": [{
            "entry_point": "stub_entry",
            "crossing": "unauth network -> application logic",
            "reachable_assets": ["primary-asset"],
        }],
        "threats": [{
            "id": "T1",
            "threat": "Stub threat for offline tests",
            "actor": "remote_unauth",
            "surface": "stub_entry",
            "asset": "primary-asset",
            "impact": "high",
            "likelihood": "possible",
        }],
        "open_questions": [],
    })


def _default_s3_response() -> str:
    return json.dumps({
        "chunks": [],
        "rationale": "stub: deterministic offline manifest from the prompt stub",
    })


def _default_s4_response() -> str:
    return json.dumps({"findings": []})


class PromptStub:
    """Callable stand-in for ``prompt(user_prompt, *, model, **kw) -> str``.

    Usage in a test::

        def test_something(stub_prompt):
            stub_prompt.set_response("s3", json.dumps({"chunks": [...], "rationale": "x"}))
            ...
            assert stub_prompt.calls[-1]["kw"]["timeout"] == 1800

        def test_s4_failure_path(stub_prompt):
            stub_prompt.set_raise("s4", TimeoutError("simulated provider timeout"))
            ...  # exercise the code path that must survive prompt() raising
    """

    def __init__(self) -> None:
        self.responses: dict[str, str | Callable[[], str]] = {
            "s2": _default_s2_response,
            "s3": _default_s3_response,
            "s4": _default_s4_response,
        }
        self.raises: dict[str, BaseException] = {}
        self.calls: list[dict[str, Any]] = []

    @staticmethod
    def _stage_of(kw: dict) -> str:
        """Stages are inferred from the ``tag`` kwarg every real call site
        passes (``_threatmodel_call``, `~s2_threatmodel.py:1321`/`:1331`,
        tag="s2 threatmodel"; s3 ``run``, `~s3_decompose.py:229`,
        tag="s3 decompose"; ``_single_run``, `~s4_deepdive.py:745`,
        tag=f"s4 {chunk.id}", and its JSON-repair retry at `~:770`,
        tag=f"s4 {chunk.id} json-repair", which maps to the same "s4"
        stage). Falls back to "default" for any call with no tag."""
        tag = str(kw.get("tag") or "")
        # `split()[0]` would raise on a whitespace-only tag.
        return next(iter(tag.split()), "default")

    def set_response(self, stage: str, value) -> None:
        """Override the canned response for ``stage`` ("s2"/"s3"/"s4").
        ``value`` may be a JSON string, or a zero-arg callable returning one
        (for tests that want a fresh/varying body per call)."""
        self.responses[stage] = value

    def set_raise(self, stage: str, exc: BaseException) -> None:
        """Make the next (and all subsequent) calls tagged for ``stage``
        raise ``exc`` instead of returning — for exercising the "model call
        failed, degrade gracefully" paths in the stages that call this."""
        self.raises[stage] = exc

    def clear_raise(self, stage: str) -> None:
        self.raises.pop(stage, None)

    def __call__(self, user_prompt: str, *, model: Any = None, **kw) -> str:
        stage = self._stage_of(kw)
        self.calls.append({
            "stage": stage,
            "prompt": user_prompt,
            "model": model,
            "kw": dict(kw),
        })
        if stage in self.raises:
            raise self.raises[stage]
        resp = self.responses.get(stage, self.responses.get("default", "{}"))
        return resp() if callable(resp) else resp
