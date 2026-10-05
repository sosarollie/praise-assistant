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

"""Tests for the in-pipeline remediation wiring and the shared per-finding loop.

When enabled, the auto-editing in-pipeline path
(``orchestrator.scan._run_remediation``) applies the top-N cap and DELEGATES the
per-finding loop to the SAME ``runner.process_targets`` the standalone
``remediate`` command uses — one loop, not two. These tests lock:

  * the delegation contract — top-N cap, TYPED ``Finding`` hand-off, fix mode,
    resume threading, shared ckpt_dir/run_id via Layout, binding the EXACT scan
    report for augmentation, and returning the runner's exit code;
  * the canonical loop's invariants in ``runner.remediate_one`` — resume-skip and
    per-finding failure-isolation — which now serve BOTH entry points.

The hand-off used to downgrade each ranked finding into a five-field
Markdown-shaped struct, which dropped ``duplicates`` and the structured
``source_ref``/``sink_ref`` pair; the assertions below are what keeps them.
"""
from __future__ import annotations

import io
from contextlib import contextmanager, redirect_stderr
from types import SimpleNamespace

import pytest

from vvaharness.models import (
    Disposition,
    DupLocation,
    Finding,
    RankedFinding,
    Remediation,
    RemediationKind,
    Severity,
)
from vvaharness.orchestrator import scan
from vvaharness.remediation_agent import runner
from vvaharness.remediation_agent.discovery import Layout
from vvaharness.remediation_agent.options import RemediateOptions
from vvaharness.remediation_agent.target import RemediationTarget


def _remediated() -> Remediation:
    """What ``apply_plugin`` now returns: the harness's account of one attempt."""
    return Remediation(kind=RemediationKind.EDITS_APPLIED, summary="fixed",
                       diff="@@ -1 +1 @@\n-old\n+new\n")


def _ranked(title: str, score: float, *,
            severity: Severity = Severity.HIGH) -> RankedFinding:
    """A real pipeline RankedFinding, carrying the evidence the old adapter lost."""
    finding = Finding(
        title=title, file="app/db.py", line_start=10, line_end=10,
        vuln_class="injection", severity=severity, cwe="CWE-89",
        description="desc", source_ref="app/web.py:4", sink_ref="app/db.py:10",
        code_snippet="cur.execute(q)", cvss_score=score,
        duplicates=[DupLocation(file="app/admin.py", line_start=77,
                                vuln_class="injection")],
    )
    return RankedFinding(finding=finding, severity=severity,
                         exploitability_notes="notes")


@pytest.fixture
def cfg():
    # top_n_findings None → no profile cap; tests pass an explicit --top where
    # the cap itself is under test. Provide a minimal models.remediate spec so
    # the orchestrator backend resolution succeeds.
    return SimpleNamespace(
        step_remediate=SimpleNamespace(top_n_findings=None),
        models=SimpleNamespace(remediate=SimpleNamespace(id="claude-opus-4-8", via="cli")),
    )


def _capture_process_targets(monkeypatch):
    """Replace runner.process_targets with a recorder so the delegation
    contract can be asserted without running the real agent loop."""
    calls: dict = {}

    def fake(targets, *, layout, cfg, repo_path, opts, report=None):
        calls.update(targets=targets, findings=[t.finding for t in targets],
                     layout=layout, cfg=cfg, repo_path=repo_path, opts=opts, report=report)
        return 0

    monkeypatch.setattr(
        "vvaharness.remediation_agent.runner.process_targets", fake)
    return calls


def test_run_remediation_delegates_to_process_targets(tmp_path, cfg, monkeypatch):
    calls = _capture_process_targets(monkeypatch)
    report = SimpleNamespace(findings=[_ranked("SQLi", 9.0), _ranked("XSS", 5.0)])
    ckpt = tmp_path / "ck"

    rc = scan._run_remediation(report, tmp_path, cfg, ckpt, "run-1",
                               resume=False, top=None,
                               report_md=tmp_path / "report.md")

    # The runner's exit code is returned, not discarded.
    assert rc == 0
    # Both findings delegated as TYPED Findings, in CVSS order. The runner's own signature is
    # asserted separately by test_process_targets_takes_typed_targets; this is the other
    # half of the seam -- that the ORCHESTRATOR hands over the typed object rather than a
    # rendering of it. Neither test implies the other, so neither is redundant.
    assert [f.title for f in calls["findings"]] == ["SQLi", "XSS"]
    assert all(isinstance(f, Finding) for f in calls["findings"])
    # The evidence the old markdown-shaped adapter threw away arrives intact -- the whole
    # point of the change: source/sink and the other call sites reach remediation.
    first = calls["findings"][0]
    assert first.source_ref == "app/web.py:4" and first.sink_ref == "app/db.py:10"
    assert [(d.file, d.line_start) for d in first.duplicates] == [("app/admin.py", 77)]
    assert first.severity is Severity.HIGH and first.cwe == "CWE-89"
    # Fix mode is forced (the in-pipeline path always auto-edits).
    assert calls["opts"].mode == "fix"
    assert calls["opts"].resume is False
    # Scan's ckpt_dir/run_id threaded through Layout → shared resume state.
    assert calls["layout"].ckpt_dir == ckpt
    assert calls["layout"].run_id == "run-1"
    assert calls["layout"].rem_dir == tmp_path / "security-remediation"
    # The EXACT scan report is bound for augmentation, not a glob.
    assert calls["report"] == tmp_path / "report.md"
    assert calls["repo_path"] == tmp_path


def test_run_remediation_applies_top_n_cap(tmp_path, cfg, monkeypatch):
    calls = _capture_process_targets(monkeypatch)
    report = SimpleNamespace(findings=[
        _ranked("low", 3.0), _ranked("high", 9.0), _ranked("mid", 6.0)])

    scan._run_remediation(report, tmp_path, cfg, tmp_path / "ck", "run-1", top=2)

    # Only the 2 highest-CVSS findings are delegated, highest first.
    assert [f.title for f in calls["findings"]] == ["high", "mid"]


def test_run_remediation_threads_resume_flag(tmp_path, cfg, monkeypatch):
    calls = _capture_process_targets(monkeypatch)
    report = SimpleNamespace(findings=[_ranked("SQLi", 9.0)])

    scan._run_remediation(report, tmp_path, cfg, tmp_path / "ck", "run-1",
                          resume=True)

    assert calls["opts"].resume is True


def test_run_remediation_returns_the_runners_failure_code(tmp_path, cfg, monkeypatch):
    """A partial remediation must not read as success.

    ``process_targets`` returns 1 when it did not process every finding. That code was
    discarded here, so an s10 that failed on every finding still let the scan exit 0.
    """
    monkeypatch.setattr(
        "vvaharness.remediation_agent.runner.process_targets",
        lambda *a, **k: 1)
    report = SimpleNamespace(findings=[_ranked("SQLi", 9.0)])

    rc = scan._run_remediation(report, tmp_path, cfg, tmp_path / "ck", "run-1")

    assert rc == 1


def _target(idx: int = 1) -> RemediationTarget:
    """One typed finding wrapped for the loop — what a caller hands ``process_targets``."""
    return RemediationTarget(
        finding=Finding(title="SQLi in db", file="app/db.py", line_start=10,
                        vuln_class="injection", severity="high"),
        index=idx,
    )


def _layout(tmp_path) -> Layout:
    return Layout(rem_dir=tmp_path / "rem", ckpt_dir=tmp_path / "ck",
                  run_id="run-1")


def test_process_targets_takes_typed_targets(tmp_path, monkeypatch):
    """The public entry point accepts ``models.Finding`` and assigns the ordinals itself.

    This is the seam both callers meet at: the pipeline hands its ranked findings straight
    over, and the standalone command parses markdown into the same type first. Neither has
    to know what the prompt builder wants."""
    seen: list = []
    monkeypatch.setattr(runner, "load_ckpt", lambda *a, **k: None)
    monkeypatch.setattr(runner, "save_ckpt", lambda *a, **k: None)
    monkeypatch.setattr(
        runner, "apply_plugin",
        lambda target, *a, **k: (seen.append(target), _remediated())[1])
    monkeypatch.setattr(runner._policy, "build_context",
                        lambda cfg, repo: SimpleNamespace(enabled=False))
    monkeypatch.setattr("vvaharness.remediation_agent.report_augment.augment_reports",
                        lambda *a, **k: None)

    findings = [
        Finding(title="SQLi", file="app/db.py", line_start=10, vuln_class="injection"),
        Finding(title="XSS", file="app/web.py", line_start=20, vuln_class="injection"),
    ]
    from vvaharness.remediation_agent.target import RemediationTarget
    targets = [RemediationTarget(finding=f, index=i)
               for i, f in enumerate(findings, start=1)]
    rc = runner.process_targets(
        targets, layout=_layout(tmp_path), cfg=object(), repo_path=tmp_path,
        opts=RemediateOptions(resume=False, mode="fix"))

    assert rc == 0
    # The caller owns the ordinal; the findings pass through untouched.
    assert [t.index for t in seen] == [1, 2]
    assert [t.finding for t in seen] == findings
    assert [t.slug for t in seen] == ["01_sqli", "02_xss"]


def test_process_targets_reports_unapplied_fix_distinctly(tmp_path, monkeypatch,
                                                          capsys):
    """A clean agent call is not a successful fix when it applied nothing."""
    outcomes = iter([
        _remediated(),
        Remediation(kind=RemediationKind.NO_ACTION, summary="could not fix",
                    disposition=Disposition.NOT_APPLICABLE),
    ])
    monkeypatch.setattr(runner, "load_ckpt", lambda *a, **k: None)
    monkeypatch.setattr(runner, "save_ckpt", lambda *a, **k: None)
    monkeypatch.setattr(runner, "apply_plugin", lambda *a, **k: next(outcomes))
    monkeypatch.setattr(runner._policy, "build_context",
                        lambda cfg, repo: SimpleNamespace(enabled=False))
    monkeypatch.setattr("vvaharness.remediation_agent.report_augment.augment_reports",
                        lambda *a, **k: None)

    progress = {}
    rc = runner.process_targets(
        [_target(1), _target(2)], layout=_layout(tmp_path), cfg=object(),
        repo_path=tmp_path, opts=RemediateOptions(resume=False, mode="fix"),
        progress=progress)

    err = capsys.readouterr().err
    assert rc == 0  # both attempts ran without an infrastructure failure
    assert "○ [2/2]" in err and "— not fixed" in err
    assert "2/2 findings processed — 1/2 fixed, 1 not fixed" in err
    assert progress == {"attempted": 2, "fixed": 1, "not_fixed": 1}


def test_process_targets_counts_failed_attempt_as_not_fixed(tmp_path, monkeypatch):
    """The progress stream reports the true fix outcome, including agent errors."""
    monkeypatch.setattr(runner, "load_ckpt", lambda *a, **k: None)
    monkeypatch.setattr(runner, "save_ckpt", lambda *a, **k: None)
    monkeypatch.setattr(runner, "apply_plugin", lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("agent failed")))
    monkeypatch.setattr(runner._policy, "build_context",
                        lambda cfg, repo: SimpleNamespace(enabled=False))
    monkeypatch.setattr("vvaharness.remediation_agent.report_augment.augment_reports",
                        lambda *a, **k: None)
    progress = {}

    rc = runner.process_targets(
        [_target()], layout=_layout(tmp_path), cfg=object(), repo_path=tmp_path,
        opts=RemediateOptions(resume=False, mode="fix"), progress=progress)

    assert rc == 1
    assert progress == {"attempted": 1, "fixed": 0, "not_fixed": 1}


def test_remediate_one_resume_skips_checkpointed(tmp_path, monkeypatch):
    """A checkpoint whose recorded identity MATCHES the current finding is
    skipped on --resume: the agent is never invoked, and it counts processed."""
    finding = _target()
    calls = {"applied": 0}
    # Authentic cache hit: the record carries this finding's identity.
    cached = {"kind": "edits_applied",
              "finding_id": runner._finding_identity(finding)}
    monkeypatch.setattr(runner, "load_ckpt", lambda *a, **k: cached)
    monkeypatch.setattr(
        runner, "apply_plugin",
        lambda *a, **k: calls.__setitem__("applied", calls["applied"] + 1))

    ok = runner.remediate_one(
        finding, idx=1, total=1, layout=_layout(tmp_path), cfg=object(),
        repo_path=tmp_path, opts=RemediateOptions(resume=True, mode="fix"))

    assert ok is True
    assert calls["applied"] == 0  # agent NOT run for an authenticated cache hit


def test_remediate_one_resume_reruns_on_identity_mismatch(tmp_path, monkeypatch):
    """A checkpoint that EXISTS but whose recorded identity does
    NOT match the current finding (a reordered prior run on the same repo path,
    or a tampered state DB) must NOT be treated as done — the finding is
    re-remediated rather than silently counted processed."""
    applied = []
    monkeypatch.setattr(   # exists, but bound to a different finding
        runner, "load_ckpt",
        lambda *a, **k: {"kind": "edits_applied", "finding_id": "someone-elses-hash"})
    monkeypatch.setattr(runner, "save_ckpt", lambda *a, **k: None)
    monkeypatch.setattr(
        runner, "apply_plugin",
        lambda finding, *a, **k: (applied.append(finding.index), _remediated())[1])

    ok = runner.remediate_one(
        _target(), idx=1, total=1, layout=_layout(tmp_path), cfg=object(),
        repo_path=tmp_path, opts=RemediateOptions(resume=True, mode="fix"))

    assert ok is True
    assert applied == [_target().index]  # re-ran, did not trust the cache


def test_remediate_one_isolates_failure(tmp_path, monkeypatch):
    """A finding whose remediation raises does NOT abort the run: remediate_one
    swallows the error and returns False so the caller continues."""
    def boom(*a, **k):
        raise RuntimeError("agent exploded")

    monkeypatch.setattr(runner, "load_ckpt", lambda *a, **k: None)
    monkeypatch.setattr(runner, "apply_plugin", boom)

    ok = runner.remediate_one(
        _target(), idx=1, total=1, layout=_layout(tmp_path), cfg=object(),
        repo_path=tmp_path, opts=RemediateOptions(resume=False, mode="fix"))

    assert ok is False  # failure reported, no exception propagated


@pytest.mark.parametrize(("verbose", "expected_animate"), [
    (False, None),
    (True, False),
])
def test_remediate_one_preserves_the_shared_tty_gate(
        tmp_path, monkeypatch, verbose, expected_animate):
    """Normal S10 output lets ``stage`` inspect stderr; verbose output stays plain.

    Passing ``True`` for the normal case bypasses ``stage``'s isatty gate and writes
    spinner frames and cursor escapes into redirected scan logs.
    """
    animate_args = []

    @contextmanager
    def capture_stage(*_args, **kwargs):
        animate_args.append(kwargs.get("animate"))
        yield SimpleNamespace(mark_incomplete=lambda _detail: None)

    monkeypatch.setattr(runner, "stage", capture_stage)
    monkeypatch.setattr(runner, "step_key_of", lambda *_a, **_k: "step")
    monkeypatch.setattr(runner, "apply_plugin", lambda *_a, **_k: _remediated())
    monkeypatch.setattr(runner, "save_ckpt", lambda *_a, **_k: None)

    ok = runner.remediate_one(
        _target(), idx=1, total=1, layout=_layout(tmp_path), cfg=object(),
        repo_path=tmp_path,
        opts=RemediateOptions(resume=False, mode="fix", verbose=verbose),
    )

    assert ok is True
    assert animate_args == [expected_animate]


def test_remediate_one_redirected_stderr_contains_no_spinner_output(
        tmp_path, monkeypatch):
    """A plain redirected scan must not acquire ANSI output when it reaches S10."""
    from vvaharness.util import status

    class RecordingSpinner:
        """Make accidental spinner construction visible without a timing-sensitive thread."""

        def __init__(self, _label, out, **_kwargs):
            self.out = out

        def start(self):
            self.out.write("\x1b[36m⠋\x1b[0m")
            return self

        def stop(self):
            self.out.write("\x1b[K")

    monkeypatch.setattr(status, "_Spinner", RecordingSpinner)
    monkeypatch.setattr(runner, "step_key_of", lambda *_a, **_k: "step")
    monkeypatch.setattr(runner, "apply_plugin", lambda *_a, **_k: _remediated())
    monkeypatch.setattr(runner, "save_ckpt", lambda *_a, **_k: None)
    redirected = io.StringIO()

    with redirect_stderr(redirected):
        ok = runner.remediate_one(
            _target(), idx=1, total=1, layout=_layout(tmp_path), cfg=object(),
            repo_path=tmp_path,
            opts=RemediateOptions(resume=False, mode="fix", verbose=False),
        )

    assert ok is True
    assert redirected.isatty() is False
    assert "⠋" not in redirected.getvalue()
    assert "\x1b" not in redirected.getvalue()


@pytest.mark.parametrize(("verbose", "expected_animate"), [
    (False, None),
    (True, False),
])
def test_interactive_remediation_preserves_the_shared_tty_gate(
        tmp_path, monkeypatch, verbose, expected_animate):
    """The standalone numbered fallback follows the same animation contract as S10."""
    from vvaharness.remediation_agent.interactive import loop

    animate_args = []

    @contextmanager
    def capture_stage(*_args, **kwargs):
        animate_args.append(kwargs.get("animate"))
        yield

    monkeypatch.setattr(loop, "stage", capture_stage)
    monkeypatch.setattr(loop, "step_key_of", lambda *_a, **_k: "step")
    monkeypatch.setattr(loop, "apply_plugin", lambda *_a, **_k: _remediated())
    monkeypatch.setattr(loop, "save_ckpt", lambda *_a, **_k: None)
    monkeypatch.setattr(loop.report_parser, "mark_done", lambda *_a, **_k: None)

    ok = loop._remediate_one(
        _target(), report_path=tmp_path / "report.md",
        rem_dir=tmp_path / "rem", ckpt_dir=tmp_path / "ck", run_id="run-1",
        cfg=object(), mode="fix", verbose=verbose,
    )

    assert ok is True
    assert animate_args == [expected_animate]


# _remediate_preflight is the call-site gate (scan.py) that decides whether the
# in-pipeline remediation step runs at all — independent of the loop above. It
# refuses when no models.remediate role is configured, when that role's backend
# credential is missing (startup preflight only WARNs on a post-scan gap, so this
# is where it becomes a skip), or when HEAD moved since the scan report was built
# (stale line numbers → a patch would land on the wrong code), unless --force
# overrides.

def _report(git_sha=None):
    return SimpleNamespace(findings=[], git_sha=git_sha)


def _credential(monkeypatch, ready=True, detail="credential present"):
    """Pin the backend-credential answer so the HEAD/role cases below exercise only
    their own logic. Patched on the environment module because _remediate_preflight
    imports the helper at call time (circular-import avoidance)."""
    from vvaharness.util import environment
    monkeypatch.setattr(environment, "_backend_credential_ok",
                        lambda *_a, **_k: (ready, detail))


def test_preflight_blocks_when_remediate_role_missing(tmp_path):
    cfg = SimpleNamespace(models=SimpleNamespace(remediate=None))
    args = SimpleNamespace(force=False)
    err = scan._remediate_preflight(cfg, args, tmp_path, _report())
    assert err and "models.remediate" in err


def test_preflight_blocks_when_credential_missing(tmp_path, monkeypatch):
    """A credential gap disables s10 (scan continues) instead of aborting."""
    cfg = SimpleNamespace(models=SimpleNamespace(remediate="x"))
    args = SimpleNamespace(force=False)
    _credential(monkeypatch, ready=False, detail="`claude` CLI not on PATH")
    monkeypatch.setattr(scan, "_head_sha", lambda _repo: "a" * 40)
    err = scan._remediate_preflight(cfg, args, tmp_path, _report(git_sha="a" * 40))
    assert err and "via:cli" in err and "not on PATH" in err


def test_preflight_blocks_when_head_moved(tmp_path, monkeypatch):
    cfg = SimpleNamespace(models=SimpleNamespace(remediate="x"))
    args = SimpleNamespace(force=False)
    _credential(monkeypatch)
    monkeypatch.setattr(scan, "_head_sha", lambda _repo: "b" * 40)
    err = scan._remediate_preflight(cfg, args, tmp_path, _report(git_sha="a" * 40))
    assert err and "HEAD moved" in err


def test_preflight_head_move_overridden_by_force(tmp_path, monkeypatch):
    cfg = SimpleNamespace(models=SimpleNamespace(remediate="x"))
    args = SimpleNamespace(force=True)
    _credential(monkeypatch)
    monkeypatch.setattr(scan, "_head_sha", lambda _repo: "b" * 40)
    assert scan._remediate_preflight(
        cfg, args, tmp_path, _report(git_sha="a" * 40)) is None


def test_preflight_passes_when_sha_matches(tmp_path, monkeypatch):
    cfg = SimpleNamespace(models=SimpleNamespace(remediate="x"))
    args = SimpleNamespace(force=False)
    _credential(monkeypatch)
    monkeypatch.setattr(scan, "_head_sha", lambda _repo: "a" * 40)
    assert scan._remediate_preflight(
        cfg, args, tmp_path, _report(git_sha="a" * 40)) is None
