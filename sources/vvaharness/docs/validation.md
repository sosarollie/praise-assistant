<!--
Copyright 2026 Visa, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Validation panel (`validate` / `s11` — step 11)

The canonical reference for the agentic validation command. It grades the fixes
the [Remediation Agent](remediation.md) (step 10) produced. For the trust model
see [security.md](security.md); for config knobs see
[configuration.md](configuration.md#step_validate--validator-s11).

> **Not the live re-check for exploit verification.** The panel grades a fix from
> the repo and the remediation DTO only; it consumes no `ev_*` finding fields, so
> a finding that [exploit verification](exploit-verification.md) confirmed live is
> graded with no extra evidence from that confirmation. The live re-check for a
> remediated EV-confirmed finding is the separate
> [`ev-replay`](exploit-verification.md#re-checking-a-fix-ev-replay) command,
> which re-sends the stored exploit against the redeployed target.

## What it does

`vvaharness validate` (alias `vvaharness s11`) runs two phases over the
remediation DTOs under `<repo>/security-remediation/<NN_slug>/finding_case.json`:

1. **discover** *(deterministic, no model spend)* — locate DTOs in a
  validatable state (`state` = `open`, `remediated`, or `failed`; a `declined`
  case is validatable only when its latest attempt's disposition is
  `not_applicable`, never a false positive, a policy denial, or an accepted
  risk). A `pending` case is not validatable.
2. **s11 — panel** — an agentic adversarial panel scores each fix and writes
   the verdict back into the DTO. The default runtime is the DeepAgents backend
   (`via: deepagents`); the `cli` and `sdk` backends run the bundled Claude Agent
   SDK instead.

> **Opt-in in the default profile.** The shipped `default.yaml` sets
> `step_validate.enabled: false`, so a plain scan using that profile skips
> **Step 11**. Set `step_validate.enabled: true` in the effective config to run
> it in-scan; `sdk` and `full` still enable it, while `taint` leaves it off.
> Scan has no `--validate` flag, and `--remediate` enables S10 only. Standalone
> `vvaharness validate` remains available with `enabled: false` and grades
> existing remediation DTOs (below).

## The panel

Three persona subagents (`vvaharness/validation/subagents/`):

| Persona | When | Role |
|---|---|---|
| `security-architect` | always on | Reviews the fix design / root-cause coverage. |
| `penetration-tester` | always on | Adversarial: tries to bypass the fix. (Per-CWE bypass cheatsheets from `./inputs/validator_hints.yaml` are injected into the shared session launch prompt's finding-details block, available to the whole panel — not scoped to this persona.) |
| `cross-repo-analyzer` | conditional | The orchestrator is instructed to spawn it **only when the launch prompt indicates 2+ repositories**; it checks cross-repo consistency and coverage from a multi-repo perspective and returns `skip` for gates outside that scope. |

The panel stages one finding per session in a single workspace, so its launch
prompt never indicates 2+ repositories and the `cross-repo-analyzer` persona
effectively never runs. In practice, consensus rests on the two always-on
personas against a `MIN_CONSENSUS_VOTES` of 2 — a two-persona majority.

All three inherit `models.validate.orchestrator` when unset. Override only their
model IDs with the nested keys `models.validate.security_architect`,
`models.validate.penetration_tester`, and
`models.validate.cross_repo_analyzer`; persona-level `via`/`provider` values are
ignored because the whole panel shares the orchestrator route.

**Permitted backends:** `models.validate` (and any per-persona override) resolves to
`via: cli`, `via: sdk`, or `via: deepagents`. A legacy `via: openai` value is
**routed to `via: deepagents` with the OpenAI provider** when the validate step
starts — before discovery or any model spend.

The backend that serves `via: openai` for detection (S1-S9) and report-only
remediation cannot run the agentic validation panel, so the panel is pointed at
DeepAgents instead of the value being refused. That way one profile spelling behaves
consistently at every stage rather than being accepted by some and fatal at others.
It is equivalent to writing `{via: deepagents, provider: openai}`, which is not the
pair `default.yaml` ships. An explicit `provider:` still wins, so
`{via: openai, provider: anthropic}` runs against Anthropic.

Because the routed role is a DeepAgents role, it needs the DeepAgents OpenAI
credential (`OPENAI_API_KEY`, plus `OPENAI_BASE_URL` for a custom endpoint). Both the
scan's Step-11 preflight and `vvaharness doctor` report the credential for the routed
backend, and `doctor` discloses the routing (`via:openai routed to deepagents`).

### Limitation: one backend and one vendor for the whole panel

The orchestrator and all three personas share a **single** backend and model provider,
both taken from `models.validate.orchestrator`. The per-persona keys honour **`id`
only** — a `via:` or `provider:` written on a persona is ignored.

A persona whose model belongs to the other vendor is therefore **refused when the
validate step starts** (exit code 2), before discovery, staging, or any model spend:

```yaml
# REFUSED — gpt-5.5 cannot run on the Anthropic endpoint the panel uses
validate:
  orchestrator:        {id: claude-opus-4-8, via: deepagents, provider: anthropic}
  security_architect:  {id: gpt-5.5}
  penetration_tester:  {id: gpt-5.5, provider: openai}    # `provider` ignored
  cross_repo_analyzer: {id: gpt-5.5, via: openai}         # `via` ignored
```

```
validate: models.validate.security_architect is 'gpt-5.5', which routes to an
OpenAI-compatible endpoint, but the panel runs on Anthropic (from
models.validate.orchestrator). Every persona shares the orchestrator's provider —
a persona's own via/provider is not honoured. Set security_architect to an
Anthropic model, or change models.validate.orchestrator.
```

The split is Anthropic vs everything else: a `provider:` of `anthropic` (or, with no
provider, a model id containing `claude`) is the Anthropic route, and anything else is
an OpenAI-compatible endpoint.

What is still allowed: different model *ids within one vendor* — e.g. an expensive
orchestrator with cheaper personas (`gpt-5.5` + `gpt-5.5-mini`, or
`claude-opus-4-8` + `claude-sonnet-4-6`). All four shipped profiles are built this way.

Note this interacts with the `via: openai` routing above — an orchestrator spelled
`via: openai` becomes a DeepAgents/OpenAI session, so its personas must be OpenAI
models too.

### Backend synthesis split

The three permitted backends differ in **where gate consensus is computed**,
which matters when you move S11 off the shipped `default.yaml` setting:

| Backend | Who synthesises gate consensus |
|---|---|
| `via: deepagents` *(default)* | **Host code** (`validation/synthesis/_consensus.py`). Persona subagents return schema-validated per-gate reports; the host applies a conservative majority rule deterministically and overwrites the gates file (`validation/session/launcher.py`). The orchestrator prompt instructs the model to stay out of synthesis. |
| `via: cli` / `via: sdk` | **In-session orchestrator** (model-authored). The orchestrator applies the synthesis rules and returns consensus gates in structured output; after a successful session, host code persists them as `synthesized_gates.json` (`validation/session/launcher.py`). |

Both paths then re-score deterministically from `synthesized_gates.json`
(`validation/io/_host_score.py`). If that file is absent or unparseable the
host **fails closed**: the verdict is `INCONCLUSIVE`, which maps to
`open` state (re-validatable). This applies to both backends — a session that
exits before returning persistable consensus gates is always inconclusive.

**Operational implication:** moving S11 off `deepagents` shifts persona
consensus from host code into model-authored JSON. Gate synthesis becomes
subject to model output quality, increasing the probability of inconclusive
outcomes on ambiguous or complex fixes. The `deepagents` default is the
recommended path for production use.

## Scoring → verdict

The panel scores each fix against four weighted gates:

| Gate | Weight |
|---|---|
| `root_cause` | 0.43 |
| `instance_coverage` | 0.2467 |
| `no_new_vulnerabilities` | 0.1867 |
| `security_best_practices` | 0.1366 |

The weighted score maps to a verdict:

| Score | Verdict |
|---|---|
| ≥ 0.80 | **Fixed** |
| ≥ 0.50 | **Partially Fixed** |
| < 0.50 | **Not Fixed** |
| — | **Inconclusive** |

**Critical-gate cap.** Two gates are load-bearing: `no_new_vulnerabilities` and
`root_cause`. Even a score ≥ 0.80 is capped to **Partially Fixed** when either
of those gates is `fail` or `partial` (neither can be out-weighted by the
others).

**Inconclusive is returned (not scored) when** the criteria set is malformed
(a required gate is missing or duplicated), when either critical gate
(`root_cause` or `no_new_vulnerabilities`) is `skip`/invalid, or when persona
consensus on **any** gate — critical or not — is flagged. A gate is flagged
when no status wins a two-persona majority (the panel split, or only one
persona evaluated the gate) or when every persona abstains; on the
`deepagents` default this synthesis is host code, so a split on any single
gate deterministically yields Inconclusive. There is no aggregate
coverage-floor rule. A `skip` is an abstention, excluded from persona
consensus; a gate stays `skip` only when every persona abstains — and an
all-abstain gate is itself flagged. Exclusion of a `skip` gate from the score
numerator/denominator therefore applies only when its consensus is not
flagged (in practice, the `cli`/`sdk` path, where the confidence marker is
model-authored).

The verdict is written into the most recent attempt's `verdict` key, and the
case `state` is derived from it:

- `validated` — the fix was judged fixed
- `failed` — the fix was judged partially fixed or not fixed (re-validatable)
- `open` — the session produced an inconclusive verdict (re-validatable)

## Running it standalone

```bash
# vvaharness requires Python >= 3.11 — no extra install needed
vvaharness validate --repo /path/to/target
```

| Flag | Effect |
|---|---|
| `--repo <path>` | Target repo whose `security-remediation/` DTOs are validated. **Required.** |
| `--config <file>` | Config profile path; else `./config.yaml` if present, else the packaged `default.yaml`. |
| `--finding <id>` | Validate this finding id (repeatable); these exact ids only, no cap. |
| `--all` | Validate every validatable finding (`open` / `remediated` / `failed`, plus `declined` with a `not_applicable` disposition); bypasses the `max_findings` cap. |
| `--max-findings <n>` | Cap to the top-N validatable findings by CVSS (overrides `step_validate.max_findings`). |
| `--workspace <path>` | Staging root for per-finding copies. **Ephemeral** — removed on completion; a non-empty path is refused. Default `<repo>/security-remediation/validation`. |
| `--resume` | Reuse a matching cached validation checkpoint for each selected validatable finding. Terminal `validated` cases are excluded by state with or without this flag. |
| `--scan-report <file>` | Combined report (`.md`) to enrich with validation results; defaults to the newest report under `<repo>/security-remediation/`. |

Re-runs **re-validate by default**: terminal `validated` DTOs are excluded;
`open`, `remediated`, and `failed` states remain validatable, as does `declined`
with a `not_applicable` disposition. `--resume` may reuse a matching validation
checkpoint for selected validatable DTOs.

### Exit codes

Standalone `validate` writes no `run_manifest_*.json`, so its exit code is the
only machine-readable outcome the invocation leaves behind — which is why the
code matters more here than on the scan path, where the manifest records the
same value as `exit_code`. The command follows the harness-wide contract
published in [outputs.md → Exit codes](outputs.md#exit-codes). The value to
know before scripting it is `3` — the run itself completed, but nothing it
remediated validated as fixed. That is a verdict, not a malfunction: distinct
from `1` (the pipeline broke) and from `2` (the invocation was refused before
the work it guards).

`3` is decided from the verdicts of the cases this run validated, not from the
case files on disk, so a case an earlier run left behind cannot make a healthy
run report a shortfall. The condition is narrow on purpose: nothing validated
**and** at least one case failed. A run of only inconclusive cases exits `0` —
it neither validated nor failed, and the answer to it is re-validation, not a
red build. Any single validated fix clears the gate; per-case detail is in the
manifest's `remediation` rollup for anyone who wants a stricter rule.

A session or agent failure still outranks the verdicts and reports `1`: a run
that broke is never reported as a run that merely failed to fix anything.

## Configuration (`step_validate:`)

| Key | Default | Effect |
|---|---|---|
| `enabled` | `false` in default/taint and in the built-in fallback; `true` in sdk/full | Run the validator as in-scan Step 11. `--remediate` does not enable it. Does not gate standalone `validate`. |
| `effort` | `high` | Reasoning effort for each panel session. Threaded to the model on the DeepAgents `provider: openai` branch (mapped to `reasoning_effort`, with a runtime fallback if the endpoint rejects it); ignored only on the DeepAgents Anthropic branch. |
| `max_turns` | `50` | Per-finding panel-session turn cap; DeepAgents maps it to a recursion limit. |
| `max_budget_usd` | `15.0` | Per-finding panel-session cap enforced by the Claude Agent SDK Harness; DeepAgents ignores it. |
| `max_findings` | `20` | Top-N validatable by CVSS; applies to both standalone `vvaharness validate` and in-scan Step 11. `--all` (standalone only) bypasses, `--finding` ignores. |
| `allowed_tools` | `[Read, Grep, Glob]` | Read-only repository tools. Persona dispatch is provided by the session; agents receive no Write/Edit/Bash capability. DeepAgents additionally exposes deterministic read-only diff/test inventory helpers. |

(The Claude binary is selected by the `VVAHARNESS_CLAUDE_BINARY` env var, not a
config field.)

## Trust model & outputs

The panel reads the repo but is **read-only on every backend**. Agents return
structured output and never receive Write/Edit/Bash. Host code persists the
temporary artifacts, recomputes the score, updates the DTO, and removes the
workspace. It never applies a patch, mutates source, or runs target code. Per
DTO the host produces:

- the `verdict` merged into the most recent attempt in
  `finding_case.json`; the case `state` is derived from that verdict
- temporary `validation_report.json` — the panel's per-DTO findings
- temporary `synthesized_gates.json` — qualitative consensus gate outcomes;
  host code applies the configured weights to compute the score and verdict

The two JSON artifacts above live only in the staging workspace and are folded
into the DTO before that workspace is deleted. A redacted session transcript
may be persisted beside the DTO for audit.

Two host-side controls bound what an agent's structured output can put into the
DTO. An out-of-range `raw_score` is **clamped** into `[0.0, 1.0]` (and the clamp
logged) rather than rejected — rejecting the field would drop the finding from
the report entirely. The agent-supplied file lists (`affected_files`,
`files_needing_fixes`) are **redacted first, then length-capped**; doing it in
that order avoids bisecting a secret at the truncation boundary and leaving an
unredactable fragment behind.

See [security.md](security.md) for the full validation trust model.
