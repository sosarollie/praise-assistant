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

# vvaharness — User Guide

Agentic vulnerability discovery, remediation, and validation. It surveys a code
repo, threat-models it, decomposes it into analysis chunks, deep-dives each,
adversarially verifies findings, deduplicates, analyses exploit chains, and
emits a Markdown report + SARIF 2.1.0. It then proposes fixes and grades them:
the `remediate` command applies fixes by default (`--mode report-only` proposes
instead), and the `validate` command scores them with an agentic adversarial
panel that never modifies the repo.

> **Read this first:** findings are **LLM-generated triage candidates, not
> confirmed vulnerabilities.** Human review is required. Runs are
> non-deterministic — two scans of the same repo may differ. See *Limitations*.

For full installation and credential/config setup, see
**[SETUP_GUIDE.md](SETUP_GUIDE.md)**.

---

## Install

Requires Python ≥ 3.11.

```bash
pipx install .        # global `vvaharness` command in its own env
vvaharness setup      # check Python, agents, keys, gateway, config
```

That is the whole happy path. A virtualenv is **not** required — `pipx` already
isolates dependencies, and plain `pip install .` works too.

**[SETUP_GUIDE.md](SETUP_GUIDE.md) is the install reference**: per-OS venv and
Windows commands, editable/development installs, credentials and `.env`, TLS and
proxy certificates, and choosing a config profile. This guide assumes you are
already installed and covers *using* the tool.

---

## 1. Commands

`vvaharness` exposes these subcommands (a bare invocation prints help):

| Command | Purpose |
|---|---|
| `vvaharness scan …` | Run the full pipeline against one repo or a batch. |
| `vvaharness remediate --repo <path>` | Walk a prior scan's findings and, in the default `fix` mode, apply a minimal fix per finding; `--mode report-only` only proposes. Writes DTOs under `<repo>/security-remediation/`. See [§2b](#2b-remediate--apply-or-propose-fixes). |
| `vvaharness validate --repo <path>` | Run S11: deterministically discover validatable remediation DTOs, then verify them with an agentic adversarial panel through the configured Harness backend. CLI/SDK routes use Claude Agent SDK; the default uses DeepAgents/Anthropic. (Alias: `s11`.) |
| `vvaharness ev-replay --repo <path>` | Re-send the confirming payloads a prior exploit-verified scan stored for this repo and report each finding as `REMEDIATED`, `STILL VULNERABLE`, or `NOT PROVEN FIXED` against a **redeployed** target. Needs `EV_TARGET_URL` (and the same `EV_*` env a scan uses); reads no scan artefacts and edits no source. Writes a timestamped `*_ev-replay.md` plus a `.json` sidecar under `<repo>/security-scan/`. Accepts `--config <file>`; there is no `--help`. Exit codes: `0` nothing still vulnerable, `2` setup failure, and `1` both for a completed run that found a finding still vulnerable and for a run that aborted on a configuration or `EV_AUTH_*` error — an abort prints a traceback, which is how the two exit-`1` outcomes are told apart. See [exploit-verification.md](exploit-verification.md). |
| `vvaharness setup [--install-agents] [--write-env]` | Readiness wizard; `--install-agents` writes AGENTS.md and .github/copilot-instructions.md unconditionally, plus CLAUDE.md + a Claude skill when the `claude` CLI is detected and GEMINI.md when `gemini` is detected, never overwriting an existing file; `--write-env` scaffolds `.env`. (Alias: `init`.) |
| `vvaharness doctor [--config <file>]` | Report credential/backend readiness and live-probe detection transports. The probe spends model tokens; for S10/S11 Agent-SDK routes it does not exercise the actual Harness launcher. Neither `doctor` nor `setup` runs an exploit-verification readiness check — use `vvaharness scan --stop-after ev` to verify the EV collection and target reachability before an armed run. |
| `vvaharness doctor --cache-probe` | Report, per model route, what happens to prompt caching as far as that route's usage accounting can show. Prints a cost estimate first, then a verdict per route. Opt-in and never run during a scan. `vvaharness setup` points you here when it detects a gateway whose host it cannot classify — see [configuration.md](configuration.md#prompt-caching-cache_markers--cache_route--cache_min_block_tokens) for the verdicts and what each one can and cannot establish. |
| `vvaharness estimate --repo <path>` | Print a rough scope/cost preview (file count, bytes, ~input tokens). Spends nothing. |
| `vvaharness gc [--keep-runs N] [--max-age-days N] [--run <path>] [--dry-run]` | Prune old checkpoint runs from the SQLite state DB (defaults: keep 100 runs / 5 days). `--run <path>` instead fully evicts the single run for that repo path (its `run_id` is path-derived). |

The first trusted `.env` found at exactly the current directory or user home is
loaded automatically; arbitrary ancestor directories are not searched.
Variables you export yourself take precedence, so no manual `source` step is
required. On POSIX, the file and its parent must be user-owned and not
group/world-writable. The file actually loaded is printed as a `[env] loaded …`
line.

Two flags are **global** and may precede any subcommand: `--log-level <level>`
attaches a redacting log handler (`debug`/`info`/`warning`/`error`/`critical`)
and `--log-file <path>` sends that log to a file instead of stderr. Both are
also settable through `VVAHARNESS_LOG_LEVEL` / `VVAHARNESS_LOG_FILE`.

---

## 2. `scan` — flags

| Flag | Effect |
|---|---|
| `--repo <path>` | Scan a single local checkout. **Mutually exclusive** with `--repo-file`; one of the two is required. |
| `--repo-file <file>` | Batch mode. A `.csv` with header `AppId,RepoName[,Path]` (see [repos-csv.md](repos-csv.md)) or a `.txt` with one `application_id,repository_name,path` per line. Each entry is cloned/scanned in sequence with a fresh context. |
| `--config <file>` | Use a specific config YAML. Default: `./config.yaml` if present, else the packaged `default.yaml` profile. |
| `--repo-name <slug>` | Module / `repositoryName` tag for report filenames and SARIF `run.properties` (single-repo mode; defaults to the directory name). |
| `--application-id <id>` | Application / asset identifier — drives CMDB AppProfile lookup, VulContextSeverity environmental scoring, and SARIF `run.properties.applicationId`. |
| `--workspace <dir>` | Where remote repos are cloned in batch mode. Default `./batch-workspace`. |
| `--group-by-app` | Batch mode: clone every repo sharing an AppId under `<workspace>/<AppId>/` and run **one** scan over that directory (one report per application instead of one per repo). |
| `--keep-clones` | Don't delete cloned repos after scanning (batch mode). |
| `--resume` | Reuse on-disk checkpoints (SQLite state DB at `$VVAHARNESS_STATE_DIR/vvaharness.db`, default `~/.vvaharness/state/…`) instead of re-running completed stages. **Assumes the source is unchanged since the checkpointed run** — vvaharness does not detect code edits here. If the target changed, omit `--resume` (a fresh scan is clean) or run `vvaharness gc --run <path>` first to evict stale state. Checkpoints are per stage, not per chunk — a scan interrupted mid-S4 re-runs S4 in full on resume (see [§3](#3-pipeline-stages)). |
| `--stop-after <step>` | Stop after `clone`/`ev`/`s0`/`s1`/…/`s11` (debugging). `clone` stops right after acquiring repos in batch mode and implies `--keep-clones`. `ev` checks exploit verification's setup only — it parses the collection named by `EV_API_COLLECTION` and probes the target's reachability, then stops **before S0** — no call graph and no model spend. `s0` stops after the static seed / callgraph stage. |
| `--remediate` | Run the Remediation Agent (s10) in fix mode after detection; successful sessions can edit target source and write DTOs under `<repo>/security-remediation/`. ORs with `step_remediate.enabled` (`false` in default/taint; `true` in sdk/full). Enables S10 only, not S11; `--stop-after s9` skips both. See [§2b](#2b-remediate--apply-or-propose-fixes). |
| `--top <N\|all\|*>` | With remediation: select only the N highest-CVSS findings (overrides `step_remediate.top_n_findings`; `all`/`*` selects every finding). |
| `--force` | Override safety refusals (currently the s10 git-SHA staleness check that guards remediating against a moved checkout). |
| `--skip-preflight` | Skip the startup credential/backend readiness probe. Does **not** bypass model/API authentication. |
| `--step1-config <file>` | Apply an explicit Step-1 overlay YAML (exclude_dirs/exts/globs, max_file_kb, config_dedup). Lists **append** to the config's `step1`. Overrides `--auto-step1` when both are given: the auto-derivation is skipped with a notice (no error). |
| `--auto-step1` | After clone, AI-survey each target to derive its Step-1 overlay; writes `$VVAHARNESS_STATE_DIR/checkpoints/<run_id>/step1.yaml` and applies it before s1. Ignored when `--step1-config` is given. Reused on `--resume`. **Also enabled via `step1.auto_exclude` in config** (flag and config OR together, like `--remediate`/`step_remediate.enabled`). All four shipped profiles set it to `true`, so it runs by default; pass `--no-auto-step1` to opt out. |
| `--no-auto-step1` | Hard-disable AI auto-exclude for this run, **irrespective of `step1.auto_exclude` in whichever profile is active**. Wins over `--auto-step1` and any config default (mutually exclusive with `--auto-step1`). Use this to say "no" from the command line without editing a profile. |
| `--s6-progress-file` | Write `$VVAHARNESS_STATE_DIR/s6_progress/<run_id>/s6_progress.json` after each S6 verification. The file contains total, completed, remaining, status, outcome counts, and an update timestamp. When exploit verification is armed, the counter is written to `s6_progress/current/s6_progress.json` instead of the `<run_id>` path, its `total` and `remaining` count only the findings handled by the static verifier (not S6's whole finding set), and concurrent scans of different repositories overwrite each other on that shared `current/` path — run one scan at a time when you rely on this file, and read `run_manifest_*.json` for the whole-scan finding count. |

### Examples

> **The packaged default skips S10/S11.** Both stages have `enabled: false`.
> Other configs or a local overlay can enable them; `sdk` and `full` still do.
> **Source-edit warning:** enabled S10 runs in fix mode and can edit target
> source when findings, credentials, and a successful remediation session are
> available. Use `--stop-after s9` to explicitly skip S10/S11 with any profile.

```bash
# Preview scope/cost (spends nothing)
vvaharness estimate --repo /path/to/target

# Detection-only scan of a local checkout
vvaharness scan --repo /path/to/target --application-id 12345 --stop-after s9

# Batch — clone + scan many repos, one report per AppId
vvaharness scan --repo-file repos.csv --workspace ./scans --group-by-app --keep-clones
```

---

## 2a. `validate` — verify remediations

`vvaharness validate` scores remediations produced by the `remediate` command.
With the shipped `default` profile, **in-scan Step 11 is disabled**
(`step_validate.enabled: false`); the standalone command remains available.
Set `step_validate.enabled: true` in the effective config to enable in-scan S11.
There is no scan `--validate` flag, and `--remediate` does not enable S11.
Its deterministic S11
discovery phase locates each finding's DTO under
`<repo>/security-remediation/<NN_slug>/finding_case.json` (no model spend),
then the S11 agentic adversarial panel fills the
most recent attempt's `validation` block. The case `state` is derived from the
verdict: `validated` is terminal, while `open`, `remediated`, and `failed`
remain validatable. Re-runs are idempotent, so a corrected patch is re-driven
on the next run with no manual DTO edit.

```bash
# vvaharness requires Python >=3.11 — no extra install needed
vvaharness validate --repo /path/to/target
```

| Flag | Effect |
|---|---|
| `--repo <path>` | Target repo whose `security-remediation/` DTOs are validated. **Required.** |
| `--config <file>` | Config profile path; else `./config.yaml` if present, else the packaged `default.yaml`. |
| `--finding <id>` | Validate this finding id (repeatable); these exact ids only, no cap. |
| `--all` | Validate every finding in a validatable state (`open`, `remediated`, or `failed`), bypassing the `max_findings` cap. Terminal `validated` cases remain excluded. |
| `--max-findings <n>` | Cap to the top-N validatable findings by CVSS (`open`, `remediated`, or `failed`; overrides `step_validate.max_findings`). |
| `--workspace <path>` | Staging root for per-finding copies. **Ephemeral** — removed on completion; a non-empty path is refused. Default `<repo>/security-remediation/validation`. |
| `--resume` | Reuse a matching cached validation checkpoint for each selected validatable finding. Terminal `validated` DTOs are excluded by status whether or not this flag is present. |
| `--scan-report <file>` | Combined report (`.md`) to enrich with validation results; defaults to the newest report under `<repo>/security-remediation/`. |

The panel uses `security-architect`, `penetration-tester`, and
`cross-repo-analyzer` personas, and scores each fix against weighted gates →
a Fixed / Partially Fixed / Not Fixed / Inconclusive verdict. It supports
`via: cli`, `via: sdk`, and `via: deepagents`; legacy `via: openai` is normalized
to DeepAgents with the OpenAI provider. Every validation route is read-only
against the repository, applies no patch, and runs no Docker.

**See [validation.md](validation.md)** for the full reference — gate weights,
verdict bands, per-persona model overrides, `step_validate` knobs, and the
trust model.

---

## 2b. `remediate` — apply or propose fixes

`vvaharness remediate` reads a prior scan's findings from
`<repo>/security-scan/` and walks them with the Remediation Agent (step 10),
running the configured `models.remediate` role per finding. For each finding it
writes a DTO under `<repo>/security-remediation/<NN_slug>/finding_case.json`
(consumed later by `validate`). In-scan remediation is **off in the default
profile** (`step_remediate.enabled: false`). Pass `--remediate` or set
`step_remediate.enabled: true` to enable S10; neither enables S11.
The standalone command remains available with `enabled: false`.

```bash
# Standalone: remediate the findings of a completed scan
vvaharness remediate --repo /path/to/target

# Only the 10 highest-CVSS findings, interactive picker, report-only (no edits)
vvaharness remediate --repo /path/to/target --top 10 -i --mode report-only
```

| Flag | Effect |
|---|---|
| `--repo <path>` | Target repo whose `security-scan/` findings are remediated. **Required.** |
| `--config <file>` | Config profile path; else `./config.yaml`, else packaged `default.yaml`. |
| `--mode fix\|report-only` | `fix` (default) applies minimal diffs through `via: cli`, `via: sdk`, or the repo-confined `via: deepagents` filesystem backend. Legacy direct `via: openai` has no edit tools and is report-only. `report-only` proposes without touching files. |
| `--top <N\|all\|*>` | Remediate only the N highest-CVSS findings (overrides `step_remediate.top_n_findings`; `all`/`*` does every finding). |
| `-i`, `--interactive` | Pick which findings to remediate from a menu. |
| `--resume` | Skip findings already remediated in a prior run. |
| `-v`, `--verbose` | Print the prompt + raw LLM response per finding. |

The fix-mode tool set is `Read/Glob/Grep/Edit/Write` (cwd-confined) — **Bash is
denied** so a prompt-injected agent can't reach a host shell.

**See [remediation.md](remediation.md)** for the full reference — modes, the
`step_remediate` knobs, the policy gate, and the kill-switch.

---

## 3. Pipeline stages

S0 is a configurable static seed stage controlled by `step0.enabled`. The
shipped `default.yaml`, `full.yaml` and `taint.yaml` profiles enable it (`llm`
mode in the first two, `rules` mode in `taint.yaml`); `sdk.yaml` omits `step0:`
entirely and inherits the disabled built-in default.

| Step | Role | Output |
|---|---|---|
| s0 static seed *(profile-controlled)* | — in rules mode; `graph_annotate` in LLM mode | source/sink callgraph seed when usable specs exist; otherwise empty |
| s1 preprocess | `preprocess` (+ `autoexclude` for `--auto-step1`) | repo survey → `ContextPackage` |
| s2 threatmodel | `threatmodel` | assets, trust boundaries, ranked threats |
| s3 decompose | `decompose` | analysis chunks → `TaskManifest` |
| s4 deepdive | `deepdive` | per-chunk findings (×N runs + majority vote when enabled) |
| s5 prefilter | — (deterministic gates; optional semantic pre-dedup via `dedup`) | drops low-confidence / unproven findings; the shipped `default.yaml` runs one semantic pre-dedup model call before s6 whenever the survivor count reaches `step5_prefilter.pre_verify_threshold` — which ships at `0`, so the call always runs (a run left with fewer than two findings simply has nothing to merge) |
| s6 verify | `verify` | adversarial TRUE/FALSE_POSITIVE verdict + CVSS per finding; optional live exploit verification runs alongside it (**Beta — API only**, off unless `EV_API_COLLECTION` is set). In the default configuration it only adds an `Exploit Verification` stamp and the static verifier keeps the verdict and the ranking CVSS; the legacy `ev_overrides_static` path lets a live confirmation replace the static verdict and skip the static verifier, but no shipped profile sets it |
| s7 dedup | `dedup` | deterministic + semantic dedup → canonical findings |
| s8 chain | `chain` | exploit-chain analysis + re-ranking → `FinalReport` |
| s9 SARIF | — (deterministic) | parses the Markdown report → SARIF 2.1.0 |
| s10 remediate *(off in default/taint; on in sdk/full)* | `remediate` | candidate fix, source edits in fix mode, remediation DTO |
| s11 validate *(off in default/taint; on in sdk/full)* | `validate.orchestrator` + personas | read-only adversarial verdict written into the DTO |

### Taint evidence

When enabled S0 has usable external or LLM-derived specs, it can build
structured **taint evidence**—typed transfer edges that trace how tainted data
moves through source code. S1 still builds its own repository context and call
graph when S0 returns empty, but does not synthesize these S0 typed-transfer
records. S0 evidence rides on the scan context rather than on individual
findings: S3 uses it to shape analysis chunks, S4's taint-path chunk prompts
embed the matching typed-transfer path, and the deterministic s5 pre-filter
can backfill a missing source/sink ref from S0 seed paths. S6 verification
sees each finding's `source_ref`/`sink_ref` plus call-graph context, not the
S0 dataflow paths themselves. Base edge kinds
include `source`, `assign`, `arg_to_param`, `return_to_local`, `local_to_sink`,
`return_to_sink`, `field_write`, `field_read`, `container_put`, `container_get`,
`sanitize`, `reflect`, and `framework`. `condition` remains reserved in the
schema; the current scanner does not emit condition transfers or a branch CFG.

During such an S0 scan, framework sources are detected from annotations and
naming conventions already present in your source code—no vvaharness-specific
instrumentation is required:
- **Spring**: `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader` on method parameters; `@GetMapping`/`@PostMapping` path variables; `ServletRequest`/`HttpServletRequest` parameter types
- **Django**: `request.GET`/`POST`/`META`/`FILES` accesses; view functions with a `request` parameter following Django naming conventions; `HttpResponse`/`JsonResponse` output sinks
- **ASP.NET**: `[FromQuery]`, `[FromRoute]`, `[FromBody]`, `[FromHeader]` on controller parameters; `[HttpGet]`/`[HttpPost]` route template variables; `Ok()`/`BadRequest()`/`Json()` response sinks

Response output sinks are identified as potential XSS risk (languages: **Python, Java, C#**). Paths where an explicit sanitizer neutralizes the flow are suppressed from findings — not surfaced as false positives; sanitizer matching is language-agnostic.

**Reflection APIs detected** (emits `reflect` edges with confidence scores):
- **Java:** `getMethod`, `getDeclaredMethod`, `getDeclaredField`, `getField`, `getDeclaredConstructor`, `getConstructor`, `forName`, `invoke`, `newInstance`, `MethodHandles.lookup()`
- **Python:** `getattr`, `setattr`, `__import__`, `importlib.import_module`, `vars`, `type`, `eval`, `exec`, `compile`
- **C#:** `GetMethod`, `GetMethods`, `GetConstructor`, `GetConstructors`, `GetType`, `Invoke`, `CreateDelegate`, `Activator.CreateInstance`, `Assembly.Load`, `Assembly.LoadFrom`, `Assembly.LoadFile`, `Type.InvokeMember`

Each step checkpoints to the SQLite state DB at
`$VVAHARNESS_STATE_DIR/vvaharness.db` (default `~/.vvaharness/state/…`;
`run_id` is derived from the absolute target path); `--resume` skips
completed steps. A scan **without** `--resume` clears that run's prior
checkpoints first, so a fresh scan never inherits stale state. `--resume`
**trusts that the source is unchanged** since the checkpointed run — it does
**not** detect code edits, so resume only after a clean/aborted run on the same
code; if the code changed, omit `--resume` or run `vvaharness gc --run <path>`
to evict the run. Run `vvaharness gc` to prune old runs.

Checkpoint granularity is **per stage, not per chunk**. S4 deep-dive runs
every chunk and saves one checkpoint only after all of them finish, so a scan
interrupted mid-S4 resumes S0–S3 from checkpoints but re-runs S4 **in full**,
however many of its chunks had already completed. S5 and S6 then run fresh
too — their checkpoints are only ever reusable when the S4 (and S5) checkpoint
they depend on was restored. Coverage is unaffected — the re-run reviews the
same code — but budget the repeated time and tokens: prompt caching does not
soften the cost, because cache entries are short-lived (5 minutes on Anthropic
routes; provider-defined where an OpenAI-compatible endpoint's implicit cache
applies) and a resume usually comes later than that. (S2
also re-runs on resume when its threat model came back empty — an empty model
is deliberately not checkpointed.) See
[architecture.md](architecture.md) for the data flow and
[models.md](models.md) for how roles map to backends.

---

## 4. Backends

Each model role picks its own `{id, via}` (plus `provider` on a
`via: deepagents` role) in `config.yaml: models`:

| `via:` | Transport | Auth | Tools |
|---|---|---|---|
| `cli` *(opt-in per role)* | `claude` CLI subprocess | run `claude` then `/login` (or `CLAUDE_CODE_OAUTH_TOKEN` via `claude setup-token`) | Read/Glob/Grep (the only backend that *can* also run **Bash** — but no shipped profile grants it; add `- Bash` to a role's `allowed_tools` to enable) |
| `sdk` | Anthropic Python SDK | `ANTHROPIC_SDK_API_KEY` | Read/Glob/Grep (sandboxed) — honours `temperature`, `max_turns` |
| `openai` | OpenAI-compatible API | `OPENAI_API_KEY` | Read/Glob/Grep (sandboxed) |
| `deepagents` | DeepAgents/LangGraph harness: agent graph on S10/S11; a one-shot completion on the single-shot detection roles (`autoexclude`, `graph_annotate`, `threatmodel`, `decompose`, `deepdive`, `dedup`, `chain`); a read-only agentic loop on `preprocess` and `verify` (and S2 with `step2.agentic: true`) | Anthropic: `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`; OpenAI: `OPENAI_API_KEY` | repo-confined writes in S10 fix mode, read-only in S11; the single-shot detection roles offer the model **no tools at all** (no filesystem, no shell, no sub-agent dispatch); agentic detection roles get read-only Read/Glob/Grep; Bash denied everywhere |

The `cli`/`sdk` rows describe the detection dispatcher. In S11, both selectors
use the read-only Claude Agent SDK Harness. In S10, `via: cli` remains the
direct CLI route, while `via: sdk` fix mode delegates Edit/Write to the Claude
Agent SDK.

### Shipped profiles & how to switch (modes)

Four ready profiles live in `vvaharness/config/profiles/`. Run
`vvaharness setup`—its recommendation is a starting point based on detected
credentials, not a guarantee that every post-scan role is ready. Re-run setup
with the selected profile and resolve its warnings. Select a profile per run
with `--config`; with no flag, a `./config.yaml`
in the working dir wins, else the packaged `default.yaml`.

| Profile | Backend(s) | Use when… | Run |
|---|---|---|---|
| `default.yaml` | local S0 (LLM mode); S1–S11 all `via: deepagents` (Anthropic; detection on `claude-opus-4-7`, `preprocess` on `claude-sonnet-4-6`, S10 remediate on `claude-opus-4-8`, S11 validate on `claude-opus-5` with `claude-opus-4-8` personas) | you have any one of `ANTHROPIC_SDK_API_KEY`, `ANTHROPIC_API_KEY`, or `ANTHROPIC_AUTH_TOKEN` — one credential covers every stage. The built-in default. | *(no flag)* |
| `sdk.yaml` | every role spelled `via: sdk`: Anthropic Python SDK for detection; Claude Agent SDK paths for S10 fix/S11; no Bash. Ships `step4.runs: 1`, so majority voting is **off** (use `full.yaml` for voting) | you want every role on one SDK credential with no Bash. `ANTHROPIC_SDK_API_KEY` covers S1–S10; S11 pins external `claude` and uses Claude login/OAuth or standard Anthropic auth. One standard credential can cover all stages via the sole-SDK fallback. | `--config vvaharness/config/profiles/sdk.yaml` |
| `full.yaml` | as shipped, all roles `via: deepagents` (Anthropic), with commented `cli`/`sdk`/`openai` alternatives to copy and edit. The only shipped profile with s4 voting on (`runs: 3`/`vote_threshold: 2`) | you want majority voting, or a multi-backend template. As shipped one Anthropic credential covers a detection-only run. One Anthropic credential covers an EV-armed `default` or `taint` run; `full.yaml` additionally needs `OPENAI_API_KEY`, for its `judge` alone. Uncommenting a `via: cli` role adds a Claude-auth requirement, a `via: openai` role adds `OPENAI_API_KEY` | `--config vvaharness/config/profiles/full.yaml` |
| `taint.yaml` | S0 (rules mode) + S1–S9 all `via: deepagents` (Anthropic); S10/S11 disabled | you want taint-first source→sink scanning. One Anthropic credential covers it — no `claude` binary needed. Shipped rules mode needs operator-supplied generated rule files for an S0 seed. | `--config vvaharness/config/profiles/taint.yaml` |

> **S0 rules note:** rules mode has no implicit source/sink baseline. It needs
> usable external source/sink rule files, such as files generated by
> `build_kb.py`, to produce a seed. No such generated files are shipped; without
> them S0 returns an empty seed and S1 continues. See
> [SETUP_GUIDE.md → Generated source/sink rule files](SETUP_GUIDE.md#generated-sourcesink-rule-files-taint-profile)
> for copy-paste build commands and
> [vvaharness/rules/README.md](../vvaharness/rules/README.md)
> for corpus/artifact workflow details.

To pin your own choice, copy a profile to `./config.yaml` and edit it:
```bash
cp vvaharness/config/profiles/sdk.yaml ./config.yaml   # then `vvaharness scan` uses it automatically
```

For the full walkthrough — config resolution order, `config.local.yaml`
overrides, secrets in `.env`, and every tunable knob — see
[configuration.md → Setting up your config](configuration.md#setting-up-your-config).

### Setting / changing the models

Edit the `models:` block of your config. Detection roles and `remediate` use a
flat `{id, via, provider}` node — `provider: anthropic | openai` picks the
vendor on a `via: deepagents` role; when absent it is inferred from whether the
model id contains "claude". Validation is nested under `models.validate`, with an
`orchestrator` node and optional persona model overrides. **Note:** detection
roles run on `via: cli`, `via: sdk`, `via: openai`, or `via: deepagents`. On
the deepagents route the single-shot roles (`autoexclude`, `graph_annotate`,
`threatmodel`, `decompose`, `deepdive`, `dedup`, `chain`) run one completion
offering the model no
tools, while `preprocess` and `verify` run a read-only agentic loop. Validation
runs on `via: cli`, `via: sdk`, or `via: deepagents`; a
legacy `via: openai` validate role is routed to `via: deepagents` with the OpenAI
provider, so it runs and needs `OPENAI_API_KEY`. Remediation fix mode supports
`via: cli`, `via: sdk`, and repo-confined `via: deepagents`; legacy direct
`via: openai` is limited to `--mode report-only`.
```yaml
models:
  deepdive:   {id: claude-opus-4-8,  via: sdk}     # SDK on a public Opus
  verify:     {id: claude-sonnet-4-6, via: cli}    # ← flip one role to the CLI
  threatmodel: {id: gpt-4o,          via: openai}  # ← or to OpenAI
  # …autoexclude, preprocess, decompose, dedup, chain…
  validate:
    orchestrator: {id: gpt-5.5, via: deepagents, provider: openai}
```
- `id` is whatever your endpoint accepts (a public id, a dated id, or a CLI
  alias like `sonnet`/`opus`).
- After editing, run `vvaharness doctor --config <file>`. It probes the unique
  detection transports, but currently substitutes a raw-SDK probe for
  SDK-spelled S10/S11 and can false-green S11; verify external `claude` and
  either Claude login/OAuth or standard Anthropic auth separately.

### Internal gateway (if your key is a Claude-Code/JWT token)
Set the endpoint in your shell or `.env` (NOT in source). `setup` auto-detects
and prints these lines when the active profile reaches an Anthropic endpoint
through the `sdk:` block — `sdk.yaml` (all roles `via: sdk`) and also
`default.yaml` / `full.yaml` / `taint.yaml`, whose Anthropic-routed
`via: deepagents` roles read the same block. Set these variables explicitly when
your gateway token requires them:
```bash
export ANTHROPIC_BASE_URL=https://<your-gateway>/
export SSL_CERT_FILE=$HOME/cacerts.pem         # only if a private CA
export CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1 # if the gateway rejects beta flags (HTTP 400)
```
One scope caveat on that CA line: `SSL_CERT_FILE` (or the profile's `ca_cert` —
`ANTHROPIC_SDK_CA_CERT` in the shipped profiles) is what the Python Anthropic
clients (`via: sdk` detection, Anthropic-routed `via: deepagents`) read.
`NODE_EXTRA_CA_CERTS` covers only the **Node-based** paths (the `claude`
subprocess of `via: cli` roles and the Agent-SDK S11 launcher) and OpenAI-routed
DeepAgents roles — set it *in addition* if your profile uses those routes
(details in [SETUP_GUIDE.md](SETUP_GUIDE.md)'s TLS notes).

**TLS / private gateways.** CLI, SDK, and direct OpenAI adapters carry an
optional `verify_ssl` / `ca_cert` block in the profile—including a `cli:` block whose CA bundle
(`${CLAUDE_CLI_CA_CERT}`) is propagated into the direct adapter's `claude`
subprocess. A `via: deepagents` **detection** role reads `verify_ssl`,
`ca_cert`, and `client_cert` from the `sdk:` (Anthropic) or `openai:`
(OpenAI-compatible) block matching its resolved vendor — never the `cli:`
block; the default S10/S11 read `SSL_CERT_FILE` /
`VVAHARNESS_TLS_CLIENT_CERT` from the process environment instead. Use absolute
certificate paths for clarity; a relative value in a profile's
`sdk:`/`openai:`/`cli:` block resolves against the **selected config's
directory** (not `.env`'s location or the process working directory), and
network/UNC paths are refused. That refusal covers certificate paths set in
those config blocks; CA paths supplied through the ambient environment
(`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`) are used as given. Every TLS
setting is **optional**: with only an API key set, the public official endpoint
is used and **no certificate is required**. A CA bundle is needed only behind a
private gateway or a TLS-intercepting proxy whose cert chains to an internal CA.
Mutual TLS (mTLS client certs) is supported on the direct Anthropic SDK
detection transport and on every `via: deepagents` role — including the
default S10/S11 (via `VVAHARNESS_TLS_CLIENT_CERT`). `via: cli` and `via: openai` still cannot do mTLS (Node
exposes no env path for a client cert). See
**[SETUP_GUIDE.md](SETUP_GUIDE.md)** for the full
when-is-a-cert-needed matrix and env-var names.

**Pinning the `claude` executable (shared/CI hosts).** Direct `via: cli` roles
and S11 validation configured as either `via: cli` or `via: sdk` launch the
external `claude` CLI;
by default it is resolved to an
absolute path via `PATH`. On a shared or CI host where `PATH` may include a
directory another user can write, set **`VVAHARNESS_CLAUDE_BINARY=/abs/path/to/claude`**
to pin the exact executable and bypass `PATH` resolution entirely (prevents a
planted `claude` from running under the harness with your credentials).

### Environment variables

Backend **credentials and endpoints** (`ANTHROPIC_SDK_API_KEY`,
`ANTHROPIC_SDK_BASE_URL`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`,
`OPENAI_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`,
`ANTHROPIC_BASE_URL`, and the route-scoped CA variables `SSL_CERT_FILE` /
`NODE_EXTRA_CA_CERTS`, …) go in `.env` — see
[`configuration.md`](configuration.md) and [`SETUP_GUIDE.md`](SETUP_GUIDE.md).
Exploit verification (Beta — API only, localhost-only, off by default) is
switched on by `EV_API_COLLECTION` and additionally requires `EV_TARGET_URL`;
both, plus every `EV_AUTH_*` credential, come from `.env` only — there is no CLI
flag. **Exploit verification is single-repo only** — it runs under `--repo` and
nowhere else. Under `--repo-file` (batch mode) it is disabled, the only notice
is a `WARN` on stderr, and no finding is live-verified even with
`EV_API_COLLECTION` set.
See [exploit-verification.md](exploit-verification.md).
The harness-specific `VVAHARNESS_*` knobs are:

| Variable | Default | Effect |
|---|---|---|
| `VVAHARNESS_STATE_DIR` | `~/.vvaharness/state` | Root for the SQLite state DB (`vvaharness.db`), checkpoints, and the batch staging area. Reports under `<repo>/security-scan/` are unaffected. |
| `VVAHARNESS_DEBUG` | unset | On a fatal scan error, print the full Python traceback to stderr (otherwise a one-line redacted message + a pointer to `*_errors.jsonl`). Set to any value. |
| `VVAHARNESS_JSON_LOGS` | unset | Emit structured JSON stage events (`stage_start`/`stage_ok`/`stage_fail`) instead of the `▶`/`✓`/`⚠`/`✗` lines. Accepts `1`/`true`/`yes`. |
| `VVAHARNESS_SCAN_PROGRESS_ENABLED` | unset | Force-enable scan observability (`scan_progress.enabled=true`) even if the active profile disables it. Accepts `1`/`true`/`yes`. |
| `VVAHARNESS_CLAUDE_BINARY` | `claude` (on `PATH`) | Absolute path to the `claude` executable, bypassing `PATH` (see *Pinning the `claude` executable* above). |
| `VVAHARNESS_ALLOW_CWD_CONFIG` | unset (gate active) | Opt out of the trust gate that refuses a `--config` / `.env` located **inside the scan target** (which otherwise falls back to the packaged default / is ignored). It does not bypass `.env` ownership or mode checks. Set only for a target you trust. |
| `VVAHARNESS_NO_LOCAL_CONFIG` | unset (overlay applied) | Skip the `config.local.yaml` overlay for a reproducible run that honours **only** the selected config. |
| `VVAHARNESS_REMEDIATE_DISABLE` | unset | Kill-switch for autonomous remediation: when truthy (`1`/`true`/`yes`/`on`), the remediation gate returns guidance-only for **every** finding (active when `step_remediate.enforce_policy: true`; a `./.vvaharness-remediate-off` file is an equivalent sentinel). See [`remediation.md`](remediation.md). |
| `VVAHARNESS_INGEST_URL` | unset (upload skipped) | Step 9 ingest-hub upload destination for `report.md` + `report.sarif`. All four shipped profiles expand it into `output.ingest_url`. |
| `VVAHARNESS_INGEST_TOKEN` | unset (upload skipped) | Bearer token for the ingest upload (`output.ingest_token`). With no URL or token, the upload is skipped. |
| `VVAHARNESS_INGEST_VERIFY` | `false` in `default.yaml`; `true` in the other shipped profiles | TLS verification for the ingest upload (`output.ingest_verify`): a boolean or a CA-bundle path. Note the profile asymmetry — set it explicitly if you rely on ingest TLS verification under the default profile. |
| `VVAHARNESS_PRICING_FILE` | unset (`cost_usd` reported as `null`) | Path to an operator-supplied model price table (US$ per million tokens) used to cost the run manifest's per-stage token counts. Overrides the `pricing.file` config key; with neither set every `cost_usd` is `null`. |
| `VVAHARNESS_LOG_LEVEL` | unset (no log handler) | Attach a redacting log handler at this level (`debug`/`info`/`warning`/`error`/`critical`). Also settable with the global `--log-level` flag. |
| `VVAHARNESS_LOG_FILE` | unset (stderr) | Destination file for the handler enabled by `VVAHARNESS_LOG_LEVEL`; unset logs to stderr. Also settable with the global `--log-file` flag. |
| `VVAHARNESS_DEBUG_LOG` | unset (no-op) | Append remediation plugin-runner debug lines to this path; unset disables the trace. |
| `VVAHARNESS_SETTINGS_FILE` | `$XDG_CONFIG_HOME/vvaharness/settings.json` | Override the path to the remediation `settings.json` (whose `inputs_dir` can point at custom policy/playbook rule files). |
| `VVAHARNESS_SCAN_PROGRESS_LLM_MAX_CHARS` | `12000` | Character cap applied to each prompt/response body printed by the `scan_progress` `llm_debug` style. |
| `VVAHARNESS_DEBUG_MEM` | unset | Set to `1` to print call-graph rules-engine memory diagnostics. |
| `VVAHARNESS_TLS_CLIENT_KEY` | unset | Private-key path for when the mTLS client certificate named by `VVAHARNESS_TLS_CLIENT_CERT` is a split key/cert pair rather than a combined PEM. |

> The `validate`/`s11` subsystem reads only a small credential/host-local
> environment surface: `VVAHARNESS_CLAUDE_BINARY` (see the table above),
> `VVAHARNESS_MAX_RETRIES` (per-session retry cap, default `2`), and
> `VVAHARNESS_GHE_TOKEN` / `VVAHARNESS_GHE_ARCHIVED_TOKEN` (GitHub Enterprise
> tokens passed through to the agent for `gh api`). **Every tunable — model,
> `via`, effort, turns, budget, findings cap, tool allowlist, persona models —
> comes from the profile's `models.validate` / `step_validate` block and is
> passed in-process, never through the environment.** Environment variables
> like `VVAHARNESS_MODEL`, `VVAHARNESS_EFFORT`, `VVAHARNESS_VIA`, or a
> per-persona `*_MODEL` are **not read by any code**; setting them has no
> effect. Tune the profile, not the environment.

---

## 5. Output

Per target, under `<target>/security-scan/`:

| File | Contents |
|---|---|
| `<module>_<ts>_report.md` | findings + dropped-findings appendix |
| `<module>_<ts>_report.sarif` | SARIF 2.1.0 for tooling ingestion |
| `<module>_<ts>_errors.jsonl` | non-fatal errors; absent on a clean run |

The `validate` command writes per-DTO under
`<repo>/security-remediation/<NN_slug>/`: the `validation` block is merged back
into `finding_case.json`; the case `state` derives to `validated`, `failed`,
or `open`. When a source session log is
available and redaction/persistence succeeds, a redacted
`validation_session_<finding>.jsonl` transcript is also retained; this audit
artifact is best-effort. The agent's
`validation_report.json` and `synthesized_gates.json` are written into an
ephemeral staging workspace, consumed for host-side scoring, and removed on
completion — they are **not** persisted under the DTO folder.

Batch scans also write `<workspace>/batch_summary.md`. Every **scan** writes
`run_manifest_YYYYMMDDTHHMMSSZ.json` in the current working directory (tool version, detection
model roles — each with `id`, `via`, `provider`, and its resolved route —
config/overlay hashes, target git SHA, arguments, outcome, timing, and — when
Step 11 ran — a `remediation` rollup of validation outcomes; that key is
omitted rather than zeroed when validation did not run; if a same-second name
already exists, `_NN` is appended)
so each scan is auditable. See [outputs.md](outputs.md) for the
full report/SARIF anatomy and the manifest field reference.

### Progress & logs
On an interactive terminal each executed stage shows a **live spinner** with
elapsed time, replaced by a green `✓` + duration when it finishes (`✗` on
failure). A stage that finished but recorded unrecovered (non-fatal) errors while
it ran is marked with a yellow **`⚠`** rather than `✓`: it did not fail, but it lost
coverage, and that must not read as a clean stage at a glance. That line also
carries the error count and a pointer to the per-run `errors.jsonl`, and the stage
is recorded in `run_manifest_*.json` with the outcome `completed_with_errors` instead
of `completed`. The `⚠` does not change the exit code — a stage that ran to
completion is still a completed stage. Records the pipeline recovered from, or
that are purely informational, still appear in `errors.jsonl` but do not
count toward that line. The current counter uses stage numbers rather than one-based slots:
a full S0–S11 run passes `n=0..11`, `total=11`, so completed lines range from
`[0/11]` through `[11/11]`. On CI / non-TTY
the tool prints plain `▶`/`✓`/`⚠`/`✗` lines (the `⚠` carries no colour
there, which is why the glyph itself changes and not merely its colour). For
machine-readable output set **`VVAHARNESS_JSON_LOGS=1`** — each stage then emits
a structured JSON event (`stage_start` / `stage_ok` / `stage_fail` with timing;
`stage_ok` also carries an `errors` count when the stage recorded unrecovered
errors) instead, alongside the existing JSON artifacts (`run_manifest_*.json`,
`*_errors.jsonl`, SARIF).

### Observability
`scan_progress` is the file/chunk-level observability stream. It is enabled in
`compact` mode by `default.yaml` and `full.yaml`, `verbose` by `taint.yaml`,
and disabled by `sdk.yaml` unless overridden. No shipped profile enables
`llm_debug` — it is opt-in, and because it prints the full prompt (including
the scanned source code) for every model dispatch, treat its stderr with the
same care as the repository.

Enable it in either way:

1. Config profile:
```yaml
scan_progress:
  enabled: true
  style: verbose   # compact | verbose | summary_only | stage_only | llm_debug
```

  Use `stage_only` for only stage start/done lines, each prefixed with a stage
  counter (S11 currently prints an unnumbered `?/11` slot). Add
  `--s6-progress-file` to publish a queryable S6 verification counter after each
  finding.

2. Environment override:
```bash
VVAHARNESS_SCAN_PROGRESS_ENABLED=1 vvaharness scan --repo /path/to/target
```

When observability is enabled, progress starts at the first detection stage and
prints stage events for all scan stages (`s0`–`s11`):

- `default.yaml`, `full.yaml` and `taint.yaml`: S0 runs (LLM mode in the first two,
  rules mode in `taint.yaml`); a resumed S0 can report `cached`.
- `sdk.yaml`: S0 is disabled, so the wrapper completes with an empty seed; normal
  stage events then continue through S1–S11 (S10/S11 report `outcome=disabled`
  when remediation/validation cannot run).

You will see lines such as:

```text
[progress] stage-start s0   callgraph
[progress] stage-done  s0   outcome=completed  0.9s
[progress] stage-start s1   preprocess
[progress] discovered    247 files  (repo: my-service)
[progress] queued      chunk-01 ...
[progress] scanning    chunk-01 ...
[progress] scanned     chunk-01 ... outcome=completed findings=2
[progress] stage-done  s10  outcome=completed  12.3s  attempted=5 fixed=4 not_fixed=1
[progress] stage-done  s11  outcome=completed  18.7s  validated=5 passed=4 failed=1
```

`style: verbose` prints file-by-file lines (`discovered`, `queued`, `scanning`,
`scanned`) plus stage milestones (`stage-start`, `stage-note`, `stage-done`).
`style: llm_debug` adds backend payload traces (phase/model/backend +
`system_prompt` and `user_prompt` content) for each model dispatch.

### Save verbose output to a log file

#### Linux / macOS (`bash` / `zsh`)

To save terminal output while still seeing it live, pipe both stdout and stderr
to `tee`:

```bash
mkdir -p logs
set -o pipefail
VVAHARNESS_SCAN_PROGRESS_ENABLED=1 vvaharness scan --repo /path/to/target 2>&1 \
  | tee logs/scan-$(date +%Y%m%d-%H%M%S).log
```

- `2>&1` captures stderr (where progress/stage lines are printed).
- `set -o pipefail` preserves scan failure as the shell exit code when piping.

The exit code `pipefail` preserves follows a five-value contract: `0` clean,
`1` pipeline failure, `2` refused before the work the refusal guards, `3`
completed but nothing remediated validated as fixed, `130` user abort. Scripts
should branch on the code, not grep the log — see
[outputs.md → Exit codes](outputs.md#exit-codes) for the full table, the
`1`-vs-`3` distinction, and what `2` does and does not promise.

Append to an existing log instead of creating a new one:

```bash
VVAHARNESS_SCAN_PROGRESS_ENABLED=1 vvaharness scan --repo /path/to/target 2>&1 \
  | tee -a logs/scan-latest.log
```

If you want a full terminal transcript (including TTY spinner rendering), use
`script`:

```bash
mkdir -p logs
script -q logs/scan-terminal-$(date +%Y%m%d-%H%M%S).log \
  vvaharness scan --repo /path/to/target
```

#### Windows (PowerShell)

Create a timestamped log while streaming output live:

```powershell
New-Item -ItemType Directory -Force -Path logs | Out-Null
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
vvaharness scan --repo C:\path\to\target 2>&1 |
  Tee-Object -FilePath "logs/scan-$ts.log"
exit $LASTEXITCODE
```

Append to a rolling log:

```powershell
vvaharness scan --repo C:\path\to\target 2>&1 |
  Tee-Object -FilePath "logs/scan-latest.log" -Append
exit $LASTEXITCODE
```

Full terminal transcript (Windows equivalent of `script`):

```powershell
New-Item -ItemType Directory -Force -Path logs | Out-Null
Start-Transcript -Path "logs/scan-terminal-$((Get-Date).ToString('yyyyMMdd-HHmmss')).log"
vvaharness scan --repo C:\path\to\target
Stop-Transcript
exit $LASTEXITCODE
```

---

## 6. Limitations (important)

- **Non-deterministic & LLM-judged.** Treat findings as leads to verify, not
  ground truth. Majority-vote false-positive filtering engages on `via: sdk`,
  `via: openai`, and `via: deepagents` deep-dive models; the `via: cli`
  backend runs once (it has no temperature control), and models that reject
  `temperature` still execute every configured run at the provider's default
  sampling — the diversity is just not tunable. Only `full.yaml` ships with
  voting on, and the deterministic s5 pre-filter is the main FP defence when
  voting is off.
- **Severity is derived from the CVSS base-score band, not judged separately.**
  Findings are labelled Critical / High / Medium / Low / Info. The four scored
  tiers come straight from the CVSS 3.1 qualitative band — Critical (9.0–10.0),
  High (7.0–8.9), Medium (4.0–6.9), Low (0.1–3.9) — so the label can never
  disagree with the reported vector, while Info covers findings with no
  demonstrated exploit path. The base score (0–10) and full vector are reported
  verbatim on each finding.
- **Token-hungry.** There is no global spend cap. Compatible Claude CLI and
  Claude Agent SDK paths can enforce per-session `max_budget_usd`; raw SDK,
  OpenAI, and DeepAgents paths ignore it. Use `vvaharness estimate` before a
  scan and treat token accounting as reporting, not enforcement.
- **Validation accepts `via: openai` by routing it; remediation _fix mode_ does
  not.** A `via: openai` validate role is routed to `via: deepagents` with the
  OpenAI provider, so it runs. Remediation _fix mode_ needs the `Edit`/`Write`
  tools that only the `via: cli`, `via: sdk`, and repo-confined `via: deepagents`
  backends expose — under `via: openai` it can only run `--mode report-only`.
  Detection (S1–S9) and report-only remediation run on `via: cli`, `via: sdk`,
  or `via: openai`; every detection role also accepts `via: deepagents`.
- **Missing post-scan credentials are a warning, not a fatal error.** If
  `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` is absent but only required by S10
  (remediate) or S11 (validate), preflight emits a `WARN` and skips that stage —
  S1–S9 detection still runs and produces findings. Missing credentials for any
  detection role (S1–S9) remain fatal and abort the scan before spending tokens.
- **`via: deepagents` is valid on every model role** — `models.remediate`,
  `models.validate`, the single-shot detection roles (`autoexclude`,
  `graph_annotate`, `threatmodel`, `decompose`, `deepdive`, `dedup`,
  `chain` — one completion with no tools offered to the model), and the
  agentic detection roles (`preprocess`, `verify` — a read-only agentic
  loop). See [models.md](models.md) for the full role/backend matrix.
- **Validation is capped unless explicitly uncapped.** In-scan and standalone
  validation apply `step_validate.max_findings` by default. Standalone
  `vvaharness validate --all` bypasses the cap for every validatable DTO;
  already-`validated` DTOs remain excluded.
- **Elevated privilege; trusted targets only.** vvaharness assumes an authorized
  operator running against a repository they trust. Scanning untrusted or
  malicious code can expose host credentials, files, or other risk. If you must
  scan a less-trusted or sensitive target, apply the compensating controls in
  [`security.md` → Hardening for less-trusted or sensitive targets](security.md#hardening-for-less-trusted-or-sensitive-targets).
- **No published accuracy numbers yet.** Precision/recall figures are not yet published.
- **No rules-mode S0 corpus is bundled.** `taint.yaml` is the shipped profile that
  runs S0 in rules mode, and rules mode returns an empty seed without
  operator-supplied generated source/sink files; later stages still run.
  `default.yaml` and `full.yaml` run S0 in LLM mode instead, so they are not
  affected by the missing corpus.
- **Structured S0 taint evidence, when usable specs exist, is Python, Java, and C# only.** JavaScript,
  TypeScript, and Go use reachability-only S0 paths without typed transfer
  edges, sanitizer neutralization, framework-source detection, or reflection
  tracking. Languages without an S0 plugin, including Rust, receive no static
  seed; later LLM stages still run.

---

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `command not found: vvaharness` | use `pipx install .`, or run `python3 -m vvaharness …` |
| `ANTHROPIC_SDK_API_KEY not set` | put it in `.env` (auto-loaded) or export it; re-run `vvaharness doctor` |
| `claude` CLI not found / not logged in | install the Claude Code CLI, then run `claude` and use `/login` (or `claude setup-token`) |
| Scan too slow / costly on a huge repo | add exclusions in the config `step1` section, or a `--step1-config` overlay; AI auto-exclude (`--auto-step1`) already runs by default in all shipped profiles |
| Re-run only later stages | `--resume` (reuses checkpoints in `$VVAHARNESS_STATE_DIR/vvaharness.db`) |

See the other guides in this folder for [configuration](configuration.md),
[models](models.md), [outputs](outputs.md), and [batch-CSV](repos-csv.md) details.
