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

# Features & Capabilities

A single reference for **everything vvaharness does and everything you can
combine** when running it, and **how config lets the team mix and match models
per stage without touching code**.

**Agentic vulnerability discovery, remediation, and validation** — an S0 seed
stage plus S1–S11: 9 detection stages, S10 remediation, S11 validation ·
4 backends (`cli`, `sdk`, `openai`, `deepagents`) · 11 specialist lenses ·
42 language lenses · **config-driven**. It surveys a repo, threat-models it,
decomposes it, deep-dives, verifies, dedups, chains exploits, and emits enriched
**Markdown + SARIF 2.1.0**. A `remediate` command applies fixes by default
(`report-only` mode proposes instead) and an agentic `validate` command grades
them — both also run **in-scan by default** in the sdk/full profiles;
default/taint ship both stages disabled. Standalone commands remain available.

> Shipped profiles live in **`vvaharness/config/profiles/`**
> (`default.yaml`, `sdk.yaml`, `full.yaml`, `taint.yaml`). Every config key is
> in [configuration.md](configuration.md); this file is the map of what to
> combine and why.

```
s0 static seed → s1 preprocess → s2 threatmodel → s3 decompose → s4 deepdive
              → s5 prefilter   → s6 verify     → s7 dedup → s8 chain → s9 SARIF
```

The standalone `vvaharness validate` command runs separately (s11 agentic
panel — which first discovers the DTOs awaiting validation, then runs the
panel) over the remediation DTOs written by the `remediate` command (Step 10) — see [§2](#2-pipeline-stages) and [§6](#6-commands--run-time-options).

The core idea: **every LLM stage is a config switch.** Each role picks its own
`{id, via}` (plus `provider` on a `via: deepagents` role) in `config.yaml: models`,
and the dispatcher (`backends/llm/registry.py`)
routes on `via:` (a `via: deepagents` role bypasses the registry through the
dispatch seam in `backends/llm/deepagents.py` — see §3). **Swapping a role is
config-only — no code change.**

---

## 1. The two axes you combine

A run is defined by combining choices on two axes:

1. **Per-role backend** (`via:`) — `cli`, `sdk`, or `openai`, chosen
   independently for each detection LLM role. Every role additionally supports
   `deepagents`: the single-completion roles (`autoexclude`, `graph_annotate`,
   `threatmodel`, `decompose`, `deepdive`, `dedup`, `chain`) as a zero-tool
   one-shot, the agentic `preprocess` and `verify` roles as a read-only loop,
   and S10/S11 as the agent graph; legacy `via: openai` validation is
   normalized to DeepAgents/OpenAI.
2. **Per-stage tuning** (`step0:`, `step1:`…`step4:`, `step5_prefilter:`,
   `step6_verify:`, `step6_exploit_verification:`, `step7_dedup:`, `step8:`,
   `step_remediate:`, `step_validate:`, `inject:`, `batch:`, `output:`) — cost /
   depth / precision knobs, plus CLI flags at runtime.

---

## 2. Pipeline stages

| Step | Role | Backend? | Output |
|---|---|---|---|
| s0 static seed | — in rules mode; `graph_annotate` in LLM mode | local AST; `default.yaml` and `full.yaml` run LLM mode (model-annotated seed, spends tokens), `taint.yaml` runs rules mode (external rule YAML) | source/sink callgraph seed; in taint's rules mode the shipped blank rule paths yield an empty seed |
| auto-step1 | `autoexclude` | yes | AI-derived Step-1 exclusion overlay — enabled by `step1.auto_exclude` (`true` in all four shipped profiles, so it runs on every default scan) or forced with `--auto-step1` |
| s1 preprocess | `preprocess` | yes (agentic) | repo survey + call graph → `ContextPackage` |
| s2 threatmodel | `threatmodel` | yes | assets, trust boundaries, ranked threats |
| s3 decompose | `decompose` | yes | risk / taint / catch-all / specialist / threat-fallback chunks → `TaskManifest` |
| s4 deepdive | `deepdive` | yes | per-chunk findings (single pass by default; ×N runs + majority vote when enabled) |
| s5 prefilter | (`dedup`) | **deterministic gates** | drops low-confidence / unproven findings; runs one optional semantic pre-dedup call (the `dedup` role) when survivors ≥ `step5_prefilter.pre_verify_threshold` (falls back to `step7_dedup.pre_verify_threshold`, then 25; `default.yaml` ships 0 = always run) and `step5_prefilter.pre_verify_semantic` is on (falls back to `step7_dedup.pre_verify_semantic`, then `step7_dedup.semantic`) |
| s6 verify | `verify` | yes (agentic) | adversarial TRUE / FALSE_POSITIVE + CVSS per finding |
| s7 dedup | `dedup` | yes | deterministic + semantic dedup → canonical findings |
| s8 chain | `chain` | yes | exploit-chain analysis + re-rank → `FinalReport` |
| s9 SARIF | — | **deterministic** | parses the Markdown report → SARIF 2.1.0 |

Each `scan` stage checkpoints to the SQLite state DB at
`$VVAHARNESS_STATE_DIR/vvaharness.db` (default `~/.vvaharness/state/…`);
`--resume` skips completed stages. `s9` uses no model. `s5`'s gates are
deterministic, but it also fires one optional semantic pre-dedup call (the
`dedup` role) when the survivor count reaches
`step5_prefilter.pre_verify_threshold` (`step7_dedup.pre_verify_threshold`
is only a fallback; the shipped `default.yaml` sets the step5 key to 0, so
the call always runs).

The standalone **`vvaharness validate`** command runs two phases of the s11 stage
over the remediation DTOs the `remediate` command writes: a **discover** phase
(deterministic, no model spend — locates DTOs awaiting validation) and an **s11
panel** phase (agentic adversarial panel: two always-on personas
`security-architect` + `penetration-tester`, plus a `cross-repo-analyzer` the
orchestrator is instructed to spawn only when the fix spans two or more repositories,
which then returns `skip` for gates outside its multi-repo perspective) that fills
each DTO's `validation` block. The default runtime is `via: deepagents`
(set in `default.yaml`); `cli` and `sdk` backends run the bundled Claude Agent
SDK instead. `models.validate` resolves to `via: cli`, `via: sdk`, or
`via: deepagents`; a legacy `via: openai` value is routed to `via: deepagents` with
the OpenAI provider before any model spend, so the spelling that detection and
report-only remediation accept also works for validation.

These same two stages also run automatically at the **end of a `scan`** —
Step 10 (remediate) then Step 11 (validate) — when `step_remediate.enabled` /
`step_validate.enabled` are true. The `sdk` and `full` profiles enable both;
`default` and `taint` ship both disabled (`step_remediate.enabled: false`,
`step_validate.enabled: false`). `--remediate` can enable S10, but not S11;
scan has no `--validate` flag. Run standalone `validate` to grade existing
remediation DTOs without enabling in-scan S11.

> ⚠️ **The shipped `default` profile skips S10/S11; enabled remediation can
> still edit your target's source.** A plain scan using the unchanged default
> profile runs detection through S9 without automatic fixes or fix validation.
> If S10 is enabled by `--remediate` or the effective config (as in `sdk`/`full`),
> it runs in fix mode and can write source changes and
> `<repo>/security-remediation/` artifacts when findings, credentials, and a
> successful session are present. S11 runs only when separately enabled in
> config. Pass **`--stop-after s9`** to explicitly skip both with any profile.

---

## 3. Backends (`via:`)

| `via:` | Transport | Auth | Tools | Honours | TLS / mTLS |
|---|---|---|---|---|---|
| `cli` *(opt-in per role; used by S11 validation)* | `claude` CLI subprocess | run `claude` → `/login`, or `CLAUDE_CODE_OAUTH_TOKEN` | allowlisted Read · Glob · Grep; **Bash** capable only when explicitly listed | capability-gated `max_budget_usd`, `effort`, `max_turns` | `ca_cert` → `NODE_EXTRA_CA_CERTS`; **no mTLS** |
| `sdk` *(all roles in `sdk.yaml`)* | Anthropic Python SDK (detection) | `ANTHROPIC_SDK_API_KEY` | Read · Glob · Grep *(sandboxed, no Bash)* | `temperature`, `thinking_budget`, `betas`, `max_turns` | direct detection transport: `ca_cert` + **`client_cert` (mTLS)** — Agent-SDK S10/S11 do not consume them |
| `openai` | OpenAI-compatible Chat Completions | `OPENAI_API_KEY` (+ `OPENAI_BASE_URL`) | Read · Glob · Grep *(sandboxed, no Bash)* | `temperature`, `max_turns` | `ca_cert`; no mTLS |
| `deepagents` *(S10/S11 default; also detection roles)* | DeepAgents/LangGraph harness: agent graph on `remediate`/`validate`; a one-shot completion on the single-shot detection roles; a read-only agentic loop on `preprocess` and `verify` (and agentic S2) | Anthropic: `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`; OpenAI: `OPENAI_API_KEY` | S10 repo-confined Read/Glob/Grep/Edit/Write; S11 read-only agents; single-shot detection: **no tools offered** (no filesystem, no shell, no sub-agent dispatch); agentic detection: read-only Read/Glob/Grep | `max_turns` (S10/S11 and agentic detection; mapped to a recursion limit), structured output (S10/S11 only) | `verify_ssl` / `ca_cert` / **`client_cert` (mTLS)** from the `sdk:` or `openai:` block matching the role's vendor (detection roles; S10/S11 read `SSL_CERT_FILE` / `VVAHARNESS_TLS_CLIENT_CERT` from the environment) |

Every **detection** role runs on `cli`, `sdk`, or `openai`, and every
detection role also accepts `via: deepagents`: the single-shot
roles (`autoexclude`, `graph_annotate`, `threatmodel`, `decompose`,
`deepdive`, `dedup`, `chain`) run one completion offering
the model no tools and no sub-agent dispatch, while `preprocess` and `verify`
run a read-only agentic loop (see [models.md](models.md) for
the full role matrix). Bash is CLI-exclusive and no shipped
profile grants it. For S11, `cli` and `sdk` both select the read-only Claude
Agent SDK Harness. S10 `via: sdk` delegates fix-mode Edit/Write to the Agent
SDK; S10 `via: cli` remains the direct CLI route. A bare-string model id
defaults to `via: cli`.

### Combination rules that actually matter

| Rule | Why |
|---|---|
| **Bash** is available only in agentic stages (`preprocess`, `verify`, and opt-in agentic S2) when that role is `via: cli`. | Only the CLI backend exposes Bash; re-add `- Bash` to `allowed_tools` when you switch. The opt-in agentic S2 (`step2.agentic`, off by default) validates its allowlist against `{Read, Glob, Grep}` and refuses `Bash`/`Edit` on `via: sdk` / `via: openai` / `via: deepagents` before any model call; on `via: cli` the allowlist is honoured verbatim, so Bash can be granted to agentic S2 the same way as to `preprocess` / `verify`. That guard matters because on `via: sdk` an unsupported or mutating tool would otherwise delegate to the Agent SDK backend, which could modify the scanned repository. |
| **s4 repeated-run voting** (`step4.runs > 1`) is supported on `via: sdk`, `via: openai`, and `via: deepagents` — the backend the shipped `full.yaml` votes on (`runs: 3`, `vote_threshold: 2`). | Runs auto-collapse to one on `via: cli` only. A `via: sdk` model that rejects `temperature`, an OpenAI endpoint that drops it, or `via: deepagents` (which never sends it) still executes every configured run: the provider samples at its own non-zero default, so the runs diverge and the vote means something — you just cannot tune how much. The s5 prefilter is the main FP defence when voting is off. |
| **mTLS** (`client_cert`) is exposed by the direct Anthropic SDK detection transport and by every `via: deepagents` role — including the default S10/S11. | A `via: deepagents` **detection** role reads `verify_ssl`, `ca_cert`, and `client_cert` from the `sdk:` (Anthropic) or `openai:` (OpenAI-compatible) block matching its resolved vendor — never the `cli:` block — while S10/S11 read `SSL_CERT_FILE` / `VVAHARNESS_TLS_CLIENT_CERT` from the process environment instead. Direct CLI/OpenAI and the Claude Agent SDK S10/S11 paths still do not consume a client cert (`via: cli` cannot: Node exposes no env path for one). |
| **`cli` ignores** `temperature`; budget, effort, and turn flags are capability-gated. | `--max-budget-usd`, `--effort`, and `--max-turns` are each forwarded only when the installed binary advertises that flag. The subprocess timeout remains the fallback bound. |
| **`cli` agentic stages** drive the CLI with `--output-format stream-json --verbose`. | Recent Claude CLI builds reject `--print` + `stream-json` without `--verbose`; the pairing is mandatory and emitted unconditionally. Requires a `claude` build that accepts `--verbose` with stream-json (every supported 2.x does). |
| `sdk` / `openai` auto-drop and retry params the model rejects. | Lets you mix model generations without config churn. |

---

## 4. How config helps the team — recipe profiles

The `models:` block is where the team encodes its trade-offs. Six common
shapes:

### 4.1 Quick start — the shipped `default.yaml`

`default.yaml` is all DeepAgents: S1–S9 detection runs `via: deepagents`
with the Anthropic provider (`claude-opus-4-7` on every role except
`preprocess`, which is `claude-sonnet-4-6`). S10 remediation uses
`claude-opus-4-8`, and S11 validation's orchestrator uses `claude-opus-5`.
One Anthropic credential can cover the whole run — `ANTHROPIC_SDK_API_KEY`,
`ANTHROPIC_API_KEY`, or `ANTHROPIC_AUTH_TOKEN`; the SDK-named key has highest
precedence and is the one that carries the `sdk:` block's gateway/mTLS settings.
S4 majority voting is **off**
here (`runs: 1`); `full.yaml` is the only shipped profile that ships it on
(`runs: 3`, `vote_threshold: 2`). `sdk.yaml` and `taint.yaml` also ship
`runs: 1`, so despite `sdk.yaml`'s temperature-capable deepdive it does **not**
vote unless you raise `step4.runs` yourself.

In `sdk.yaml`, every configured role is spelled `via: sdk`: detection uses the
Anthropic Python SDK, S10 translates the SDK-named key for its Claude Agent SDK
path, and S11 uses that Harness but pins an external `claude` executable. S11
there uses ambient Claude login/OAuth or standard `ANTHROPIC_API_KEY` /
`ANTHROPIC_AUTH_TOKEN`; the SDK-named key alone is not translated. A standard
credential can cover the profile through the sole-SDK fallback.

The default also enables the local S0 stage — in **LLM mode**
(`callgraph_detection: llm`): the `graph_annotate` model classifies AST call
fingerprints into source/sink specs, so default's S0 builds a real seed and
spends tokens. `sdk.yaml` omits S0; `full.yaml` also enables LLM mode;
`taint.yaml` enables it in **rules mode**
(`callgraph_detection: rules`). No source/sink pack is bundled, so shipped
rules mode is empty unless the operator supplies generated rule files.

For source→sink callgraph scanning, use the shipped `taint.yaml` profile
(`--config vvaharness/config/profiles/taint.yaml`) and supply generated rule
files, or copy a profile and set `step0.callgraph_detection: llm`. The
`graph_annotate` / `callgraph_creation` models are preflighted and
credential-checked only when `step0.callgraph_detection: llm`; in `rules`
mode they are dead config and deliberately skipped, so a rules-mode profile
scans without their credentials.

```yaml
models:
  autoexclude:    {id: claude-opus-4-7,   via: deepagents, provider: anthropic}
  graph_annotate: {id: claude-opus-4-7,   via: deepagents, provider: anthropic}  # S0 LLM annotator
  preprocess:     {id: claude-sonnet-4-6, via: deepagents, provider: anthropic}
  threatmodel:    {id: claude-opus-4-7,   via: deepagents, provider: anthropic}
  decompose:      {id: claude-opus-4-7,   via: deepagents, provider: anthropic}
  deepdive:       {id: claude-opus-4-7,   via: deepagents, provider: anthropic}
  verify:         {id: claude-opus-4-7,   via: deepagents, provider: anthropic}
  dedup:          {id: claude-opus-4-7,   via: deepagents, provider: anthropic}
  chain:          {id: claude-opus-4-7,   via: deepagents, provider: anthropic}
```

### 4.2 Multi-backend template — `full.yaml`

As shipped, `full.yaml` routes every model role `via: deepagents` with the
Anthropic provider, enables S0 LLM annotation, and is the only shipped profile
with S4 voting on (`runs: 3`, `vote_threshold: 2`). All four exploit-verification
roles ship `via: deepagents` in `default.yaml`, `full.yaml` and `taint.yaml`, and
`via: sdk` in `sdk.yaml`. No shipped profile routes an EV role `via: cli`. One
Anthropic credential covers an EV-armed `default` or `taint` run; `full.yaml`
additionally needs `OPENAI_API_KEY`, for its `judge` alone. It also carries commented
`via: cli`, `via: sdk`, and `via: openai` alternatives beside the roles that
accept them. Uncommenting those alternatives changes the credential set: CLI
roles need Claude CLI auth, SDK roles need Anthropic SDK/standard Anthropic
auth, and OpenAI roles need `OPENAI_API_KEY` plus any gateway settings.

A mixed layout using those backends could look like this —
it is **not** the shipped block (as shipped, every role is `via: deepagents`):

```yaml
models:
  autoexclude: {id: claude-opus-4-7,   via: cli}
  preprocess:  {id: claude-sonnet-4-6, via: sdk}
  threatmodel: {id: gpt-5.5,           via: openai}
  decompose:   {id: gpt-5.5,           via: openai}
  deepdive:    {id: claude-opus-4-7,   via: sdk}  # voting still on: full.yaml sets step4.runs: 3
  verify:      {id: gpt-5.5,           via: openai}
  dedup:       {id: claude-opus-4-7,   via: sdk}
  chain:       {id: claude-opus-4-7,   via: cli}
```

### 4.3 Other shapes

| Recipe | Shape | Unlocks / trade-off |
|---|---|---|
| **Max precision (voting)** | shipped on in `full.yaml` only (`step4.runs: 3`, `vote_threshold: 2`); the other three profiles ship `runs: 1`, so `sdk.yaml`'s `temperature: 0.4` deepdive makes voting *available* but not active. Raise toward `temperature: 1.0` / `runs: 4` / `vote_threshold: 3` for more | Majority-vote FP filtering; higher cost. Forced to single-pass on `via: cli` only. A temp-rejecting Anthropic SDK model, or an OpenAI-compatible endpoint that drops `temperature`, still receives all configured runs, sampled at the provider's own default rather than a tunable one. |
| **Bash-powered recon** | `preprocess` + `verify` → `cli` (add `- Bash`), rest `sdk` | Shell-based repo inventory & evidence retrieval. |
| **Detection behind mTLS** | SDK detection roles with `ca_cert` + `client_cert`, or `via: deepagents` detection roles reading the same keys from the matching `sdk:`/`openai:` block (S10/S11 via `VVAHARNESS_TLS_CLIENT_CERT` in the environment) | Direct Anthropic SDK detection and every `via: deepagents` role — including the default S10/S11 — can reach an mTLS gateway; direct `cli`/`openai` roles and the Claude Agent SDK S10/S11 paths still cannot. |
| **Cost-lean detection** | detection roles on `openai`; stop after S9 or explicitly configure supported post-scan roles | Lower-cost compatible endpoint; no Bash. S4 voting still works on endpoints that drop `temperature`, but the sampling divergence is then not tunable. |

**To use any of these:** copy the nearest shipped profile to `./config.yaml`,
edit the relevant block, then run `vvaharness doctor`. It live-probes detection
transports, but currently does not exercise the actual S10/S11 Claude Agent SDK
Harness launcher, so verify its external-CLI and standard-auth requirements too.

---

## 5. Credentials per combination

Which credentials a run needs is the **union of the backends any role uses**:

| If any role is… | You need |
|---|---|
| `via: sdk` | Detection uses `ANTHROPIC_SDK_API_KEY` (or the standard Anthropic credential fallback when every configured role is `via: sdk` or `via: deepagents`); S10 translates the SDK key/base URL, while S11 pins external `claude` and uses Claude login/OAuth or standard Anthropic auth. SDK CA/mTLS vars apply to direct detection and, via the `sdk:` block, to Anthropic-routed `via: deepagents` roles. |
| `via: openai` | `OPENAI_API_KEY` (+ optional `OPENAI_BASE_URL`, `OPENAI_CA_CERT`) |
| `via: cli` | Claude CLI logged in — run `claude` → `/login`, or set `CLAUDE_CODE_OAUTH_TOKEN` (+ optional `CLAUDE_CLI_CA_CERT`) |
| `via: deepagents`, Anthropic provider | `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` (+ optional `ANTHROPIC_BASE_URL`); TLS/mTLS from the `sdk:` block (`verify_ssl`, `ca_cert`, `client_cert`) |
| `via: deepagents`, OpenAI provider | `OPENAI_API_KEY` (+ optional `OPENAI_BASE_URL`); TLS/mTLS from the `openai:` block (`verify_ssl`, `ca_cert`, `client_cert`) |

All TLS keys are optional: with just an API key the public endpoint is used and
no certificate is required. Certificate env values are best given as absolute
paths; after `${VAR}` interpolation the value lands in the profile's transport
block, and a relative value there resolves against the **selected config's
directory** (not the process's current working directory); network/UNC paths
are refused. `${VAR}` interpolation is itself policed by name: an env var
whose name matches a secret pattern (contains `API_KEY`/`APIKEY`, `TOKEN`,
`SECRET`, `PASSWORD`/`PASSWD`, `CREDENTIAL` or `PRIVATE_KEY`, or has an
underscore-delimited name segment ending in `AUTH` — so `OAUTH` counts,
`AUTHOR` does not) may expand only into `sdk.api_key`, `openai.api_key`,
`batch.git_token`, or `output.ingest_token`; interpolating it anywhere else
makes the config refuse to load, whether the variable is set or not. See
[SETUP_GUIDE.md](SETUP_GUIDE.md) for the full when-is-a-cert-needed matrix.

---

## 6. Commands & run-time options

| Command | Purpose |
|---|---|
| `vvaharness setup` | Guided readiness check (Python/git, AI agents, keys, gateway, config); read-only unless `--write-env`, optional `--install-agents`. (Alias: `init`.) |
| `vvaharness scan …` | Run the configured pipeline against one repo or a batch; the packaged default skips S10/S11. `scan` is the implicit default — arguments with no leading subcommand are run as a scan. |
| `vvaharness remediate --repo <path>` | Walk a prior scan's findings and, in the default `fix` mode, apply a minimal fix per finding; `--mode report-only` proposes without editing (Remediation Agent, s10). `-i`/`--interactive` picks findings from a menu; `-v`/`--verbose` prints the prompt + raw response per finding. Standalone use is independent of the in-scan toggle (off in default/taint; on in sdk/full). |
| `vvaharness validate --repo <path>` | Run S11: deterministically discover validatable remediation DTOs, then run the read-only agentic panel on the configured Harness backend. Standalone use is independent of the in-scan toggle (off in default/taint; on in sdk/full). (Alias: `s11`.) |
| `vvaharness ev-replay --repo <path>` | Re-send a prior exploit-verified scan's confirming payloads against a redeployed target and report each finding as `REMEDIATED` / `STILL VULNERABLE` / `NOT PROVEN FIXED`. Accepts `--config`; needs `EV_TARGET_URL` + the same `EV_*` env a scan uses. See [exploit-verification.md](exploit-verification.md). |
| `vvaharness doctor [--config <file>]` | Report readiness and live-probe detection transports; it does not exercise the actual S10/S11 Agent-SDK Harness launcher. `--cache-probe` adds an opt-in prompt-cache diagnostic. |
| `vvaharness estimate --repo <path>` | Print a rough scope/cost preview. Spends nothing. |
| `vvaharness gc […]` | Prune old checkpoint runs (`--keep-runs` / `--max-age-days` / `--dry-run`), or fully evict one run with `--run <path>`. |

| Flag | Effect |
|---|---|
| `--repo` / `--repo-file` | Single local checkout, or batch CSV/TXT (clone + scan each). One required, mutually exclusive. |
| `--config <file>` | Use a specific config YAML (default `./config.yaml`, else packaged `default.yaml`). |
| `--repo-name <name>` | Module / repository name used for report + SARIF filenames and the report title (single-repo mode only; default: target dir name). |
| `--application-id <id>` | Drives CMDB AppProfile lookup, VulContextSeverity scoring, SARIF `applicationId`. |
| `--group-by-app` | Batch: clone every repo sharing an AppId under one dir → one report per application. |
| `--resume` | Reuse on-disk checkpoints instead of re-running completed stages. |
| `--stop-after <step>` | `scan`: stop after `clone`/`ev`/`s0`/`s1`…`s11`; `s0` stops after the static seed/callgraph stage; `ev` parses the collection named by `EV_API_COLLECTION` and probes target reachability, then stops **before S0** — no call graph and no model spend. |
| `--s6-progress-file` | Write `<state dir>/s6_progress/<run_id>/s6_progress.json` as the static S6 verifier works through the findings (same as `step6_verify.progress_file`). With exploit verification armed the file lands at `s6_progress/current/` instead of the `<run_id>` path, `total`/`remaining` cover only the statically verified findings rather than S6's whole set, and concurrent scans of different repositories collide on that shared `current/` path. |
| `--auto-step1` / `--no-auto-step1` | Force AI auto-exclude on (survey each target to derive its Step-1 overlay) / hard-disable it for this run, overriding the profile's `step1.auto_exclude` (which ships `true` in all four profiles, so auto-exclude already runs on every default scan). Mutually exclusive. |
| `--workspace <dir>` | Batch: directory to clone remote repos into (default `./batch-workspace`). |
| `--remediate` / `--top <N\|all\|*>` | Run the Remediation Agent (s10) after the scan; `--top` caps it to the N highest-CVSS findings. |
| `--step1-config <file>` | Apply an explicit Step-1 overlay (exclude dirs/exts/globs, `max_file_kb`, `config_dedup`). |
| `--keep-clones` / `--skip-preflight` | Keep cloned repos after scanning / skip the startup readiness probe. |
| `--force` | Override safety refusals (currently: the s10 git-SHA staleness check when HEAD moved since the scan). |

`validate` accepts `--repo` (required), `--config`, `--finding` (repeatable),
`--all`, `--max-findings`, `--workspace`, `--resume`, and `--scan-report`.

```bash
vvaharness estimate --repo /path/to/target                      # preview scope/cost, no spend
vvaharness scan --repo /path/to/target --application-id 12345 --stop-after s9
vvaharness scan --repo-file repos.csv --workspace ./scans --group-by-app --keep-clones --stop-after s9
```

---

## 7. Per-stage tuning knobs

**Every config key lives in [configuration.md](configuration.md)** — it is the
single reference, organised one section per block (`step0:` … `output:`), and it
is kept in sync with the shipped profiles. This file deliberately does not
restate the key list: a second copy drifts from the first, and the copy that used
to live here had done exactly that.

What each block is *for*:

| Block | Governs |
|---|---|
| [`step0`](configuration.md#step0--static-ast-seed) | static AST seed: rules vs LLM mode, external rule files |
| [`step1`](configuration.md#step1--repo-intake--file-inventory) | repo intake, exclusions, call-graph construction |
| [`step2`](configuration.md#step2--threat-model) | threat model: baseline, evidence and prompt caps |
| [`step3`](configuration.md#step3--decompose) | how work is split into chunks: taint, catch-all, specialists, packing |
| [`step4`](configuration.md#step4--deep-dive) | deep-dive concurrency, voting, per-run finding caps |
| [`step5_prefilter` / `step6_verify`](configuration.md#step5_prefilter--step6_verify) | deterministic gates, then adversarial verification |
| [`step7_dedup` / `step8`](configuration.md#step7_dedup--step8) | deduplication and exploit chaining |
| [`step_remediate`](configuration.md#step_remediate--remediation-agent-s10) | S10 fix generation, policy gate, tool allowlist |
| [`step_validate`](configuration.md#step_validate--validator-s11) | S11 panel effort, caps, tool allowlist |
| [`inject`](configuration.md#inject--optional-context-inputs) | optional CVE / controls / CMDB context |
| [`rules`](configuration.md#rules--s4-cwe-knowledge-overlays) | external CWE knowledge overlays for s4 |
| [`scan_progress`](configuration.md#scan_progress--filechunk-observability) | observability stream and verbosity |
| [`batch`](repos-csv.md) | multi-repo cloning and skip patterns |
| [`output`](configuration.md#output--cleanup-and-coverage-appendix) | cleanup preservation, unreachable-file appendix |
| [`cache_markers` / `cache_route` / `cache_min_block_tokens`](configuration.md#prompt-caching-cache_markers--cache_route--cache_min_block_tokens) | prompt-cache behaviour on the `sdk`/`openai` routes (`via: cli` places no markers; `via: deepagents` does not read these keys — see the caveat there) |

---

## 8. Inputs → outputs

| Inputs | Effect | Outputs |
|---|---|---|
| target repo / batch CSV | code under scan | `<module>_<timestamp>_report.md` |
| `known_cves.json` | **raises** threat likelihood / focuses the hunt | `<module>_<timestamp>_report.sarif` (2.1.0) |
| `design_controls.yaml` | **downranks** exploitability (demands bypass proof at s6) | `<module>_<timestamp>_errors.jsonl` *(only when non-fatal errors occur)* |
| `cmdb.csv` | environmental VulContextSeverity scoring | cwd `run_manifest_*.json` · batch-only `batch_summary.md` |
| remediation DTOs *(`validate`)* | agentic panel fills each DTO's `validation` block | `finding_case.json` updated (`state` derives to `validated`, `failed`, or `open`) |

Report and SARIF anatomy — every field, and how the Markdown maps to SARIF — is
in [outputs.md](outputs.md).

---

## 9. Specialist lenses (auto-gated)

Eleven lenses ship, and **all four shipped profiles enable all eleven**
(`step3.specialists`). Every lens except `logic-bug` is surface-gated
(`logic-bug` always runs), and each gate runs in S3 before any model
call — but the gates differ in how narrow they are, so "all
eleven" is a real cost commitment rather than a free one. `deserialization` (a
deserializer call site), `hardcoded-creds` (a credential value) and `iac` (IaC
files) genuinely drop to zero cost on a repository without that surface.
`csrf` runs on any authorization surface or explicit CSRF pattern, and
`sensitive-data` / `log-injection` run on any repository that has entry points
at all — in practice, always on for a web or API target.

| Lens | Focuses on |
|---|---|
| `crypto` | weak/abusable crypto, key handling, JWT alg-confusion, IV reuse, non-CSPRNG |
| `logic-bug` | TOCTOU races, state-machine flaws, sentinel/overflow |
| `access-control` | IDOR/BOLA, missing authz, priv-esc, mass assignment, tenant leakage |
| `batch-etl` | pipeline path traversal, COMP-3/EBCDIC parsing, CSV formula injection |
| `iac` | Terraform, Dockerfile, Kubernetes/Helm, GitHub Actions, Ansible misconfiguration |
| `deserialization` | unsafe deserialization and object injection |
| `csrf` | state-changing endpoints missing CSRF token / SameSite protection |
| `sensitive-data` | error-message leakage, PII in logs/responses, plaintext storage |
| `hardcoded-creds` | literal secrets in source and config |
| `log-injection` | attacker-controlled data in log calls; missing security-event logging |
| `injection` | SQLi/NoSQLi, command/LDAP/XPath injection, XXE, SSRF, path traversal, server-emitted XSS, SSTI, open redirect, CRLF, ReDoS — gated on presence of any injection-family sink |

Per-lens prompt sizes and the 42 per-language researcher lenses are catalogued
in [SKILLS.md](SKILLS.md).

---

## 10. Capabilities that ride on top

These are cross-cutting capabilities; backend-specific constraints are noted:

- **Taint analysis** — entry→sink data-flow chunks walked across the call graph, ranked above plain risk chunks. Detail below.
- **Coverage backstop (best-effort)** — files that are neither source nor IaC nor of a recognised language are added back into a catch-all chunk rather than being pruned. The backstop deliberately skips file classes judged unable to carry an exploitable finding — docs/examples/samples/fixtures/mocks and snapshot directories, readme/license/changelog/notice-class files, lockfiles, and extensions such as markdown, images, fonts, CSS, spreadsheets and CSV, logs, test snapshots, generated `.d.ts` declarations, translation catalogs, minified bundles and source maps (the full skip list is defined in the S3 decompose stage and is not configurable) — and `catchall_mode: reachable_only` prunes further, so files in those classes can reach zero reviewers. When it does add files back, the report's *Pipeline Diagnostics* line `Files added back by the coverage backstop` carries the count; audit overall coverage with the excluded-paths report section and `output.emit_unreachable_appendix` (see [security.md → Verify scan coverage](security.md#hardening-for-less-trusted-or-sensitive-targets)).
- **Prompt caching** — scan-invariant context is hoisted into a shared prefix and marked cacheable on routes known to accept markers, with `vvaharness doctor --cache-probe` to check what a route does with them. Marker gating, per-model minimums, `cache_route`, and the probe's limits are in [configuration.md](configuration.md#prompt-caching-cache_markers--cache_route--cache_min_block_tokens).
- **Exploit verification (S6, Beta — API only)** — opt-in live confirmation of API findings against a target the operator is already running, addressed in code to a loopback host. Off unless `EV_API_COLLECTION` names a Postman v2 / OpenAPI 3.0 / Swagger 2.0 collection; when armed, S6 routes live-verifiable findings to the verification agent and everything else to the static verifier, so it is purely additive and positive-only. Tuned under `step6_exploit_verification:`; see [exploit-verification.md](exploit-verification.md) and the limitation in §11.
- **Majority-vote FP filter** — run a chunk N× at T>0; a finding must appear in ≥ threshold runs to survive (`sdk`/`openai` + `temperature`).
- **Adversarial verification** — one verifier per finding renders TRUE / FALSE_POSITIVE with its own evidence and a CVSS 3.1 score.
- **CVSS + CMDB scoring** — CVSS 3.1 base on every finding, plus optional VulContextSeverity + OffensivePriority from a CMDB export.
- **CWE taxonomy** — per-finding CWE resolved to its MITRE name and URL (77 ids mapped) and referenced from SARIF `taxa[]`.
- **SARIF 2.1.0 output** — machine-ingestible SARIF (`tool.driver.name = "Agentic SAST"`) alongside the Markdown report, with a `tool.driver.rules[]` catalog, a CWE taxonomy referenced via `supportedTaxonomies`, and an `invocations[]` entry that marks a degraded run (`executionSuccessful=false`).
- **Secret / PII redaction** — card numbers (Luhn+IIN), SSNs, and credential material masked at the Markdown/SARIF write boundary.
- **Batch & group-by-app** — clone + scan many repos from a CSV, one report per AppId, with a `batch_summary.md`.
- **Resume + auditable runs** — SQLite scan/per-finding checkpoints; every scan
  writes `run_manifest_*.json` (version, detection roles — each entry carrying
  `id`, `via`, `provider`, and its resolved route — config hashes, git SHA,
  arguments, outcome, timing).

### What the taint engine actually tracks

Interprocedural and structural taint tracking, implemented for **Python, Java,
C#, JavaScript, and TypeScript** (Go gets call-graph reachability plus
field/container facts only; response-dataflow tracking is Python, Java, and C#
only):

| Capability | Detail |
|---|---|
| **Interprocedural taint** | Tracks across function call boundaries via argument-to-parameter, return-value, and local-alias propagation |
| **Field & container flow** | Flows through object field writes/reads and container element writes (lists, dicts, arrays) |
| **Sanitizer detection** | 18+ recognised sanitizer names (escape, quote, encode, validate, …); flows through them are neutralized |
| **CFG schema only** | The data model reserves CFG nodes and condition-gated transfer types, but the current scanner does **not** populate a branch CFG or claim branch-/path-sensitive flow |
| **Reflection & dynamic dispatch** | Detects common reflection APIs per language and emits *speculative* taint evidence with confidence scores. **Java:** `getMethod`, `getDeclaredMethod`, `getDeclaredField`, `getField`, `getDeclaredConstructor`, `getConstructor`, `forName`, `invoke`, `newInstance`, `MethodHandles.lookup()`. **Python:** `getattr`, `setattr`, `__import__`, `importlib.import_module`, `vars`, `type`, `eval`, `exec`, `compile`. **C#:** `GetMethod`, `GetMethods`, `GetConstructor`, `GetConstructors`, `GetType`, `Invoke`, `CreateDelegate`, `Activator.CreateInstance`, `Assembly.Load`, `Assembly.LoadFrom`, `Assembly.LoadFile`, `Type.InvokeMember`. **JavaScript/TypeScript:** `eval`, `Function`, `require()` of a variable, and dynamic property dispatch (`obj[name]()`). |
| **Framework lifecycle sources** | Spring (`@RequestParam`, `@PathVariable`, `@RequestBody`), Django (`request.GET/POST/META`), ASP.NET (`[FromQuery]`, `[FromRoute]`, `[FromBody]`) treated as taint sources |
| **Route parameter taint** | URL path parameters (`/user/{id}`) tainted automatically and mapped to function arguments |
| **Response dataflow** | Tracks tainted data into response objects (`JsonResponse`, `ResponseEntity`, `Ok`/`BadRequest`), flagging XSS risk |

The data-model types behind these — `TaintSymbolRef`, `TaintTransferEdge`,
`ReflectionFact`, and the `transfer_kind` values — are documented in
[models.md](models.md#pydantic-data-models-vvaharnessmodels).

---

## 11. Limitations (read before you trust output)

The same limitations the [README](../README.md#limitations-read-before-you-trust-output)
lists, with the detail behind each one.

### Reading the output

- **LLM-generated, non-deterministic.** Findings and fixes are triage candidates,
  not confirmed vulnerabilities or production-ready patches — human review is
  required. Two runs may differ, and VVAH can report issues that are not real as
  well as miss issues that are.
- **Severity is CVSS-derived.** Findings are labelled Critical /
  High / Medium / Low / Info, with the scored tiers taken straight from the CVSS
  3.1 base-score band (Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low
  0.1–3.9), so the label can never disagree with the vector; Info covers findings
  with no demonstrated exploit path. The base score (0–10) is reported verbatim.
- **No compilation or execution.** Detection is static parsing plus model review:
  vvaharness does not compile, build, or run the repository under scan, so no
  finding is confirmed by executing code. The only agent tool that could run
  commands is `Bash`, which no shipped profile grants — adding `- Bash` to a
  `via: cli` role's `allowed_tools` is an explicit operator choice. Exploit
  verification generates traffic, but against a target the operator is already
  running, and it never builds the repository.
- **No published accuracy numbers yet.** Precision/recall figures are not yet
  published, so calibrate against your own codebase.
- **Coverage is bounded, not complete.** A completed run does not mean the whole
  repository was reviewed. Per-stage caps on threats, entry points, sinks and
  findings trim the input on a large repository rather than failing the run, and a
  deep-dive chunk that fails or times out is recorded as a coverage gap while the
  scan still completes. The coverage backstop in
  [§10](#10-capabilities-that-ride-on-top) adds unrecognised files back but is
  best-effort, with documented skip classes.
- **Structured taint evidence covers Python, Java, C#, JavaScript, and
  TypeScript.** Those languages produce structured S0 taint evidence where
  usable specs exist. Go gets call-graph reachability and field/container
  facts, but no interprocedural propagation facts. A language without an S0
  plugin, Rust among them, receives no static seed, and the later LLM stages
  still run over it.
- **No rules-mode S0 corpus is bundled.** `taint.yaml` enables S0 in rules mode,
  and without operator-supplied source/sink rules it returns an empty seed and
  the pipeline continues. `default.yaml` and `full.yaml` enable S0 in LLM mode
  instead — a model-annotated seed rather than a rules-based one, which spends
  tokens.
- **Voting's sampling diversity is not always tunable.** The `cli` backend runs
  once, leaving the deterministic s5 prefilter as the main false-positive
  defence. Anthropic SDK models that reject `temperature`, and OpenAI-compatible
  endpoints that drop it, still execute every configured run — the provider
  samples at its own default, so runs diverge and voting works, you just cannot
  dial the diversity.

### How it touches your code

- **Enabled remediation modifies the target.** The `default` and `taint`
  profiles disable S10/S11; `full` and `sdk` still enable them. S10 enabled by
  config or `--remediate` can write fixes into the scanned repository (see the
  s10 note in [§2](#2-pipeline-stages)). `--stop-after s9` explicitly skips both
  stages with any profile.
- **Review remediation fixes before you rely on them.** The remediation agent
  proposes — and in fix mode applies — code changes, but vvaharness does **not**
  compile, build, or run tests against the patched tree: Step 11 grades fixes
  with an adversarial model panel and deterministic fact tools, never by
  executing them. Always review the generated fixes and build/test them yourself
  before merging.
- **Elevated privilege.** vvaharness assumes an authorized operator running
  against a repository they trust; scanning untrusted or malicious code can
  expose host credentials, files, or other risk. If you must scan a less-trusted
  or sensitive target, apply the compensating controls in
  [`security.md` → Hardening for less-trusted or sensitive targets](security.md#hardening-for-less-trusted-or-sensitive-targets).
- **Exploit verification (S6) is Beta, and API only.** When armed it sends real
  HTTP requests to a running target, addressed in code to a loopback host, which
  fixes where it sends but not what is listening there, so confirming the target
  is yours to do. Exploit verification is **not read-only**. `POST` is always
  permitted and all four shipped profiles set `allow_state_changing_methods: true`
  (the registered default is `false`), so an armed run can create records, trigger
  jobs and modify existing resources on the target. `DELETE` additionally requires
  `safe_mode: false`, which no shipped profile sets. Arming EV is itself live
  traffic: the reachability pass calls every distinct path in the collection
  before any finding is selected. Point it only at a disposable local instance you
  are authorised to attack. "API only" means it works from a Postman v2 /
  OpenAPI 3.0 / Swagger 2.0 collection you supply and skips any finding with no
  endpoint in that collection, so active coverage is bounded by the collection. It
  is positive-only: a non-confirmation is *not proven*, not *safe*. See
  [exploit-verification.md](exploit-verification.md) for the full scope, the
  classes it never live-tests, and what is left to manual review.

### Route and stage behaviour

- **`via: deepagents` is valid on every model role** — `models.remediate`,
  `models.validate`, the agentic detection roles (`preprocess`, `verify`), the
  single-shot detection roles (`autoexclude`, `graph_annotate`, `threatmodel`,
  `decompose`, `deepdive`, `dedup`, `chain`), and the exploit-verification roles
  (`classify`, `mapper`, `attacker`, `judge`). See [models.md](models.md) for the
  full role/backend matrix.
- **Validation accepts `via: openai`; remediation fix mode does not.** Validation
  routes a legacy `via: openai` role onto
  `via: deepagents` with the OpenAI provider, so it runs rather than aborting.
  Remediation *fix mode* needs the `Edit`/`Write` tools that only `via: cli`,
  `via: sdk`, and the repo-confined `via: deepagents` backends expose. An
  in-scan `via: openai` remediate role still runs in fix mode — it warns and
  then errors per finding. For usable output, run the standalone `remediate`
  command with `--mode report-only`, or switch the role to `via: cli`,
  `via: sdk`, or `via: deepagents`. Detection (S1–S9) and report-only
  remediation run on `via: cli`, `via: sdk`, or `via: openai`.
- **Missing post-scan credentials are a warning, not a fatal error.** If
  `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` is absent but only S10 or S11 needs it,
  preflight emits a `WARN` and skips that stage while S1–S9 detection still runs.
  A credential missing for a detection role remains fatal.
- **Validation is capped unless explicitly uncapped.** Both standalone
  and in-scan validation apply `step_validate.max_findings`. Standalone
  `vvaharness validate --all` bypasses the cap for every validatable status;
  terminal `validated` DTOs stay excluded.

### Planning a run

- **Token-hungry.** There is no global spend cap. `max_budget_usd` is
  route-specific: compatible Claude CLI and Claude Agent SDK paths enforce it,
  while raw SDK, OpenAI, and DeepAgents paths ignore it. Run
  `vvaharness estimate` before a scan, scope with `--repo <subdir>` or
  `--stop-after`, and treat token accounting as reporting, not enforcement.
- **`--resume` re-runs S4 in full.** S4 writes a single checkpoint only after
  every deep-dive chunk has finished, so an interrupted run resumes S0–S3 but
  repeats all of S4 — including the chunks that had completed. S5 and S6 repeat
  with it, because their checkpoints are only reusable when the S4 (and S5)
  checkpoint they depend on was restored. Prompt caching does not soften this:
  cache entries are short-lived — 5 minutes on Anthropic routes — so a later
  resume pays full token cost. (S2 likewise re-runs on resume when its threat
  model came back empty.)
- **Checkpoints over 100 MiB are silently dropped.** A stage payload above
  104,857,600 bytes is not persisted: the stage still completes, and the only
  signal is a `WARN` on stderr — no error, no run-manifest entry. The cap is
  not configurable. On a very large repository the S1 context package can
  exceed it, in which case `--resume` re-runs S1 every time. Reduce scope with
  `exclude_dirs`, `--auto-step1`, or `--stop-after`.
