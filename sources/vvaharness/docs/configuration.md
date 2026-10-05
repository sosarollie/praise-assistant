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

# Configuration Reference

All knobs live in `config.yaml`. Secrets are read from env vars via `${VAR}`
expansion — the CLI auto-loads a trusted `.env` from the exact working directory
or user home — so never commit tokens into `config.yaml`.

**You do not need most of this page.** Pick a shipped profile, put secrets in
`.env`, and stop. Come back when you want to change a specific behaviour.

### The knobs people actually change

| Want to… | Set |
|---|---|
| scan without touching the target's source | The packaged default already sets `step_remediate.enabled: false` + `step_validate.enabled: false`. `--stop-after s9` explicitly skips S10/S11 with any profile. |
| spend less | `step4.parallel` ↓, `step4.max_findings_per_run` ↓ (see [`step4`](#step4--deep-dive) for what lowering it discards and which report line shows the cost), `step3.catchall_enabled: false` on huge third-party trees |
| catch more, spend more | `step3.catchall_mode: all`, `step6_verify.min_confidence` ↓, add specialist lenses |
| cut false positives | `step4.runs` ≥ 3 **with a temperature-capable deepdive** (see [models.md](models.md)), `step6_verify.min_confidence` ↑ |
| quieten the console | `scan_progress.style: stage_only` for stage start/done lines, `summary_only` for the final summary, or `scan_progress.enabled: false` (the default profile already ships `compact`; `taint` ships `verbose`) |
| work behind a private gateway | `ANTHROPIC_BASE_URL` in `.env`; `ca_cert` under `sdk:` / `cli:` if it needs a private CA |
| stop a route rejecting cache fields | `cache_markers: "off"` — governs the `sdk`/`openai` routes (a no-op on `via: cli`, which sends no cache fields); it does **not** silence `via: deepagents` markers (see [Prompt caching](#prompt-caching-cache_markers--cache_route--cache_min_block_tokens)) |
| get cache markers on an unrecognised but Anthropic-compatible gateway | `cache_route: anthropic` |

### Contents

**Getting started** — [Setting up your config](#setting-up-your-config) ·
[Which file loads](#1-which-file-the-tool-loads-resolution-order) ·
[Pick a profile](#2-pick-a-shipped-profile) ·
[Secrets in `.env`](#4-secrets-go-in-env-never-in-the-yaml) ·
[Validate first](#5-validate-before-scanning)

**Cross-cutting** — [Top-level sections](#top-level-sections) ·
[Prompt caching](#prompt-caching-cache_markers--cache_route--cache_min_block_tokens) ·
[Backend transport](#backend-transport-sdk--openai--cli)

**Per stage** — [`step0`](#step0--static-ast-seed) ·
[`step1`](#step1--repo-intake--file-inventory) ·
[`step2`](#step2--threat-model) ·
[`step3`](#step3--decompose) ·
[`step4`](#step4--deep-dive) ·
[`step5`/`step6`](#step5_prefilter--step6_verify) ·
[`step6_exploit_verification`](#step6_exploit_verification--live-exploit-verification-s6-ev) ·
[`step7`/`step8`](#step7_dedup--step8) ·
[`step_remediate`](#step_remediate--remediation-agent-s10) ·
[`step_validate`](#step_validate--validator-s11)

**Everything else** — [`inject`](#inject--optional-context-inputs) ·
[`rules`](#rules--s4-cwe-knowledge-overlays) ·
[`scan_progress`](#scan_progress--filechunk-observability) ·
[`output`](#output--cleanup-and-coverage-appendix)

## Setting up your config

`vvaharness` ships ready-to-run **profiles** — you do **not** author a config
from a blank file. "Setting up your config" means: **pick a shipped profile,
point the tool at it, and put your secrets in `.env`.** Customise only by
*copying* a profile and editing the knobs you care about — starting from a
shipped profile (never hand-writing one) is the supported path.

### 1. Which file the tool loads (resolution order)

The active config is resolved once, in this order:

1. **`--config <path>`** — an explicit profile/file (highest precedence).
2. **`./config.yaml`** — auto-detected if present in the directory you run from.
3. **the packaged `default.yaml`** — the built-in fallback.

Then, if a **`config.local.yaml`** sits next to the chosen file, its keys are
deep-merged on top (git-ignored — your machine-local overrides). Partial files
are fine: any step-knob you omit is filled from built-in defaults, so a config
never has to be exhaustive.

> The overlay can change security-relevant settings (model routing, `base_url`,
> TLS `ca_cert`, tool permissions), so the merge is **announced** on every
> command — the loader logs `config overlay: <path> applied (overrides: …)` with
> the leaf key paths it changed (endpoint keys show the resolved host, TLS keys
> the value, credential keys only `set`/`unset`), and its SHA-256 is recorded in
> `run_manifest_*.json`. It resolves next to your `--config` path (operator-owned),
> never the scanned target. For a reproducible run that honours **only** the
> selected config, set **`VVAHARNESS_NO_LOCAL_CONFIG`** (to any value) to skip
> the overlay. The overlay itself must pass a trust check: it must be owned by
> the invoking user (or root) and must not be group/world-writable, or loading
> is refused with a `config overlay … is not trusted` error (a
> `ConfigPolicyError`) — fix with `chmod go-w config.local.yaml` (and `chown` it
> to yourself if needed), or skip the overlay as above.

> **Trust boundary — config/`.env` inside the scan target is refused.** The
> scanned repository is untrusted input. If the resolved `config.yaml` or exact
> cwd/home `.env` lives **at or under the `--repo` target**, it is ignored — the
> tool falls back to the packaged default and prints a `WARN` — so configuration
> committed into a repo you are scanning cannot redirect model endpoints,
> credentials, or TLS settings. The two halves have different reach: the `.env`
> half runs before subcommand dispatch and so applies to **every** command,
> while the config half is enforced by `scan` in single-`--repo` mode only —
> `remediate`, `ev-replay`, `validate`/`s11` and `--repo-file` batch mode resolve
> `--config` without it, so keep config outside the target rather than relying on
> the gate there. The CLI never searches arbitrary ancestor
> directories for `.env`, and it ignores a cwd/home `.env` whose file or parent
> directory is not user-owned or is group/world-writable. These ownership and
> permission checks apply on POSIX platforms and are skipped where the OS does
> not expose them (e.g. Windows) — there, keep `.env` and config out of
> shared-writable locations yourself. The `config.local.yaml` trust gate
> inspects the overlay file itself, not its parent directories; setting
> `VVAHARNESS_NO_LOCAL_CONFIG` is the deterministic way to rule the overlay out
> of a hardened or reproducible run. Your own copy-then-edit
> `./config.yaml` in an operator-owned directory is unaffected. To deliberately
> load config from inside a target you trust, set
> `VVAHARNESS_ALLOW_CWD_CONFIG=1`; this does not bypass `.env` ownership or mode
> checks. The effective config path, any applied `config.local.yaml` overlay, and
> the loaded `.env` are echoed to stderr, and the SHA-256s of the config profile
> and `config.local.yaml` overlay are recorded in `run_manifest_*.json` for
> auditability.

### 2. Pick a shipped profile

All four live in `vvaharness/config/profiles/`:

| Profile | Backends | Auth you need | Use when |
|---|---|---|---|
| **`default.yaml`** | S0 enabled (`callgraph_detection: llm`); S1–S9 all `via: deepagents` (`provider: anthropic`; `claude-opus-4-7`, S1 `preprocess` `claude-sonnet-4-6`); **S10/S11 disabled**, with DeepAgents model settings retained for opt-in use | any one of `ANTHROPIC_SDK_API_KEY` (highest precedence, carries the `sdk:` gateway/mTLS knobs), `ANTHROPIC_API_KEY`, or `ANTHROPIC_AUTH_TOKEN` — one credential covers every enabled stage, exploit verification included — all four of its roles ship `via: deepagents` (`provider: anthropic`), so arming EV adds no new credential here | The built-in default: detection through S9, without automatic remediation or validation. |
| **`sdk.yaml`** | S0 disabled; every model role spelled `via: sdk`. Detection uses the Anthropic Python SDK; S10 fix and S11 use Claude Agent SDK paths. No Bash. | `ANTHROPIC_SDK_API_KEY` for S1–S10; S11 pins external `claude` and uses Claude login/OAuth or standard Anthropic auth (or one standard credential can cover every stage via the sole-SDK fallback) | You want every role on one SDK credential with no Bash anywhere. Note it ships `step4.runs: 1`, so **majority voting is off** despite its temperature-capable deepdive — use `full.yaml` (`runs: 3`) for voting, or raise `step4.runs` here. |
| **`full.yaml`** | S0 enabled; **as shipped** every *detection* role is `via: deepagents` (Anthropic), with commented `cli` / `sdk` / `openai` alternatives beside the roles that accept them. Its exploit-verification roles all ship `via: deepagents`, and are the cross-vendor example: `attacker` / `classify` / `mapper` on `provider: anthropic`, `judge` on `provider: openai`. Ships `step4.runs: 3` / `vote_threshold: 2` — the only shipped profile with s4 voting on | For a detection-only run, one Anthropic credential (`ANTHROPIC_SDK_API_KEY`, `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`) covers it. **Arming exploit verification additionally requires `OPENAI_API_KEY`**, with nothing to uncomment — its `judge` is already `provider: openai`. Uncomment a `via: cli` role and you must add Claude CLI auth | You want s4 majority voting, or a template to spread roles across backends. |
| **`taint.yaml`** | S0 enabled (`callgraph_detection: rules`); S1–S9 all `via: deepagents` (Anthropic); **S10/S11 disabled** | One Anthropic credential (`ANTHROPIC_SDK_API_KEY`, `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`) — no `claude` binary needed, and that one credential also covers an EV-armed run, since all four exploit-verification roles ship `via: deepagents` (`provider: anthropic`). Supply generated source/sink rules for a non-empty rules-mode S0 seed. | Taint-first source→sink scanning when S0 has usable specs. With a non-empty seed, `step1.mode: gap_fill` skips agentic S1 unless the repo has >500 source files, a web-api/web-app/service classification, and either zero sinks or ≥10 entry points with <5 sinks; an empty seed takes the agentic S1 path. `catchall_mode: all` (with `catchall_deduct_lens_coverage: true`, the catch-all sweep runs after the specialist passes). Use: `--config vvaharness/config/profiles/taint.yaml`. |

> **No shipped profile grants `Bash`.** Only the `cli` backend can shell out; to
> enable it, add `- Bash` to a `via: cli` role's `allowed_tools` (e.g. `step1`,
> `step6_verify`) in your own copy — and only for a target you trust.

Not sure which? Run **`vvaharness setup`** — it inspects the credentials you
have and recommends a profile.

#### Side by side, on the settings that differ

| | `default` | `sdk` | `full` | `taint` |
|---|---|---|---|---|
| S0 static seed | on, `llm` | off | on, `llm` | on, `rules` |
| detection backend | all `deepagents` | all `sdk` | all `deepagents` | all `deepagents` |
| s4 voting (`runs`/`threshold`) | 1 / 1 | 1 / 1 | **3 / 2** | 1 / 1 |
| deepdive temperature | none | 0.4 | none | none |
| `step3.catchall_mode` | `reachable_only` | `all` | `all` | `all` |
| S10 remediate | off | **on** | **on** | off |
| S11 validate | off | **on** | **on** | off |
| `scan_progress` | on, `compact` | off | on, `compact` | on, `verbose` |

Two things this table is meant to make obvious. **S10 remediation and S11
validation are on only in `sdk` and `full`; both are off in `default` and
`taint`.** When enabled, S10 runs in fix mode and can edit files in the scanned
repository — pass `--stop-after s9` to explicitly skip both stages with any
profile. And **voting is not just `runs: 3`**:
it needs deepdive runs that can disagree. Only `sdk` pins a temperature
(`0.4`), and it ships `runs: 1`; the other three route deepdive via
`deepagents`, which never sends a `temperature` at all — so `full` votes on
provider-default sampling (all three runs still execute; a NOTE is printed),
while `default` and `taint` show `1 / 1` because they ship `runs: 1`. See [models.md](models.md#model-selection--backends).

### 3a. Run a profile as-is

```bash
# Use a specific profile:
vvaharness scan --repo /path/to/target --config vvaharness/config/profiles/sdk.yaml

# Or omit --config to use the packaged default.yaml:
vvaharness scan --repo /path/to/target
```

### 3b. Customise it (copy-then-edit)

```bash
cp vvaharness/config/profiles/full.yaml ./config.yaml
# edit ./config.yaml — e.g. swap model ids, change a role's `via`, tune step4.runs
vvaharness scan --repo /path/to/target        # ./config.yaml is auto-detected
```

The most common edit is the `models:` block. Detection roles use
`{id: <model>, via: cli|sdk|openai|deepagents, provider: anthropic|openai}` —
`provider` applies to `via: deepagents` only and defaults to name inference
(an id containing `claude` → Anthropic). `deepagents` is valid on every model
role: the single-shot detection roles (`graph_annotate`, `autoexclude`,
`threatmodel`, `decompose`, `deepdive`, `dedup`, `chain`), the agentic
detection roles (`preprocess`, `verify`), and
remediation and validation. Validation has a nested
`orchestrator` plus persona model IDs. See [models.md](models.md) for the
exact schema and role/backend matrix.

### 4. Secrets go in `.env`, never in the YAML

The profiles reference env vars with `${VAR}` (or `${VAR:-default}`); an unset
var expands to empty (or the default), so a profile with no gateway/cert vars
set just runs against the public endpoint.

> **One guardrail:** a `${VAR}` whose name contains `API_KEY`, `APIKEY`,
> `TOKEN`, `SECRET`, `PASSWORD`, `PASSWD`, `CREDENTIAL`, or `PRIVATE_KEY`, or
> an underscore-delimited segment ending in `AUTH` (so `OAUTH` counts,
> `AUTHOR` does not), may only be interpolated into `sdk.api_key`,
> `openai.api_key`, `batch.git_token`, or `output.ingest_token`. Anywhere else
> the config refuses to load (`ConfigPolicyError`) — even when the variable is
> unset — so a profile fails the same way on every machine. Remedies: move the
> value to one of those keys, rename the variable, or write the value
> literally instead of interpolating.

Copy `.env.example` to `.env` and fill in what your chosen profile needs:

| Backend / area | Env vars |
|---|---|
| SDK (`via: sdk`) | Direct detection: `ANTHROPIC_SDK_API_KEY`, `ANTHROPIC_SDK_BASE_URL`, `ANTHROPIC_SDK_CA_CERT`, `ANTHROPIC_SDK_CLIENT_CERT`; S10 translates key/base; S11 pins external `claude` and uses ambient Claude login/OAuth or standard `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_BASE_URL` (not the SDK-named key) |
| CLI (`via: cli`) | `CLAUDE_CODE_OAUTH_TOKEN` (or run `claude` → `/login`), `CLAUDE_CLI_CA_CERT` |
| OpenAI (`via: openai`) | `OPENAI_API_KEY` (required), `OPENAI_BASE_URL`, `OPENAI_CA_CERT` |
| DeepAgents (`via: deepagents` — S10/S11 and the detection roles that allow it) | Anthropic provider: `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`, optional `ANTHROPIC_BASE_URL`; OpenAI provider: `OPENAI_API_KEY`, optional `OPENAI_BASE_URL`. Also reads the matching `sdk:` / `openai:` block: `api_key` and `base_url` on every role, plus `verify_ssl` / `ca_cert` / `client_cert` on detection roles. CA trust: `SSL_CERT_FILE` / `SSL_CERT_DIR` on both vendors; the Anthropic branch deliberately ignores ambient `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS`, which only the OpenAI-compatible branch honours (see [Backend transport](#backend-transport-sdk--openai--cli)); mTLS: `VVAHARNESS_TLS_CLIENT_CERT` (+ optional `VVAHARNESS_TLS_CLIENT_KEY`) |
| Batch / git clone | `GITHUB_TOKEN`, `GIT_BASE_URL` |

Only credentials for the enabled routes are required. The `*_BASE_URL` /
`*_CA_CERT` / `*_CLIENT_CERT` vars are for private gateways and mutual TLS.
Certificate env values are best given as absolute paths: after `${VAR}`
interpolation the value lands in the profile's transport block, and a
relative value there resolves against the **selected YAML config's
directory** (not `.env`'s location or the process working directory);
network/UNC paths are refused. See
[Backend transport](#backend-transport-sdk--openai--cli).

Beyond credentials and transport, a few diagnostic variables are read from the
environment only (they have no config-file equivalent):

| Variable | Read by | Effect |
|---|---|---|
| `VVAHARNESS_LOG_LEVEL` | `util/logs.py` | Opt-in internal diagnostic logging: attaches a redacting handler to the `vvaharness` package logger at this level (`critical`, `error`, `warning`, `info`, `debug`). Unset or unrecognised = logging stays off. |
| `VVAHARNESS_LOG_FILE` | `util/logs.py` | Destination file for that diagnostic log; unset (or unopenable) falls back to stderr. |
| `VVAHARNESS_SETTINGS_FILE` | `remediation_agent/rule_paths.py` | Overrides the path of the `settings.json` that records the operator-configured remediation-rules `inputs_dir` (default `$XDG_CONFIG_HOME/vvaharness/settings.json`, i.e. `~/.config/vvaharness/settings.json`). |
| `VVAHARNESS_DEBUG_LOG` | `remediation_agent/plugin_runner/__init__.py` | Path to a file that collects DeepAgents run diagnostics (structured-output / terminal-state debug lines are appended). No-op when unset. |
| `VVAHARNESS_DEBUG_MEM` | `pipeline/stages/callgraph_engine/_rules.py` | Set to `1` to enable memory profiling (`gc.collect()` + `tracemalloc`) of S0 rule-pack loading; off by default because it adds ~3s per scan. |

### 5. Validate before scanning

```bash
vvaharness doctor    # checks readiness + live-probes detection transports
vvaharness setup     # full readiness report + profile recommendation
```

The current doctor probe does not execute the S10/S11 Claude Agent SDK Harness;
for `sdk.yaml` / `full.yaml`, separately verify external `claude` and either
Claude login/OAuth or standard Anthropic auth for S11.

`doctor` resolves the **same** config a scan would (it honours `--config`), but
its connectivity probes validate the detection transports rather than every
post-scan launcher; apply the Agent-SDK S11 caveat above.

## Top-level sections

| Section | Purpose | See |
|---|---|---|
| `models:` | Per-role model/backend routing; nested validation orchestrator/personas | [models.md](models.md) |
| `sdk:` / `openai:` / `cli:` | Backend transport (TLS/proxy). See [Backend transport](#backend-transport-sdk--openai--cli) below. | [SETUP_GUIDE.md](SETUP_GUIDE.md) |
| `step0:` | Static AST seed enablement, rules/LLM detection mode, optional external rule files | below |
| `step1:` … `step8:` | Per-stage scan tuning (cost, depth, precision) | below |
| `step6_exploit_verification:` | Live exploit-verification (S6-EV) pass — **Beta**, API-only, localhost-only, and inert unless `EV_API_COLLECTION` is set. All four shipped profiles carry the block, plus a `models.exploit_verification` role set | [below](#step6_exploit_verification--live-exploit-verification-s6-ev) · [exploit-verification.md](exploit-verification.md) |
| `step_remediate:` / `step_validate:` | Remediation Agent (s10) and validator (s11) tuning | below |
| `inject:` | Optional CVE/controls/CMDB context plus remediation policy/playbook paths | [outputs.md](outputs.md#cmdb-enrichment) |
| `rules:` | Optional external S4 CWE knowledge-base overlays | below |
| `scan_progress:` | File/chunk observability enablement and output style | below |
| `batch:` | `git_token`, `git_base_url`, `skip_repo_patterns` | [repos-csv.md](repos-csv.md) |
| `output:` | Cleanup preservation and unreachable-file appendix | [outputs.md](outputs.md) |
| `pricing:` | Operator-supplied model price table for run-cost accounting (`pricing.file`; env `VVAHARNESS_PRICING_FILE` overrides) | [outputs.md](outputs.md) |
| `cache_markers:` / `cache_route:` / `cache_min_block_tokens:` | Prompt-cache marker behaviour. `cache_markers` is read by the `sdk` and `openai` routes; `cache_route` and `cache_min_block_tokens` are read by `sdk` only. `via: cli` and `via: deepagents` read none of the three | [Prompt caching](#prompt-caching-cache_markers--cache_route--cache_min_block_tokens) below |

## Prompt caching (`cache_markers` / `cache_route` / `cache_min_block_tokens`)

Three **top-level** scalars, not per-stage, because all three describe the
model route rather than any one stage.

| Key | Default | Purpose |
|---|---:|---|
| `cache_markers` | `on` | Kill switch for the prompt-cache markers placed on the `sdk` route, and for the `openai` route's `prompt_cache_key`. Set to `off` to suppress them there. It does **not** reach `via: deepagents` (see the caveat below) and there is nothing for it to suppress on `via: cli`, which places no markers. |
| `cache_route` | `auto` | How the endpoint's cache-marker regime is decided: detect it from the hostname (`auto`), declare it outright (`anthropic` / `vertex` / `bedrock`), or force no markers (`none`). Case-insensitive. |
| `cache_min_block_tokens` | unset | Global override of the per-model minimum cacheable size. Leave unset to use the published per-model minimums (table below); set an integer only for a gateway that enforces its own floor. |

**On the `sdk` route, every marker passes the same three gates, in order:** the
`cache_markers` kill switch, then the route capability decided by `cache_route`,
then the minimum cacheable size. That includes the system-prompt block. The
`openai` route has only the first gate — `cache_markers` toggles its
`prompt_cache_key` and it places no `cache_control` markers to gate — and
`via: cli` has none of the three, because that route never reaches the Messages
API and a caller's markers are dropped with nothing to cache. A call that
fails any gate is sent with the same content, same order, no marker, so routes
with an implicit provider-managed cache still benefit from the stable prefix.

> **`via: deepagents` honours the kill switch through the `sdk:` block.** On
> that route every marker — the middleware's three block-level breakpoints
> (system prompt, tool definitions, conversation tail) and the shared-prefix
> breakpoint — is gated on one `cache_markers` key read from the **`sdk:`
> transport block**, not on this top-level scalar. On a strict
> Anthropic-Messages gateway that rejects `cache_control` fields, set BOTH:
> this top-level `cache_markers: off` for the `cli`/`sdk`/`openai` roles, and
> `sdk: { cache_markers: off }` for the `via: deepagents` roles. The residual
> asymmetry (two keys, one intent) is deliberate — the route reuses the
> existing sdk-block key rather than introducing a third.

**`cache_route` — telling the tool what your endpoint is.** With the default
`auto`, the endpoint is classified by its hostname, failing closed to *no
markers* on anything unrecognised — a rejected request field fails a scan,
while an ignored one only costs an optimisation. That fail-closed default has a
knowable cost: a corporate gateway that is in fact Anthropic-Messages-compatible
gets no markers and no caching benefit, and no hostname rule could ever
discover that it is safe. `vvaharness setup` names this whenever it detects a
gateway it does not recognise, so the choice is in front of you before a scan
spends rather than after; put the key in a `config.local.yaml` beside your chosen
profile (git-ignored, deep-merged over it) rather than editing a shipped profile,
and confirm it with `vvaharness doctor --cache-probe`.
`cache_route: anthropic` is the deliberate opt-in
for exactly that gateway; `vertex` and `bedrock` likewise force those
classifications, and `none` forces no markers at all — same effect as an
unrecognised host, but chosen on purpose. Only the `via: sdk` transport reads this
key — `via: cli` places no markers and `via: openai` has no marker regime to
declare — so it is that route's endpoint the setting describes.

Two shipped profiles pre-declare `anthropic`: `sdk.yaml` and `default.yaml`. Note
what that does and does not buy. With `sdk.base_url` unset, `auto` already resolves
to the Anthropic regime, so the declaration changes nothing; it only bites when
`ANTHROPIC_SDK_BASE_URL` names a gateway `auto` cannot classify, where it forces
the Anthropic regime rather than forfeiting caching. `full.yaml` and `taint.yaml`
leave the key unset and so keep the fail-closed behaviour there — though as
shipped neither profile has an active `via: sdk` role, so the unset key only
starts to matter once you uncomment one of `full.yaml`'s `via: sdk`
alternatives and point `sdk.base_url` at a gateway `auto` cannot classify. On any profile that declares it, repointing `sdk.base_url` at a gateway that
rejects `cache_control` means setting it back to `auto`. The cost of
leaving it unset can be material — on one enterprise gateway that was in fact
Messages-compatible, staying fail-closed forfeited roughly a fifth of the
spend that caching would have repriced (a single-gateway, single-target
observation; your ratio depends on prompt shapes and traffic). Rather than
guessing, ask the route empirically: `vvaharness doctor --cache-probe`
reports what each model route actually does with markers before you commit a
scan's budget to the answer.

```yaml
cache_markers: "off"        # quote it — see the note below
cache_route: anthropic      # only for a gateway you know honours cache_control
```

> **Quote the value.** In YAML, an unquoted `off` parses as the boolean `false`,
> not the string `"off"`. For `cache_markers`, both are accepted, along with
> `false`, `no` and `0`, so either spelling disables markers — but quoting makes
> the intent obvious to the next reader. The same footgun applies to
> `cache_route`: a bare `no` or `off` becomes boolean false and is treated as
> `"none"`. A bare `none`, on the other hand, stays the string `"none"` and
> works unquoted — only `null` and `~` parse to nothing in YAML.

**When to turn markers off.** Providers differ in whether they accept an
explicit cache marker, and a strict gateway can reject an unrecognised request
field outright rather than ignoring it. The route gate cannot protect a
*recognised* (or operator-declared) route from a gateway that silently strips
or rejects the field. If a scan starts failing with a rejected-parameter error,
set `cache_markers: off`; caching then relies on prefix stability alone, which
every route benefits from and which needs no marker. Remember the caveat
above: this top-level key covers the `cli`/`sdk`/`openai` roles only — a
`via: deepagents` role on the same strict gateway is switched off via
`sdk: { cache_markers: off }` in its transport block, per the callout above.

**Why a minimum size.** Providers enforce a per-model minimum cacheable size.
Below it, the provider silently caches nothing *and* the marker still consumes
one of the only **4 breakpoint slots** a request has — that wasted slot is the
entire reason the gate exists. The minimum is evaluated against the
**cumulative** prefix — tool schemas, the system prompt, and everything else
rendered before the marker, not the marked block alone — and sizes are
estimated with a margin that resolves doubt toward marking: a borderline
prefix is marked (at worst inertly) rather than losing a cache hit, and only
a prefix well below the floor is refused. By default the published per-model
minimum applies. The
sequence is **non-monotonic across releases**, so do not reason from version
order — check the table:

| Minimum (tokens) | Models |
|---:|---|
| 512 | Opus 5, Fable 5 |
| 1024 | Opus 4.8, Opus 4.1, Opus 4, Sonnet 5, Sonnet 4.6, Sonnet 4.5, Sonnet 4 |
| 2048 | Opus 4.7, Haiku 3.5 |
| 4096 | Opus 4.6, Opus 4.5, Haiku 4.5 |

A model the table has never seen gets the largest published minimum (4096).
Setting `cache_min_block_tokens` to an integer replaces every row with one
global floor — do that only for a gateway that enforces its own minimum.

**What caching costs and saves.** On Anthropic-shaped routes a cache **read**
bills at **0.1×** the base input rate; a 5-minute cache **write** at **1.25×**;
a 1-hour write at **2×**. The 5-minute entry refreshes free on every hit, and
its lifetime is measured from the *start* of the request, so a stage that keeps
re-reading the same prefix keeps it warm for nothing. On the OpenAI route,
cached input is 0.1× on GPT-5-family models (set per-model `cache_read_per_mtok` under `models:` in your pricing table), GPT-5.6+ writes are 1.25×, and pre-5.6 models have no
write fee. Cost reporting falls back to these same fractions when the
operator's pricing table omits the cache rates; explicit rates — including an
explicit `0` — always win.

**The OpenAI route works differently — do not conflate the two.** There are no
`cache_control` breakpoints on OpenAI or OpenAI-compatible endpoints: caching
is automatic from 1,024 tokens over a byte-stable prefix. What vvaharness adds
there is a `prompt_cache_key`, a routing hint that biases load-balancing toward
a server already holding the prefix. The key is **sharded** so a single
high-fan-out stage cannot push all its traffic through one key and exceed the
provider's documented ~15-requests-per-minute-per-key guidance, and it is a
SHA-256 digest that by design contains no path, credential, or repository root.
`cache_markers: off` suppresses the key; `cache_route` does not apply on this
route.

**Bedrock deliberately gets no marker.** Anthropic models on Bedrock *do*
accept Anthropic-shaped `cache_control` on the InvokeModel path (the
`cachePoint` block is the Converse-API shape, which nothing here needs) — but
this package cannot build a SigV4-signed client, so a Bedrock-looking
`base_url` reached through it is necessarily some unverified intermediary. And
Bedrock reports cache usage under camelCase field names this codebase does not
read, so even a working marker would be recorded as zero in the cache totals —
though the unparsed-field note below names those keys when they appear.
Until both halves are verifiable, this route relies on prefix stability alone.
The escape hatch, for an operator fronting Bedrock with a Messages-compatible
gateway that normalises the usage fields, is `cache_route: anthropic`.

**Cache accounting under field names this tool does not parse.** Some gateways
report cache accounting under names the backends do not read — Bedrock's
camelCase `cacheReadInputTokens` / `cacheWriteInputTokens`, or an OpenAI-shaped
`prompt_tokens_details` block arriving on an Anthropic-shaped route. Absent
fields are coerced to zero, on its own indistinguishable from "no caching
happened". Each backend therefore checks the raw usage payload: the first
affected call (per distinct key-set) prints a stderr note **naming** the
unparsed keys — key names only, never values, filtered to a safe identifier
shape and capped — and every affected call is counted in that stage's
`cache_unparsed` token bucket. If you see the note, caching may well be
working but is **not meterable here**: cache reads will show as zero in the
token and cost accounting. The remedy is at the gateway — front the endpoint
with one that normalises usage to the standard field names. One residual blind
spot: on `via: cli` the true wire response lives inside the `claude`
subprocess and the envelope's usage is the CLI's own summary of it, so a
foreign field name may never reach this process at all — "no cache accounting
observable" remains a legitimate outcome on that route.

**Probing a route.** `vvaharness doctor --cache-probe` fires an A/B pair of
prefix-sharing calls for each of two prompt shapes and two thinking arms —
eight calls per `sdk`/`openai`/`cli` model route, and two per `deepagents`
route — reads the cache-write and cache-read counters from the usage fields
that route's backend parses, then classifies each pair: working, prefix
already warm, writes without reads, no reads, or no cache accounting at all. Before blaming the gateway for a zero-write/zero-read
pair on a `via: sdk` route, the probe asks the backend's **own marker gate**
whether a `cache_control` marker was ever placed on the call. When the gate
withheld it — cache markers switched off, an unrecognised route, or a prompt
below the model's minimum cacheable size — the verdict is the distinct
`anthropic_marker_withheld_by_gate`: the gateway was never asked to cache
anything, so there is nothing to investigate there; re-probe with a larger
prompt shape, or set `cache_route` / `cache_min_block_tokens` to change the
gate's decision. "Marker not honoured" is therefore reserved for the case
where this tool *did* place the marker and still observed no cache effect.
Even then, know the probe's limit: it establishes only what that route's
*parsed* usage fields show. An endpoint reporting cache usage under field
names this tool does not parse still reads as zero on both counters — the
unparsed-field note above fires during the probe too and names the keys when
they are visible — so treat "marker not honoured" as a prompt to inspect the
gateway and its usage accounting, not proof the marker was dropped. The probe
spends real tokens, prints an estimate first, and never runs as part of a
scan.

## Backend transport (`sdk:` / `openai:` / `cli:`)

Each backend has its own transport block holding TLS/proxy knobs. **Every key
is optional** — when its `${...}` env var is unset it expands to empty and
injects nothing, so the default profile runs with just an API key. The `sdk:`
and `openai:` blocks are consulted by roles routed to that backend (`via: sdk`,
`via: openai`) **and** by `via: deepagents` roles resolving to the matching
vendor; the `cli:` block is consulted only by `via: cli`.

| Key | `sdk:` | `openai:` | `cli:` |
|---|---|---|---|
| `api_key` | `${ANTHROPIC_SDK_API_KEY}` | `${OPENAI_API_KEY}` | — (CLI native auth) |
| `base_url` | `${ANTHROPIC_SDK_BASE_URL}` | `${OPENAI_BASE_URL}` | — (CLI native, `ANTHROPIC_BASE_URL`) |
| `verify_ssl` | `true` (set `false` to disable TLS verification) | `true` | `true` |
| `ca_cert` | `${ANTHROPIC_SDK_CA_CERT}` | `${OPENAI_CA_CERT}` | `${CLAUDE_CLI_CA_CERT}` |
| `client_cert` (mTLS) | `${ANTHROPIC_SDK_CLIENT_CERT}` (direct SDK detection transport, and `via: deepagents` detection roles resolving to Anthropic) | read only by `via: deepagents` detection roles resolving to OpenAI-compatible (`via: openai` itself does not consume it) | not supported |
| `no_proxy` | comma-separated hosts to bypass the proxy | same | exported as `NO_PROXY`/`no_proxy` into the subprocess |

`verify_ssl` accepts a native YAML boolean or a string boolean (`"false"`,
`"true"`, `"0"`, `"1"`, `"no"`, `"yes"`, …). A string is coerced to a real
boolean, so an environment-templated value like `verify_ssl: ${VERIFY_SSL:-false}`
disables verification as intended rather than being read as a CA-bundle path.
Any other string is treated as a CA-bundle path.

A configured `ca_cert` **wins over `verify_ssl: false`, uniformly on every
route** (`sdk`, `openai`, and `via: deepagents`): a profile carrying both
verifies against the private CA rather than running unverified. On
`via: sdk`/`via: openai` a `ca_cert` that points at a **missing** file warns
and falls back to the block's `verify_ssl` value; on `via: deepagents` a
`ca_cert` that does not resolve to a real file fails the run instead. A
**malformed** CA bundle fails the run on every route (fail closed) rather
than silently dropping the operator's CA pin and continuing on system trust.

`via: deepagents` reads the transport block matching its **resolved vendor** —
`sdk:` for Anthropic, `openai:` for OpenAI-compatible. It never reads the
`cli:` block, and never `organization`. On the cache side it reads exactly one
key: the route gates all of its prompt-cache markers on the `sdk:` block's
`cache_markers`
(see [Prompt caching](#prompt-caching-cache_markers--cache_route--cache_min_block_tokens));
`cache_route` and `cache_min_block_tokens` are still ignored.
From the matching block it takes `api_key` and `base_url` on every deepagents
role; the detection roles also take `verify_ssl`, `ca_cert`, `client_cert`,
and `no_proxy` from it, while S10/S11 take their TLS material from the process
environment instead (`SSL_CERT_FILE` for CA trust,
`VVAHARNESS_TLS_CLIENT_CERT` for mTLS) and do not read `no_proxy` at all. A
detection role's `no_proxy` scopes client construction the same way it does on
`via: sdk`/`openai`, with one caveat: on the Anthropic-routed branch it takes
effect only when the HTTP clients are built at construction time — i.e. when
the block also configures TLS material or the credential is an Anthropic
OAuth token; otherwise the SDK builds them lazily, out of reach. The vendor comes from the role's
`provider` key, inferred from the model id when absent:

```yaml
models:
  threatmodel: {id: gpt-5.5, via: deepagents, provider: openai}   # detection, single-shot
  remediate: {id: claude-opus-4-8, via: deepagents, provider: anthropic}
  validate:
    orchestrator: {id: claude-opus-5, via: deepagents, provider: anthropic}
    security_architect: {id: claude-sonnet-4-6}
    penetration_tester: {id: claude-sonnet-4-6}
    cross_repo_analyzer: {id: claude-sonnet-4-6}
```

Use `ANTHROPIC_BASE_URL` or `OPENAI_BASE_URL` (or the matching block's
`base_url`) for a private endpoint. `verify_ssl: false` on a deepagents
detection role disables TLS verification with the same loud man-in-the-middle
warning the other routes print — set `ca_cert` (or `SSL_CERT_FILE`) to trust a
private-CA gateway instead, and note that a configured `ca_cert` wins over a
leftover `verify_ssl: false` here too. Disabling verification on this route is
config-only: the profile's `verify_ssl` reaches the harness through an
internal env carrier (`VVAHARNESS_TLS_VERIFY`) that honours config-derived
values only, so an ambient `export VVAHARNESS_TLS_VERIFY=false` is ignored
with a warning — it is not a user-facing knob; set `verify_ssl` in the
profile's `sdk:`/`openai:` block instead. Validation is read-only for every
backend: agents
return structured results, and host code writes temporary validation artifacts
and the DTO update.

The Claude Agent SDK paths selected by `via: sdk` for S10 fix mode and S11 do
not consume the `sdk:` block's CA/client-cert fields. S10 translates the
SDK-specific key and base URL to standard Anthropic names; S11 does not
translate them and pins an external `claude` executable. That process can use
ambient Claude login/`CLAUDE_CODE_OAUTH_TOKEN` or standard
`ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_BASE_URL`. The
`ANTHROPIC_SDK_CLIENT_CERT` value (the `sdk:` block's `client_cert`) is used
by the direct SDK detection transport and by `via: deepagents` detection
roles resolving to Anthropic.

The `cli:` block tunes TLS/proxy for the `claude` **subprocess** only:

- `ca_cert` → exported as `NODE_EXTRA_CA_CERTS` into the subprocess env.
- `verify_ssl: false` → exports `NODE_TLS_REJECT_UNAUTHORIZED=0` (insecure;
  throwaway/test environments only).
- `client_cert` / mTLS is **not** available on `cli:` (Node exposes no env
  path — the backend emits a warning if one is set). A configured client
  certificate reaches the direct SDK detection transport and `via: deepagents`
  detection roles, no other route.
- Auth and endpoint stay delegated to the CLI's own precedence: run `claude`
  then `/login`, or set `CLAUDE_CODE_OAUTH_TOKEN`; `ANTHROPIC_BASE_URL` is
  honoured if already exported. The CLI defaults to `api.anthropic.com` when
  no base URL is set.
- `effort` (e.g. `high`) pins the reasoning effort for the `claude -p`
  subprocess so a scan never inherits the operator's interactive `/effort`
  default (some models reject `xhigh`). Accepted values are typically
  `high|low|max|medium`.

**When is a cert needed?**

- Public endpoint (`api.anthropic.com` / `api.openai.com`) + a normal API
  key → nothing TLS-related needed.
- Private gateway or a TLS-intercepting proxy whose server cert chains to an
  internal root CA not in the OS trust store → set the per-backend CA bundle
  env var (`ANTHROPIC_SDK_CA_CERT`, `OPENAI_CA_CERT`, or `CLAUDE_CLI_CA_CERT`;
  the first two also cover `via: deepagents` detection roles resolving to that
  vendor, and `SSL_CERT_FILE` covers every deepagents role). For an
  **Anthropic-routed deepagents role** the honoured names are exactly
  `sdk.ca_cert` and ambient `SSL_CERT_FILE` / `SSL_CERT_DIR` — that branch
  deliberately ignores ambient `NODE_EXTRA_CA_CERTS` and `REQUESTS_CA_BUNDLE`
  (those are *additive* in their home tools, while here a CA path *replaces*
  system trust, so honouring a corporate-proxy CA ambiently would break public
  `api.anthropic.com`). Without one of the honoured names, a private-CA
  Anthropic gateway fails with `CERTIFICATE_VERIFY_FAILED`. The
  OpenAI-compatible branch honours the broader ambient set for historical
  compatibility.
- Gateway requires mutual TLS → `ANTHROPIC_SDK_CLIENT_CERT` for the direct
  Anthropic SDK detection transport, the matching block's `client_cert` or
  `VVAHARNESS_TLS_CLIENT_CERT` for `via: deepagents`; the Claude Agent SDK
  S10/S11 paths do not consume it. mTLS **fails open with a warning, not an
  error**: a `client_cert` chain that cannot be loaded (e.g. the path points
  at a CA bundle instead of a client cert) prints
  `client_cert '<path>' could not be loaded (…) — mTLS is NOT active` and the
  run continues on server-authenticated TLS only — check stderr for that
  warning when a gateway unexpectedly rejects the connection.

If only the API key is set and no base URL is given, `sdk:` defaults to
`api.anthropic.com` and `openai:` to `api.openai.com` — neither fails for lack
of a URL.

## `step0:` — static AST seed

S0 is a profile-controlled pre-stage before S1. Rules mode is deterministic;
the optional annotation mode calls a model. `default.yaml`, `full.yaml` and
`taint.yaml` enable the wrapper; only `sdk.yaml` inherits the disabled built-in
default.

| Key | Effect |
|---|---|
| `enabled` | Run S0. Built-in fallback `false`; shipped `default`/`full`/`taint` profiles set `true`. |
| `callgraph_detection` | `rules` (default) or `llm`. Rules mode loads configured external YAML and has no implicit source/sink baseline. LLM mode classifies observed call fingerprints, can add observed-call heuristics when configured, and falls back to configured rule YAML when it produces no usable specs or fails. The `graph_annotate` / `callgraph_creation` model roles are preflighted and credential-checked only in `llm` mode; in `rules` mode they are dead config and skipped. |
| `sources_yaml` / `sinks_yaml` | External Semgrep-style callgraph rule files. The shipped profiles read `VVA_STEP0_SOURCES_YAML` / `VVA_STEP0_SINKS_YAML`; no generated corpus is packaged. At least one usable file is required for rules mode to produce static matches. |
| `languages` | Optional S0 language allowlist. Omit to use every installed callgraph plugin. |
| `callgraph.llm.*` | Annotator caps and confidence thresholds: `max_tokens`, `max_candidates`, `max_batch_candidates`, `min_source_confidence`, `min_sink_confidence`, `failure_mode`, `heuristic_supplement`, `min_sources`, `min_sinks`, `max_heuristic_specs`. |

When S0 has usable external or LLM-derived specs, parser plugins exist for
Python, Java, C#, JavaScript, TypeScript, and Go. Python, Java, C#, JavaScript
and TypeScript can emit typed taint evidence; only Python/Java/C# add response
output sink detection. Go emits call-graph reachability plus field/container
facts and no interprocedural propagation facts. Languages without a plugin
receive no S0 seed, but S1–S9 still run. See
[SETUP_GUIDE.md](SETUP_GUIDE.md#generated-sourcesink-rule-files-taint-profile)
for rule-pack generation.

## `step1:` — repo intake & file inventory

The deterministic repo walk that feeds s3/s4 applies, in order:

1. **symlink containment** — a symlinked file whose target resolves
   **outside the repository root** is skipped (its content would otherwise be
   off-tree host data pulled into LLM prompts). In-tree symlinks (e.g. a
   monorepo linking shared source) are still scanned. The drop applies
   **regardless of `step1.follow_symlinks`**: setting it `true` no longer
   re-enables out-of-root links (the key is still accepted for back-compat,
   with a warning that off-root targets remain blocked). The check applies to
   links that are still links when the walk runs: staging that copies a repo
   **by value** — as batch mode's `--group-by-app` local-path staging does —
   materialises a link's off-root target as an ordinary in-root file, which is
   then scanned like any other. Treat containment as best-effort rather than a
   guarantee that no off-tree content reaches the inventory, and scan untrusted
   repositories under filesystem isolation — see
   [security.md](security.md#hardening-for-less-trusted-or-sensitive-targets).
2. **`exclude_dirs` / `exclude_exts` / `exclude_globs`** — built-in defaults
   plus `config.yaml: step1:` plus any overlay (`--step1-config` /
   `--auto-step1`). Lists **append**.
3. **`max_file_kb`** — any file larger than this (default 1024 KB) is
   skipped outright; data dumps and generated blobs never reach the LLM.

After the walk, a separate pass applies:

4. **`config_dedup`** — content-based collapse of near-duplicate per-env
   config files (below).

Everything the walk drops by rule — `exclude_dirs`, `exclude_exts`,
`exclude_globs`, `max_file_kb`, `config_dedup`, and out-of-root symlinked
*files* — is itemised in the report's *Excluded from scan* section and in the
s1 checkpoint. One case is not: the walk does not descend through a symlinked
**directory**, so a directory link is dropped before the containment test above
ever runs and gets no line in the excluded list. Where its target is inside the
root, those files are still inventoried under their real path; where it points
outside the root, that source is simply absent from the scan with nothing in
the report to say so. When you need a complete account of what a run did not
read, enumerate the target's directory symlinks yourself.

Overlay merge semantics: top-level `exclude_*` lists **append**; nested
dicts like `config_dedup` deep-merge with **replace** (the latest
overlay's `config_dedup.exts` wins outright).

| Key | Effect |
|---|---|
| `auto_exclude` | Registered default `false`, but **all four shipped profiles set it `true`**, so it is on unless you opt out. After each clone, AI-survey the target to derive a per-target Step-1 exclusion overlay before s1 — same as `--auto-step1`. Costs one `models.autoexclude` call per target per fresh scan, and the overlay changes which files every later stage sees. Flag and config OR together; `--no-auto-step1` or `auto_exclude: false` opts out, `--step1-config` overrides. |
| `auto_exclude_max_tokens` | Output cap for the auto-exclude survey call (`models.autoexclude`). Default `8000`. |
| `mode` | Built-in default `full`; the shipped `default`, `full` and `taint` profiles all ship `gap_fill` (only `sdk.yaml` omits the key and runs `full`). With a non-empty seed, `gap_fill` skips the S1 model call unless the repo has >500 source files, a web-api/web-app/service classification, and either zero sinks or ≥10 entry points with <5 sinks. An empty seed is falsey and takes the agentic S1 path; if S1 still yields no entry points or sinks, S3 restores `catchall_mode: all`. |
| `call_graph` | `regex` built-in default; `tree_sitter` in the `default`, `full` and `taint` profiles for AST-backed call/definition spans. Only `sdk.yaml` omits the key and inherits `regex`. |
| `max_budget_usd` | Dollar limit forwarded only when the selected `via: cli` binary advertises `--max-budget-usd`; raw SDK/OpenAI routes — and detection `via: deepagents` roles — ignore it. Otherwise the subprocess timeout remains the bound. Default `25.0`. |
| `max_turns` | Tool-loop cap for `via: sdk` / `via: openai`; also forwarded when an installed `via: cli` build advertises `--max-turns`. Default `40`. |
| `allowed_tools` | `[Read, Glob, Grep]` — re-add `Bash` only on `via: cli`. |
| `follow_symlinks` | `false` (default). Accepted for back-compat but no longer re-enables out-of-root symlinks: links whose target resolves outside the repo root are dropped unconditionally (host-file disclosure guard), even when this is `true`. In-tree symlinks are always followed. |
| `call_graph_validate` / `_supplement` / `_rounds` / `_max_targets` | Deterministic call-graph hardening after the agentic pass. |

**Auto-exclude proposals pass a language-erasure veto.** The auto-exclude
survey is instructed never to exclude application source, but a model can
still propose a repo-wide exclusion of an entire source language — e.g. every
`.pug` and `.hbs` file, which would silently remove the server-template attack
surface from the scan. A deterministic veto therefore rejects any
model-proposed exclusion that would erase a whole scanner-known language: a
bare extension the scanner knows, or a repo-wide glob over one (`**/*.pug`).
Compound suffixes (`.pb.go`, `.min.js`, `.spec.ts`) and path-scoped globs
(`build/**`) still pass — they narrow generated or vendored content, not a
language. Each veto is announced with a stderr `WARN` naming what was
rejected. The veto applies **only to the model's proposals**: excluding a
language deliberately in your own `step1` config or overlay still works.
Known limit, deliberately not policed: a directory-scoped glob (`views/**`)
can still remove a language on a repository whose files of that type all live
under one directory — that is legitimate directory scoping and unknowable in
general.

### `step1.config_dedup`

Repos with per-environment configs (e.g. `service/<svc>/<env>/config.yml`,
`application-{dev,qa,prod}.yml`, `values-{env}.yaml`) often carry
thousands of structurally identical files. The dedup pass:

- shape-hashes each `.yml/.yaml/.json/.toml/.ini/.properties/.conf/.cfg/.env`
  by its **key structure only** (values stripped) and clusters identical
  shapes;
- keeps **one representative per cluster** (per top-level dir, prod
  preferred) and drops the rest;
- runs a **secret / insecure-value safety net** over every file about to
  be dropped — any file with a literal credential, private key, AWS key,
  JWT, `verify: false`, `auth: none`, `debug: true`, etc. that the
  cluster rep *doesn't* already have is promoted back into scope;
- never drops a file that is unique, unparseable, oversized, or in a
  cluster smaller than `min_cluster_size`.

The block below shows the built-in defaults, with the one exception flagged
inline: `min_cluster_size` is the value all four shipped profiles set, not the
built-in default (which is `3`). Every other
line matches the built-in default:

```yaml
step1:
  config_dedup:
    enabled: true              # built-in default
    min_cluster_size: 5        # value all four shipped profiles set; built-in default is 3
    keep_per_top_dir: true     # built-in default
    promote_on_secret_hit: true       # built-in default
    promote_on_insecure_value: true   # built-in default
    max_file_kb: 512   # built-in default; dedup-pass oversize cut (distinct from step1.max_file_kb) — files larger than this are kept, never dropped
    exts: [.yml, .yaml, .json, .toml, .ini, .properties, .conf, .cfg, .env]  # built-in default
```

## `step2:` — threat model

`enabled`, `max_tokens`, `timeout`, `max_threats`, `baseline`
(`auto`/`owasp`/`none`), `max_doc_chars`, `max_manifest_chars`, evidence caps
(`max_modules`, `max_entry_points`, `max_config_reps`,
`max_config_rep_chars`, `max_config_rep_bodies`,
`max_api_artefacts`), manifest-discovery caps (`max_manifest_depth`,
`max_manifests`, `max_manifests_per_kind`, `max_manifest_total_chars`),
graph/frontier caps (`max_graph_files`,
`max_graph_sinks`, `max_graph_edges`, `max_function_sites`), prompt caps
(`max_prompt_modules`, `max_prompt_entry_points`, `max_notes_chars`,
`max_assets`, `max_trust_boundaries`), and the agentic-mode keys
(`agentic`, `allowed_tools`, `max_turns`).

Five of those are worth spelling out:

| Key | Default | Effect |
|---|---:|---|
| `max_config_rep_chars` | `2000` | Per-file character cap on the redacted **contents** of representative config files packed into the S2 prompt. |
| `max_config_rep_bodies` | `12` | How many representative config files get their contents packed; the rest of the selection is listed by path only. |
| `agentic` | `false` | **Off by default.** When `true`, S2 swaps its single-shot `prompt()` call for a tool-using `agentic()` call; output parsing is unchanged. |
| `allowed_tools` | `[Read, Glob, Grep]` | Read-only tool allowlist for the agentic call, validated against exactly `{Read, Glob, Grep}` on every via except `cli`. `Bash`/`Edit` are rejected there because on `via: sdk` an unsupported or mutating tool silently delegates the call to the Claude Agent SDK backend, which could modify the scanned repository. On `via: cli` the allowlist is forwarded verbatim to the binary, so adding `Bash` gives this detection stage a shell on the scanned repository. |
| `max_turns` | `12` | Tool-loop cap for the agentic call. When `agentic` is on, this is the **only real bound** — `max_budget_usd` is a no-op on `via: sdk` / `via: openai` and is enforced only on `via: cli` when the installed binary advertises the flag. |

`max_manifest_depth` bounds how far below the repository root the build-manifest
search descends (default `3`) and the walk skips excluded directories, so
vendored and build-output manifests no longer surface. Raise it for deeply
nested trees — a .NET solution whose `.csproj` files sit four or more levels
down needs a higher value to find them at all.

Document and manifest evidence is gathered in two passes: breadth first, so
every kind present contributes at least one item, then a top-up to the
character budget. A single large document can therefore no longer crowd out
every other kind of evidence.

> **`0` means different things in `step2` and `step3`.** The `step2` caps above
> are read through an integer sanitiser where **`0` means "emit none of this
> block"** — a legitimate operator choice. The `step3` prompt caps below are read
> as `int(value or default)`, where `0` is falsy and therefore still means "use
> the default". Do not carry an assumption from one section to the other.

## `step3:` — decompose

`taint_chunks`, `taint_max_hops`, `taint_max_chunks`,
`taint_files_per_hop`, `pack_by` (`loc`|`tokens`),
`chunk_token_budget`, `chunk_overhead_tokens`, `risk_chunk_loc`,
`catchall_enabled`, `catchall_mode` (`all`|`reachable_only`),
`catchall_deduct_lens_coverage`,
`catchall_reachable_min_ratio`, `catchall_reachable_min_files`,
`catchall_chunk_loc`, `catchall_max_files`,
`max_files_per_chunk`, `specialists[]`, `specialist_chunk_loc`,
`taint_chunk_slice` (`file`|`function`), `threat_surface_fallbacks`,
`threat_fallback_max_files`, `max_threat_fallback_chunks`,
`max_cohesion_groups`, prompt-size caps (`max_prompt_files`,
`max_prompt_entry_points`, `max_prompt_sinks`, `max_prompt_modules`,
`max_prompt_call_edges`, `max_prompt_notes_chars`), threat-model prompt caps
(`max_prompt_threats`, `max_prompt_assets`, `max_prompt_boundaries`,
`max_prompt_threat_context_chars`), `pack_merge_underfilled`, `timeout`,
`max_tokens`.

`catchall_deduct_lens_coverage` (registered default `false`; `sdk.yaml`,
`full.yaml` and `taint.yaml` ship `true`, `default.yaml` ships `false`)
reorders chunk production. When `true`, the catch-all sweep is built last,
after the specialist and threat-fallback chunks: files claimed by
risk/taint/threat-fallback chunks are skipped, but a specialist lens claim
does not count as coverage, so specialist-claimed files still receive a
generic catch-all review. When `false`, the legacy order applies: the
catch-all sweep runs first, over every file no risk/taint chunk claimed,
before the specialist passes exist.

`taint_max_chunks` caps how many dedicated entry→sink taint chunks S3 emits.
The built-in default is `60` (which `sdk.yaml` also writes explicitly);
`default.yaml`, `full.yaml` and `taint.yaml` raise it to `120`. The cap can
saturate on quite small repositories, and a pair beyond it loses its dedicated
taint chunk and falls back to the catch-all buckets; there is no dedicated
*Pipeline Diagnostics* line for that truncation today. For taint-first
scanning on anything beyond a small service, prefer the raised `120` (the
shipped default/full/taint value) over the built-in `60`.

`max_prompt_threats` (default `50`) bounds how much of the threat model the
decompose prompt carries. It matters more than its name suggests: the strategist
decides what gets deep-dived, so a threat absent from this block is a threat no
chunk is built for. Real models emit 15–32 threats, so a cap in the low teens
silently discards a large fraction of the threat model. When the cap does bite,
the truncated count is reported in the run's *Pipeline Diagnostics*, and threats
are re-promoted where needed so no trust boundary loses all of its coverage.

`pack_merge_underfilled` (default `true`) controls how chunk packing turns
cohesion groups into buckets. The packing pass emits at least one bucket per
cohesion group and never back-fills, so on its own the bucket count tracks
*group* count rather than code volume — a repository whose groups are mostly
small directories yields dozens of buckets filled to a small fraction of the
line cap, and **every bucket costs one s4 model call per lens**. With the key
on, adjacent under-filled buckets are coalesced afterwards, still respecting
the line, character, and file caps; on one measured fragmented target this cut
the s4 call count to roughly a third. Set it to `false` to restore the previous
one-bucket-per-group packing exactly — the escape hatch if detection quality
regresses on a specific target, since a merged bucket puts more, less-related
code in front of a single call.

`specialists[]` accepts `crypto`, `logic-bug`, `access-control`, `batch-etl`,
`iac`, `deserialization`, `csrf`, `sensitive-data`, `hardcoded-creds`,
`log-injection` and `injection`. Every pass is surface-gated, so one with no
matching surface costs nothing: `iac` is skipped unless the repository has
Terraform/Docker/k8s/Helm/Actions/Ansible files, `deserialization` unless a
deserializer call site is present, `hardcoded-creds` unless a literal
credential value is found, `csrf` unless there is an authz surface or an
explicit CSRF pattern, `injection` unless at least one injection-family sink
(SQL/NoSQL/command/LDAP/XPath/XXE/SSRF/path-traversal/SSTI and the like) is
present, and `sensitive-data` / `log-injection` unless the repository has
entry points at all. A name with no gate entry is kept, and an unrecognised
name yields an empty lens rather than an error — so check spelling against
this list. All four bundled profiles — `default.yaml`, `sdk.yaml`,
`full.yaml` and `taint.yaml` — enable all eleven.

`reachable_only` is a cost optimization, not a proof of whole-repo
unreachability, and `default.yaml` is now the only shipped profile that selects
it — `sdk.yaml`, `full.yaml` and `taint.yaml` all ship `catchall_mode: all`.
There a sparsity guard (`catchall_reachable_min_ratio: 0.5`) fails the mode open
to `all` when too few eligible files are reachable. `full.yaml` and `taint.yaml`
carry the same guard values, but they are inert under `all`, and `sdk.yaml` omits
both keys and inherits `0.0`/`0` (guard off, as `sdk.yaml` itself notes). So the
guard only ever decides anything in `default.yaml`. Function slicing reduces prompt size but falls back to whole-file
content when definition spans are incomplete — a fallback file is shipped
whole, never truncated to a fixed head — so `file` is a prompt-size and
latency choice, not a coverage fix.

## `step4:` — deep-dive

`parallel`, `runs`, `vote_threshold`, `specialist_runs`, `line_bucket`,
`max_findings_per_run`, `neighbor_context_lines`,
`neighbor_context_max`, `taint_prompt_mode` (`discover`|`confirm_refute`),
`taint_runs`, `taint_chunk_slice` override,
`frontier_max_funcs_per_file`, `timeout`, `max_tokens`.

`taint_model` is still accepted here for backward compatibility but is
**deprecated and ignored**: taint chunks are routed by `models.deepdive` like
every other chunk kind, so setting it changes neither the model nor the cost of
a taint call. The one-time `[s4] WARN: step4.taint_model is deprecated and
ignored` line on stderr is only emitted when a seeded taint chunk is deep-dived
under `taint_prompt_mode: confirm_refute` — under `discover` the key is dropped
with no message at all, so silence is not confirmation that it took effect.

`max_findings_per_run` caps how many findings one deep-dive call may return
(shipped profiles set `10` in `sdk`/`taint`, `20` in `full`, and `25` in
`default`).
When a call produces more, only the
highest-confidence findings are kept; the discarded count is reported in the
run's *Pipeline Diagnostics* rather than vanishing silently — see
[outputs.md](outputs.md#pipeline-diagnostics-markdown) for that line and its
caveats. On a finding-dense target a low cap can discard a large share of a
call's raw output, so if you tighten the cap below the shipped values, watch
that diagnostics line — it is the report row that tells you what the tighter
cap cost.

## `step5_prefilter:` / `step6_verify:`

`min_pre_confidence`, `require_evidence`, `ast_backfill_evidence`,
`line_tolerance` (trivial-dup line distance for the pre-verify deterministic
dedup; when unset, falls back to `step7_dedup.line_tolerance`),
`pre_verify_threshold` (when ≥N findings survive s5, run a semantic dedup pass
*before* s6 verify to cut cost; code default `25`, `default.yaml` sets `0` =
always run — the key is read from `step5_prefilter:`, and a value under
`step7_dedup:` is consulted only when this one is unset),
`pre_verify_semantic` (default `true`; `false` skips that pre-s6 dedup pass) ·
`parallel`, `min_confidence`, `max_budget_usd`, `max_turns`, `allowed_tools`,
`progress_file` (default `false`; write a per-verification s6 progress JSON
under the run state, same as `--s6-progress-file`).

## `step6_exploit_verification:` — live exploit verification (S6-EV)

**Beta — API only.** This block configures the opt-in live exploit-verification
pass (S6-EV). It is localhost-only, sends live attack traffic, and is off unless
`EV_API_COLLECTION` is set. All four shipped profiles carry the block and a
`models.exploit_verification` role set (routed `via: deepagents` in `default`,
`full` and `taint`, and `via: sdk` in `sdk`).

Every knob and its default is documented in one already-verified table in
[exploit-verification.md](exploit-verification.md#profile-configuration): the
pass-level settings (`enabled`, `on_unreachable`, `ev_overrides_static`,
`parallel`, `store_probes`), the per-sender transport/safety/budget knobs
(`timeout_s`, `safe_mode`, `allow_state_changing_methods`, `rate_limit_rps`,
`max_requests_per_finding`, `oob`, …), the credential-freshness and `ev-replay`
keys, and the per-module `classify:` / `mapper:` / `attacker:` / `judge:`
sub-blocks. That page is the single source for these values; they are not
duplicated here.

One safety point worth repeating: exploit verification is **not read-only**.
Every shipped profile sets `allow_state_changing_methods: true`, so an armed run
can create, modify, or trigger resources on the target — point it only at a
disposable local instance you are authorised to attack.

## `step7_dedup:` / `step8:`

`line_tolerance`, `semantic`, `pre_verify_threshold` (back-compat fallback for
the `step5_prefilter:` key above), `max_tokens` · `max_tokens`, `timeout`.

## `step_remediate:` — Remediation Agent (s10)

Tunes the `remediate` command and in-scan S10. The shipped `default.yaml` and
`taint.yaml` disable in-scan S10; `sdk.yaml` and `full.yaml` enable it.
`--remediate` forces S10 on for a scan, but does not enable S11. The standalone
`vvaharness remediate` command remains available regardless of `enabled`.

| Key | Effect |
|---|---|
| `enabled` | `false` in default/taint; `true` in sdk/full. Run the Remediation Agent as in-scan S10; `--remediate` forces it on. Does not gate the standalone command. |
| `top_n_findings` | Remediate only the top-N findings by CVSS: `5` in default/sdk/taint, `20` in full and the built-in fallback. `--top N` overrides; `all`/`*`/`null` remediates every finding. |
| `max_budget_usd` | Per-finding cap passed to the backend (default `10.0`). Compatible Claude CLI and Claude Agent SDK routes enforce it; raw SDK/OpenAI and DeepAgents routes ignore it. Token accounting does not enforce the cap. |
| `max_turns` | Per-finding loop cap (default `40`): forwarded to compatible Claude CLI builds and Claude Agent SDK, enforced by raw SDK/OpenAI loops, and mapped to a DeepAgents recursion limit. |
| `allowed_tools` | Fix-mode tools: `[Read, Glob, Grep, Edit, Write]` — `Edit`/`Write` apply diffs without a host shell. **Bash is omitted by design.** DeepAgents uses a repo-rooted, traversal-safe filesystem backend with no command execution; the SDK gate denies Bash even if re-added. A custom `via: cli` remediation role would grant Bash if you re-added it, so do not. |
| `enforce_policy` | `true` in every shipped profile and when omitted. Deny-list/playbook gate + diff post-gate (reverts forbidden-path edits); set `false` only for a trusted target. It remains enforced when remediation is explicitly enabled or invoked standalone, including in default/taint. |
| `policy_file` | Optional remediation-policy override. Resolves relative to the active config; unset, empty, or unresolved falls back to the installed default. |
| `playbook_file` | Optional remediation-playbook override with the same resolution/fallback behavior. |

`via: deepagents` is accepted on `models.remediate` and `models.validate`
(the agent graph), on the single-shot detection roles
`models.threatmodel`, `models.decompose`, `models.deepdive`, `models.dedup`,
`models.chain`, `models.autoexclude`, and `models.graph_annotate` (a one-shot
harness call offering the model no tools), and on `models.preprocess` and
`models.verify` (read-only agentic loops) — every model role, at this release.

The remediation model is the `models.remediate` role (see [models.md](models.md)).
Full command reference — modes, policy gate, kill-switch — in
[remediation.md](remediation.md).

## `step_validate:` — validator (s11)

Tunes the `validate` / `s11` command and in-scan S11. In-scan validation is
disabled in default/taint and enabled in sdk/full. A config that omits the key
inherits the built-in `false`. Scan has no `--validate` flag: set
`step_validate.enabled: true` in the effective config to enable in-scan S11.
`--remediate` does not enable it. The standalone `vvaharness validate` command
remains available regardless of `enabled`, and requires remediation DTOs.

| Key | Effect |
|---|---|
| `enabled` | `false` in default/taint and in the built-in fallback; `true` in sdk/full. Controls in-scan S11 only, not the standalone command. |
| `effort` | Reasoning effort for each panel session (default `high`); DeepAgents ignores it. |
| `max_turns` | Per-finding panel-session turn cap (default `50`); DeepAgents maps it to a recursion limit. |
| `max_budget_usd` | Per-finding panel-session cap (default `15.0`) enforced by the Claude Agent SDK Harness; DeepAgents ignores it. |
| `max_findings` | Top-N validatable findings by CVSS (default `20`); `--all` bypasses (standalone `validate` only), `--finding` ignores. |
| `allowed_tools` | Read-only repository tools: `[Read, Grep, Glob]`. Validation agents receive no `Write`, `Edit`, or `Bash`; persona dispatch is orchestrated by the session. Agents return structured output and host code alone writes temporary artifacts and the DTO update. |

Full command reference — gate weights, verdict bands, per-persona overrides,
trust model — in [validation.md](validation.md).

> **`max_findings` applies in-scan too.** The cap is enforced both by the
> standalone `vvaharness validate` command and by Step 11 running inside a
> `scan`. When `step_validate.max_findings` is unset it defaults to `20`
> (the `DEFAULT_MAX_FINDINGS` constant). All four shipped profiles set it
> explicitly to `20`. Hand-written or copy-then-edited configs that **omit
> the key** cap at 20 as well. When the cap kicks in, the scan log prints:
> `validate: capping to top 20 of N validatable findings by CVSS (use --all to validate every finding)`.
> To validate everything in a standalone run, pass `--all`; there is no
> equivalent override for the in-scan step — set `max_findings: 9999` in your
> profile if you want no cap.

## `inject:` — optional context inputs

| Key | Effect |
|---|---|
| `cve_file` | Known-CVE feed — raises threat likelihood / focuses the hunt. |
| `controls_file` | Design controls — downranks exploitability (demands bypass proof at s6). |
| `cmdb_file` | CMDB export — enables AppProfile lookup + VulContextSeverity scoring. |

CVE, controls, and CMDB inputs are optional and skipped when absent.

## `rules:` — S4 CWE knowledge overlays

`rules.kb_overlays` accepts one external `*.kb.yaml` path or a list of paths.
The entries are merged with the built-in `generic.kb.yaml` used by S4's
confirm/refute prompt. Overlay files are operator-owned and are not discovered
or packaged automatically. This is separate from S0's source/sink rule files.

## `scan_progress:` — file/chunk observability

| Key | Effect |
|---|---|
| `enabled` | Emit the observability stream. Shipped values: default `true`, full `true`, taint `true`, sdk `false`. `VVAHARNESS_SCAN_PROGRESS_ENABLED=1` forces it on. |
| `style` | `compact`, `verbose`, `summary_only`, `stage_only`, or `llm_debug`. Shipped values: default `compact`, full `compact`, taint `verbose`; no shipped profile enables `llm_debug` — it is opt-in. `stage_only` emits only stage start/done lines, each prefixed with a stage counter (S11 currently prints an unnumbered `?/11` slot). `llm_debug` includes prompt payload traces (`system_prompt` + `user_prompt`) at each backend dispatch. |

Stage-level events cover S0–S11. Detailed activity includes S1 discovery, S2
threat-model notes, S3 chunk queueing, and S4 scanning/results; other stages do
not manufacture per-file events.

> **`llm_debug` is verbose in proportion to your repository.** It prints the
> prompt for every model dispatch, and deep-dive prompts contain the chunk's
> source code, so a large scan emits a great deal of stderr. Payloads are passed
> through the redactor first, so credential-shaped strings are masked, but the
> code itself is not — treat the log with the same care as the repository.
> Each block is truncated to 12,000 characters; `VVAHARNESS_SCAN_PROGRESS_LLM_MAX_CHARS`
> changes that bound. Set `style: compact` to turn the payload traces off while
> keeping the stage and chunk lines.

## `output:` — cleanup and coverage appendix

`preserve_on_cleanup` lists folders retained when a batch clone is removed; all
shipped profiles preserve `security-scan` and `security-remediation`.
`emit_unreachable_appendix` controls whether S3's callgraph-unreachable files
are listed in the report (enabled by `taint.yaml`, otherwise `false`).
`ingest_url` / `ingest_verify` / `ingest_token` (env `VVAHARNESS_INGEST_URL` /
`VVAHARNESS_INGEST_VERIFY` / `VVAHARNESS_INGEST_TOKEN`) name an optional
endpoint the S9 report is uploaded to, whether that upload's TLS is verified,
and its bearer token; with no URL or token the upload is skipped. `ingest_verify`
is the one asymmetric default here: `default.yaml` ships `false` while
`full.yaml`, `sdk.yaml` and `taint.yaml` ship `true`, so set it explicitly if you
rely on TLS verification for this upload under the default profile. See
[USER_GUIDE.md](USER_GUIDE.md).

The appendix separates files **still covered by a specialist pass** from those
**not reviewed by any pass**, because only the second group is a coverage gap.
Files added back by the catch-all coverage backstop are reviewed and so do not
appear at all; note the backstop has its own skip list (see
[features.md](features.md#10-capabilities-that-ride-on-top)), so it does not
add back every unreviewed file. The remedy the appendix suggests is `step3.catchall_mode: all` —
which `sdk.yaml`, `full.yaml` and `taint.yaml` already set, so on those three the
appendix is expected to be empty. Only `default.yaml` ships `reachable_only`, so
overriding the key to `all` in your own copy of that profile is what changes the
outcome.
