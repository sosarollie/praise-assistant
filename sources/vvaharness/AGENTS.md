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
# AGENTS.md — How to operate vvaharness (for AI coding agents)

You are running **vvaharness**, a *released* command-line security-scanning
product. Your job is to **operate it**, not to develop or repair it.

This file is the operating manual for AI agents (Claude Code, GitHub Copilot,
Cursor, Codex, etc.). Read it fully before doing anything in this repo.

---

## 🔴 The three rules (most important)

1. **Do NOT modify the product's source to make a scan run.** Files under
   `vvaharness/` are the shipped tool. If a scan won't start, that is an
   environment problem to fix (below) or a bug to report — never a reason to
   edit `backends/llm/cli.py`, a stage, or any package file. Hand-edited
   source = non-reproducible, unsupported results.
2. **Do NOT hand-write config files.** Everything needed is in the shipped
   profiles (`vvaharness/config/profiles/*.yaml`). Pick a profile with
   `--config`; never create a bespoke `config-*.yaml` to work around an error.
   The one sanctioned exception is the overlay the tool itself supports: a
   git-ignored `config.local.yaml` next to the chosen config is deep-merged
   over it on every command (logged as `config overlay: … applied`). Set
   `VVAHARNESS_NO_LOCAL_CONFIG=1` to ignore it for a reproducible run.
3. **When anything fails, run `vvaharness setup` (or `doctor`) and fix the
   environment it points to** — then re-run the same command. Do not improvise.

If the tool genuinely misbehaves after `setup` is green, report it as a bug
(stack trace via `VVAHARNESS_DEBUG=1`). Don't patch around it.

---

## What this tool does
An S0–S9 detection pipeline plus remediation/validation. S0 is a configurable
static seed stage (`step0`) enabled by the shipped `default`, `full` and `taint`
profiles, which configure it in two modes. `default` and `full` set
`callgraph_detection: llm`, so they build the seed from the model; if the
annotator returns no usable specs or fails, they fall back to the same
configured rule YAML as rules mode, so an empty seed is still possible.
`taint` sets `callgraph_detection: rules`, and rules mode
needs operator-supplied source/sink YAML that no shipped rule pack provides —
with `sources_yaml`/`sinks_yaml` unset and both `build_kb`-generated rulepacks
absent from `vvaharness/rules/` (the shipped state; `setup` prints the command
to build them, and docs/SETUP_GUIDE.md gives the operator-owned-directory +
`VVA_STEP0_SOURCES_YAML`/`VVA_STEP0_SINKS_YAML` route), S0 falls back to an
empty seed and S1 and the later stages continue. The core
detection flow is survey → threat-model →
decompose → deep-dive → pre-filter → adversarial-verify → dedup → chain →
SARIF. It emits a Markdown report + SARIF 2.1.0.

> ⚠️ **The default profile skips remediation and validation.** The shipped
> `default.yaml` sets `step_remediate.enabled: false` and
> `step_validate.enabled: false`, so a plain scan using that profile runs
> detection through S9 without automatic S10/S11. `sdk` and `full` still enable
> both stages; `taint` also leaves them off. `--remediate` or
> `step_remediate.enabled: true` enables **S10 only**. Enabled S10 runs in
> **fix mode: it can edit target source** and write `<repo>/security-remediation/`
> when findings, credentials, and a successful session are available. In-scan
> **S11** requires `step_validate.enabled: true` in the effective config; there
> is no scan `--validate` flag. Standalone `remediate` and `validate` remain
> available when these flags are false. Other configs or a local overlay can
> change the effective values; use `--stop-after s9` to explicitly skip both
> stages with any profile, even with `--remediate`.

`remediate` and `validate` are also standalone commands: `vvaharness remediate`
proposes/applies fixes over a prior scan's findings, and `vvaharness validate`
runs the agentic adversarial panel over the remediation DTOs (s11 panel —
which first discovers the DTOs awaiting validation, then runs the panel). See `docs/SKILLS.md` for the analysis capabilities and
`docs/USER_GUIDE.md` for the full command/flag reference.

## First run — always start here
```bash
pipx install .            # or: pip install .   (one command on PATH: vvaharness)
vvaharness setup         # checks Python, agents, keys, gateway, config
```
`setup` reports the normal readiness checks and remedies. Do what it says, then
re-run it until green, while also applying the SDK-profile S11 caveat below:
the current probe does not exercise that Agent-SDK launcher.

## Choosing a profile (`setup` recommends a starting point)
| You have… | Use | How |
|---|---|---|
| One Anthropic credential (`ANTHROPIC_SDK_API_KEY`, `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`); S10/S11 disabled | `default` | default — no flag (a `config.yaml` in the invoking directory takes precedence over the packaged default; the effective path is printed as `config: …`) |
| One Anthropic SDK credential (`ANTHROPIC_SDK_API_KEY`) | `sdk` | `--config vvaharness/config/profiles/sdk.yaml` |
| One Anthropic credential as shipped | `full` | `--config vvaharness/config/profiles/full.yaml` |
| One Anthropic credential, detection only (S10/S11 disabled); external rules for an S0 seed | `taint` | `--config vvaharness/config/profiles/taint.yaml` |

Arming exploit verification (Beta — API only) does not change this except on
`full`, whose exploit-verification `judge` is the one role routed to OpenAI and
so needs `OPENAI_API_KEY`; Claude auth enters only if you uncomment `full.yaml`'s
`cli` alternatives.

The recommendation is a starting point, not proof that every enabled post-scan
stage is ready. Re-run `setup` with the chosen profile and resolve its warnings.

No shipped profile enables `Bash`. To let a `via: cli` role shell out, add
`- Bash` to its `allowed_tools` in your own copy (trusted targets only).

`sdk.yaml` has a post-scan credential split that `setup`/`doctor` can currently
false-green: `ANTHROPIC_SDK_API_KEY` authenticates S1–S10, but its S11 Claude
Agent SDK launcher does not translate that SDK-named key. S11 pins external
`claude` and can reuse an ambient Claude login / `CLAUDE_CODE_OAUTH_TOKEN`, or
use `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN`. A standard Anthropic
credential alone can cover all stages because sole-SDK detection accepts it as
a fallback; otherwise pair the SDK-named key with working Claude auth for S11.
`full.yaml` ships every role `via: deepagents` — Anthropic except its
exploit-verification `judge`, which uses the OpenAI provider — so the one
Anthropic credential above covers S11 too. One Anthropic credential covers an
EV-armed `default` or `taint` run; `full.yaml` additionally needs
`OPENAI_API_KEY`, for its `judge` alone. No other credential is required
unless you uncomment one of its `cli` / `sdk` / `openai` alternatives.

### Internal gateway note (common cause of 401)
If `ANTHROPIC_API_KEY` is a JWT (`eyJ…`) you are using a gateway/Claude-Code
token. It will **401 against the public API** unless you set the gateway:
```bash
export ANTHROPIC_BASE_URL=https://<your-gateway>/
export SSL_CERT_FILE=$HOME/cacerts.pem         # if it needs a private CA
export CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1 # if the gateway returns "400 invalid beta flag"
```
`vvaharness setup` auto-detects the gateway URL regardless of profile, and its Anthropic endpoint check fails when `ANTHROPIC_BASE_URL` is unset while `ANTHROPIC_API_KEY` is JWT-shaped; on the deepagents-routed profiles (`default`, `full`, `taint`) that failure appears as a `via:deepagents endpoint` ✗ row with no fix block printed under it, so apply the fix yourself — the `export ANTHROPIC_BASE_URL=…` line in the block above. The check reads only those two variables, never `sdk.base_url` / `ANTHROPIC_SDK_BASE_URL`. The shipped `default.yaml` routes S1–S11 `via: deepagents` (Anthropic), so it reads `ANTHROPIC_BASE_URL`. All four exploit-verification roles ship `via: deepagents` in `default.yaml`, `full.yaml` and `taint.yaml`, and `via: sdk` in `sdk.yaml`. No shipped profile routes an EV role `via: cli`. The CA line is route-scoped: `SSL_CERT_FILE` (or the profile's
`sdk.ca_cert`, which the shipped profiles fill from `ANTHROPIC_SDK_CA_CERT`) is
what `via: sdk` and Anthropic-routed `via: deepagents` read — they ignore
`NODE_EXTRA_CA_CERTS`, which only reaches the Node-based paths (`via: cli`
roles and the Agent-SDK S11 launcher). `taint.yaml` routes detection `via: deepagents` like `default.yaml`. Set them in
your shell or `.env` — **do not** edit the package to work around it.

## Running a scan
```bash
vvaharness estimate --repo /path/to/target          # scope/cost preview, no spend
vvaharness scan --repo /path/to/target --application-id <id> [--config <profile>]
```
- Progress prints per stage (`▶ … / ✓ … (Ns)`; `⚠` if the stage finished
  but logged unrecovered errors, `✗` if it failed). The default runs S0 and
  S1–S9; S10 remediation and S11 validation are skipped unless enabled.
- Output: `<target>/security-scan/*_report.md` and `*.sarif`; an
  `*_errors.jsonl` file is created whenever a stage logs a non-fatal error,
  whether or not the pipeline recovered from it.
- When S10 is enabled by config or `--remediate`, a successful fix session with
  findings and credentials writes `<target>/security-remediation/` and can
  **edit source files in the target repo**. S11 validates those fixes only when
  separately enabled in config, or invoked standalone. Use `--stop-after s9`
  to explicitly skip both stages with any profile.
- A `run_manifest_*.json` (written in the current working directory, not under `security-scan/`) records models/config/timing for the run.
- Exploit verification adds two commands, each `Beta — API only`.
  `--stop-after ev` parses the collection and probes the target's
  reachability, then stops **before S0** — no call graph and no model spend;
  it needs `EV_API_COLLECTION` set. `vvaharness ev-replay --repo <path>`
  re-checks exploit-verified findings against a redeployed target; it needs a
  prior EV-armed scan plus the `EV_TARGET_URL` / `EV_*` environment.
- Findings are **triage candidates, not confirmed vulnerabilities** — say so
  when you summarize them.

## When a scan fails
1. Read the one-line `✗ scan failed: …` message.
2. Run `vvaharness doctor` — fix any ✗ it reports (usually a credential or the
   gateway base-URL).
3. Re-run the same scan command. For a full stack trace: `VVAHARNESS_DEBUG=1`.
4. Still failing with a green `doctor`? **Report a bug. Do not edit source.**

## Cost & safety
- Scans spend real model tokens; large repos are expensive. Use `estimate`
  first and scope with `--repo <subdir>` or `--stop-after s3`.
- Scan only code you are authorized to scan.
- **Beta — API only.** Exploit verification needs a Postman/OpenAPI/Swagger
  collection and can only verify findings that map to an HTTP endpoint;
  everything else stays SAST-only. It is localhost-only, sends live attack
  traffic, and is off unless `EV_API_COLLECTION` is set.
- The tool never prints credential values; keep it that way.
- **Validation is opt-in in the default profile, and is also a standalone command.**
  In-scan Step 11 requires `step_validate.enabled: true` (`sdk`/`full` enable it;
  `default`/`taint` do not). `--remediate` enables S10 only. Run on its own,
  `vvaharness validate --repo <path>`
  discovers remediation DTOs written by the model-backed `remediate` command
  (S10). That S11 discovery phase has no model spend; S11 then runs an agentic
  adversarial panel to fill each DTO's
  `validation` block. The default runtime is the DeepAgents backend
  (`via: deepagents`, as shipped in `default.yaml`); `cli` and `sdk` backends run
  the bundled Claude Agent SDK instead. Permitted backends: `via: cli`, `via: sdk`,
  `via: deepagents`; a legacy `via: openai` validate model is routed to
  `via: deepagents` with the OpenAI provider, so the same profile spelling that
  detection and report-only remediation accept also works here. The panel reads
  the repo and writes only its
  own validation artifacts — there is no Docker, and nothing is applied to the
  scanned repo. Re-runs are idempotent (already-`validated` cases are skipped;
  `open` / `remediated` / `failed` cases stay validatable — an `inconclusive`
  verdict re-opens the case).

## Do / Don't (quick reference)
| ✅ Do | ❌ Don't |
|---|---|
| `vvaharness setup` / `doctor` on any error | edit files under `vvaharness/` |
| pick a shipped `--config` profile | hand-write a config-*.yaml |
| set env vars / `.env` for creds & gateway | paste keys into config or source |
| report bugs with `VVAHARNESS_DEBUG=1` | "fix" the tool to force a run |
| invoke from outside the target with explicit `--config` | `cd` into the scanned repo then run |
| use `via: sdk` or `via: openai` for untrusted targets | use `via: cli` against repos you didn't author |
| re-run a failed scan clean | pass `--resume` against an untrusted repo |
