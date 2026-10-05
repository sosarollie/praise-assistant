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

# Remediation Agent (`remediate` — step 10)

The canonical reference for the Remediation Agent. For where it sits in the
pipeline see [architecture.md](architecture.md); for the model role see
[models.md](models.md); for config knobs see
[configuration.md](configuration.md#step_remediate--remediation-agent-s10).

> **Re-checking a remediated EV-confirmed finding.** The agent reads no `ev_*`
> finding fields, so a fix for a finding that [exploit
> verification](exploit-verification.md) (Beta, API only) confirmed live is
> proposed from the static finding alone — the EV run contributes no extra
> evidence to the fix. After you apply the fix and **redeploy**, the live
> re-check is the separate
> [`ev-replay`](exploit-verification.md#re-checking-a-fix-ev-replay) command,
> which re-sends the stored exploit against the running target — not the
> [`validate`](validation.md) panel, which grades from the repo and DTO only.

## What it does

`vvaharness remediate` reads a prior scan's findings from
`<repo>/security-scan/`, walks the verified findings one-by-one on the
`models.remediate` role (LLM skill; system prompt in
`vvaharness/remediation_agent/prompts.py`), and proposes a
**minimal fix per finding**. For each finding it writes a per-finding DTO:

```
<repo>/security-remediation/<NN_slug>/
  finding_case.json         # the canonical DTO (finding + proposed fix + derived state)
  evidence/                 # triage.json (structured verdict + meta), summary.md (human-readable), diff.patch (unified diff of the change)
```

These DTOs are exactly what [`validate`](validation.md) (step 11) later grades.
Secret-bearing diff content is redacted before it is persisted in both
`finding_case.json` and `evidence/diff.patch`; the raw diff remains in memory for
the remediation policy and post-gate only. A persisted patch containing
redaction markers is validation evidence, not an application artifact, and may
not be accepted by `git apply`.

> ⚠️ **Opt-in in the default profile; when enabled, in-scan remediation runs in
> fix mode.** The shipped `default.yaml` sets `step_remediate.enabled: false`
> and `step_validate.enabled: false`, so a plain scan using that profile skips
> S10/S11. Pass `--remediate` or set `step_remediate.enabled: true` in the
> effective config to enable **Step 10**. The flag and config OR together;
> neither enables S11. The `sdk` and `full` profiles still enable both stages.
> When findings, credentials, and a successful remediation session are present,
> S10 may edit target source. `--stop-after s9` explicitly skips S10/S11 with
> any profile, even with `--remediate`. Standalone `vvaharness remediate` remains
> available when `enabled: false`.

## Modes

| Mode | Effect |
|---|---|
| `fix` *(default)* | Applies the minimal diff to the working tree via `Edit`/`Write` (cwd-confined); on the DeepAgents route the edit is applied by the `fixer` sub-agent (below). The in-scan Step-10 path always uses this. |
| `report-only` | Proposes the fix and writes the DTO; the agent is instructed not to edit files. DeepAgents additionally withholds filesystem writes at the tool-permission layer; legacy routes retain their existing prompt-enforced behavior. |

> ⚠️ **Fix mode needs a write-capable backend (`via: cli`, `via: sdk`, or
> `via: deepagents`).** DeepAgents uses a real filesystem rooted at the target
> repository with traversal-safe virtual paths and no shell backend. The legacy
> OpenAI-compatible backend is sandboxed to
> `Read`/`Glob`/`Grep` and cannot edit files, so a `via: openai`
> `models.remediate` role can only do useful work in `--mode report-only` — in
> fix mode it has no edit tool, so each finding errors and the remediation step
> exits non-zero (not a silent no-op). The shipped `default.yaml` uses an
> Anthropic `via: deepagents` remediate role, so fix mode uses its repo-confined
> filesystem backend. See
> [models.md](models.md).

The tool set is `Read / Glob / Grep / Edit / Write` — **Bash is intentionally
omitted** (a prompt-injected agent with a host shell would be RCE on the
scanner). How that exclusion is enforced depends on the route: on `via: deepagents`
the permission gate is enforced at the tool layer; on `via: sdk` a re-added Bash
is refused outright — the route errors before the session starts, and the Claude
Agent SDK sandbox it delegates fix mode to denies Bash in any case; the
`via: cli` route has no such gate — Bash is contained only by its absence from
`allowed_tools`, so re-adding it *would* grant a host shell. Don't.

On the DeepAgents route, fix mode always runs as an **orchestrator plus a
`fixer` sub-agent** — there is no single-agent fix configuration on that route.
The orchestrator has only read tools, and their results **are** redacted (best
effort); it plans the fix and dispatches the edit to the `fixer`, whose reads
are **not** redacted, because an agent permitted to write cannot mask what it
reads — `edit_file` needs the byte-exact text from that same read to apply the
patch. Treat fix-mode prompts as carrying unmasked repository content; see
[security.md](security.md#execution-boundary).

The default profile routes remediation and validation through DeepAgents per
model: set `via: deepagents` plus `provider: anthropic` or `provider: openai`
on the `models.remediate` / `models.validate` role. (The same spelling is also
accepted on every detection role — `threatmodel`, `decompose`, `deepdive`,
`dedup`, `chain`,
`autoexclude`, and `graph_annotate` run a one-shot harness call offering the
model no tools, and `preprocess` and `verify` a read-only agentic loop — not
this fix-capable agent graph; see
[architecture.md](architecture.md).)
- `provider: anthropic` — Anthropic Messages API (`ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`).
- `provider: openai` — OpenAI-compatible API (`OPENAI_API_KEY`): the Responses
  API by default, with a learned fallback and a per-model `use_responses_api:`
  override onto Chat Completions (see [deepagents.md](deepagents.md)). Also
  accepts **any OpenAI-compatible endpoint** (open-weight models via vLLM,
  Together AI, Ollama, Azure OpenAI, etc.) by setting `OPENAI_BASE_URL` to
  your endpoint. When `provider` is omitted, the backend infers from the model
  name (an id containing `claude` → Anthropic, anything else →
  OpenAI-compatible).

## Running it standalone

```bash
# Remediate the findings of a completed scan (fix mode)
vvaharness remediate --repo /path/to/target

# Only the 10 highest-CVSS findings, interactive picker, no edits
vvaharness remediate --repo /path/to/target --top 10 -i --mode report-only
```

| Flag | Effect |
|---|---|
| `--repo <path>` | Target repo whose `security-scan/` findings are remediated. **Required.** |
| `--config <file>` | Config profile path; else `./config.yaml`, else packaged `default.yaml`. |
| `--mode fix\|report-only` | `fix` (default) applies diffs; `report-only` proposes without editing. |
| `--top <N\|all\|*>` | Remediate only the N highest-CVSS findings (overrides `step_remediate.top_n_findings`; `all`/`*` = every finding). |
| `-i`, `--interactive` | Pick which findings to remediate from a menu. (Shows the FULL findings list — the profile's `top_n_findings` cap is ignored in interactive mode unless you pass an explicit `--top N`.) |
| `--resume` | Skip findings already remediated in a prior run. |
| `-v`, `--verbose` | Print the prompt + raw LLM response per finding. |

## Configuration (`step_remediate:`)

| Key | Default | Effect |
|---|---|---|
| `enabled` | `false` in default/taint; `true` in sdk/full | Run the Remediation Agent as in-scan Step 10. `--remediate` forces on; neither enables S11. Does not gate standalone `remediate`. |
| `top_n_findings` | `5` in default/sdk/taint; `20` in full | Cap by CVSS; `--top` overrides; `all`/`*`/`null` = every finding. |
| `max_budget_usd` | `10.0` | Per-finding cap passed to the backend. Compatible Claude CLI and Claude Agent SDK routes enforce it; raw SDK/OpenAI and DeepAgents routes ignore it. Token accounting does not enforce this value. |
| `max_turns` | `40` | Per-finding loop cap: forwarded to compatible Claude CLI builds and Claude Agent SDK, enforced by raw SDK/OpenAI loops, and mapped to a DeepAgents recursion limit. |
| `allowed_tools` | `[Read, Glob, Grep, Edit, Write]` | Fix-mode tools; Bash denied. |
| `enforce_policy` | `true` in every shipped profile and for custom profiles that omit it | Default-on deny-list/playbook gate + diff post-gate (reverts forbidden-path edits). Set `false` only for a trusted target. |
| `policy_file` / `playbook_file` | bundled files when unset/unresolved | Optional paths under `step_remediate` to `remediation_policy.yaml` / `remediation_playbook.yaml`; paths resolve relative to the active config. |

## Policy gate & kill-switch (`enforce_policy: true`)

When `enforce_policy` is on, every fix decision passes through the policy gate
(`remediation_policy.yaml` + `remediation_playbook.yaml`): deny/allow CWE maps,
forbidden-path globs, and a diff post-gate that reverts edits to forbidden
paths. The bundled policy blocks autonomous edits to version-control metadata,
repository hooks, and CI/build automation; findings in those paths are routed
to human review. The gate fails closed: a policy file that is missing or fails
to load/parse denies every patch, and each finding gets guidance only. (A
configured `policy_file` path that does not exist falls back to the bundled
file instead — see the table above.)

An emergency **kill-switch** is checked on *every* gate decision and forces
GUIDANCE_ONLY (no edits):

- environment variable `VVAHARNESS_REMEDIATE_DISABLE` set to `1`/`true`/`yes`/`on` (case-insensitive), or
- a sentinel file `./.vvaharness-remediate-off` in the working directory.

Both are defined in `remediation_policy.yaml`'s `kill_switch` block and are only
enforced when `enforce_policy: true`.

## Output & safety summary

- Writes `<repo>/security-remediation/<NN_slug>/{finding_case.json, evidence/}`.
- In **fix mode**, a successful remediation may edit source files in the target
  repo — only run against repos you authored/trust (see [security.md](security.md)).
- `--resume` skips findings already remediated in a prior run. (Note: `--force`
  is a *scan* flag that overrides the s10 git-SHA staleness check, not a
  remediate re-run flag.)
- The DTOs feed [`validate`](validation.md) (step 11).
