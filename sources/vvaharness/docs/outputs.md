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

# Output Formats

## On-disk layout

Per target, under `<target>/security-scan/`:

- `findings.json` — the typed `FinalReport` JSON used by downstream tools so
  they do not have to re-parse Markdown and lose structured fields
- `<module>_<ts>_report.md`
- `<module>_<ts>_report.sarif`
- `<module>_<ts>_errors.jsonl` (only written if a non-fatal error was logged; absent on a clean run)
- `*_ev-replay.md` plus a `.json` sidecar — written by the `ev-replay`
  command, not by `scan`; a timestamped re-check of previously
  exploit-verified findings against a redeployed target

Every scan also writes `run_manifest_YYYYMMDDTHHMMSSZ.json` in the **current working directory**
(not under `security-scan/`; if a same-second name exists, `_NN` is appended)
— see
[Run manifest schema](#run-manifest-run_manifest_json) below for every field
and the token-accounting identities. Batch mode additionally writes
`<workspace>/batch_summary.md`.

Remediation artifacts live separately, under
`<repo>/security-remediation/<NN_slug>/` (written by the `remediate` command).
The `validate` command updates each finding's DTO in place:

- `finding_case.json` — the persistent per-finding DTO at `<NN_slug>/`;
  `validate` merges the verdict into the most recent attempt's `validation`
  block. The case `state` is derived from that verdict: `validated` is
  terminal, while `open`, `remediated`, and `failed` remain validatable.
- `validation_report.json` — the agentic panel's per-DTO findings
- `synthesized_gates.json` — qualitative consensus gate outcomes; host code
  applies the configured weights to compute the score and verdict

`validation_report.json` and `synthesized_gates.json` are *ephemeral*: agents
return structured output and host code writes these files to the per-finding
staging workspace under
`<repo>/security-remediation/validation/<finding_id>/`, folded into the DTO's
`validation` block, and then the workspace is deleted after each finding. Only
`finding_case.json` survives under `<NN_slug>/`. When a source session log
is available and redaction/persistence succeeds, a redacted
`validation_session_*.jsonl` transcript is also retained beside it; transcript
persistence is best-effort.

Checkpoints in the SQLite state DB at `$VVAHARNESS_STATE_DIR/vvaharness.db`
(default `~/.vvaharness/state/vvaharness.db`; run
`vvaharness gc --run <repo-path>` to evict that repo's checkpoints, or delete
the file, to force a fresh run — a bare `vvaharness gc` only prunes runs
older than 5 days or beyond the 100 most recent). Payloads are JSON bytes,
schema-validated
via pydantic on load (no pickle / no code-execution path), and are never
read from the scanned repo. Because those payloads embed scanned-source
snippets, on POSIX hosts the DB file is created mode `0600` inside a `0700`
state directory, tightened back to `0600` on open if an earlier release left
it looser, and its WAL/SHM/journal sidecars are covered too (no-op on Windows).
A pre-existing state directory is treated two ways, because they are not the same
decision: one you named yourself via `VVAHARNESS_STATE_DIR` is yours, so a
group/other-accessible mode gets a warning and is left alone — you may be sharing
it on purpose. The **default** `~/.vvaharness/state` is the tool's own, so a loose
mode there is tightened to `0700` and the change is reported; point
`VVAHARNESS_STATE_DIR` at a path you manage if you need the state shared. Every directory the tool creates under the state root gets the same
`0700`, not only the DB's: `checkpoints/<run_id>/` and `stage-markers/` (batch
mode's staged-tree binding anchors) included, and intermediate levels as well as
leaves. The auto-derived `step1.yaml` (`--auto-step1`)
is still a plain file under `$VVAHARNESS_STATE_DIR/checkpoints/<run_id>/`.

The same database also holds two exploit-verification tables, present since
schema version 3; an older file is migrated from 2 to 3 the first time **any**
command opens it, not only during a scan. `ev_replays` keeps the single
confirming exchange per live-verified finding so a later `ev-replay` can
re-send it: the stored request — method, path, query, body, and payload
headers — is kept as sent, **unredacted by design**, because replay must
reproduce the exact request. Your `EV_AUTH_*` credentials are not among them:
they are applied at send time, never recorded, and re-supplied at replay time.
Conventionally named credential headers are stripped from a collection's request
before it is sent, so they never reach the store; a secret under an unconventional
header name, or in a query parameter or body field, is stored as sent. (The stored
response is redacted and capped.) These rows
deliberately survive a rescan's checkpoint reset so replay still works after
a remediate-and-rescan cycle; a later scan whose exploit verification runs
again rewrites the set with its own confirmations, and the rows are otherwise
removed only when the run itself is
deleted or pruned (`vvaharness gc`). `ev_probes` — written only when the
profile sets `step6_exploit_verification.store_probes` — logs every payload
exploit verification sent during the run, with credential material redacted
before insert. The database is therefore not only checkpoints with
scanned-source snippets: treat it as sensitive both for the source it embeds
and for the attack requests it retains.

> Only resume from checkpoints you produced yourself; do not `--resume` a
> scan of an untrusted repository.

## Exit codes

For the named `VVAH-E001` through `VVAH-E005` errors and their recovery actions,
see [errors.md](errors.md).

The process exit code is the one-line verdict on the whole invocation — the
value a CI gate or wrapper script branches on. It matters most for standalone
`validate`, which writes no manifest and so has no other machine-readable
outcome (see [validation.md](validation.md#exit-codes)); a scan additionally
records the code in the manifest's `exit_code` field.

| Code | Meaning |
|---|---|
| `0` | The run completed and nothing failed. |
| `1` | The pipeline broke — a stage errored or stopped before finishing its work. For `ev-replay` only, a **completed** replay also exits `1` when at least one finding is still vulnerable. |
| `2` | Refused before spending on the work the refusal guards: bad arguments, a missing input file, a config conflict, an empty scan scope (no file survived the exclusions), or a gate that aborted before stage 2. |
| `3` | The run itself completed, but nothing it remediated validated as fixed and at least one case failed validation. A run of only inconclusive cases exits `0`; see [validation.md](validation.md#exit-codes). |
| `130` | Aborted by the user (SIGINT / Ctrl-C). |

The distinction worth reading twice is `1` vs `3`: for the commands this
table governs, `1` means the harness failed, `3` means the harness worked and
delivered a verdict — the fixes did not pass. Treating every non-zero code as
one thing loses that difference, which is the reason `3` exists. `ev-replay`
reuses code `1` the way `3` is used here: a replay that ran to completion
exits `1` when at least one finding is still vulnerable.

Because a failed `ev-replay` command — a configuration or `EV_AUTH_*` mistake
that ends in a traceback — also exits `1`, tell the two apart by the
`*_ev-replay.md` report under `<repo>/security-scan/`: a report means the
replay completed and `1` is its verdict; a traceback with no report means the
command failed.

Two honest caveats about `2`. It is a refusal rather than a failure, but it is
*not* a promise that the run spent nothing overall: the validation step has its
own preflight, so a configuration it rejects — a cross-vendor persona, for
instance — surfaces as `2` at the end of a scan whose detection stages have
already run and billed. And a scan that is refused at startup never reaches the
stages it guards, so re-running it after fixing the invocation costs only the
re-run.

Non-fatal stage errors do **not** change the exit code — a stage that ran to
completion with lost coverage surfaces through `## Scan Health` and the per-run
`*_errors.jsonl`, not here. *Zero* coverage is the exception: a scan whose scope
is empty analysed nothing, so it is refused with `2` rather than reported, and
never presented as a clean run.

Scope: this table is the contract for `scan`, `remediate`, `validate` and
`batch`. One caveat on `batch`: refusals that exit `2` on a single-repo run —
including an empty scan scope — are recorded as an ordinary per-repo failure
and surface as batch exit `1`, and a scan whose `--resume` is refused for
safety exits `0` and is counted "OK" in the batch summary, so check that each
repo's report exists under `<repo>/security-scan/` rather than relying on the
batch exit code alone.

## Run manifest (`run_manifest_*.json`)

Written to the current working directory when a scan actually ran (`doctor`
and `estimate` write none; a usage error or `--help` writes none). It is the
run's audit record and the **only** artifact that sees the full run: the
Markdown report is rendered before S10/S11 by design, so post-scan spend
appears here and nowhere else.

Top-level fields (`vvaharness/manifest.py`):

| Field | Contents |
|---|---|
| `tool`, `version` | `"vvaharness"` and the installed package version. |
| `started`, `ended`, `duration_sec` | UTC ISO timestamps and wall-clock duration. |
| `argv` | The command line, secret-scrubbed (values after credential-shaped flags become `***`; secret-shaped tokens are redacted regardless of flag). |
| `config_profile`, `config_sha256`, `config_local_sha256` | The resolved config path and its hash, plus the hash of any `config.local.yaml` overlay (`null` when absent — the manifest's convention for not-determinable). |
| `ev_api_collection`, `ev_api_collection_sha256` | The exploit-verification API collection the run was configured with (from `EV_API_COLLECTION`) and the hash of its contents; both `null` when none was set. Present on every manifest — they record what was configured, not whether exploit verification ran. |
| `models` | One entry per configured role: `id`, `via`, `provider` (`null` when the profile pins none), `resolved_route` — the vendor the calls actually reach (`anthropic`/`openai`), which on the fixed `cli`/`sdk`/`openai` transports is a property of the transport, not of the model's name — plus `resolved_transport` (the configured OpenAI-branch transport on `via: deepagents`; `null` on every other via and on Anthropic-routed roles — see [deepagents.md](deepagents.md)) and `use_responses_api` (the explicit pin when the model node sets one, else `null`). Exploit-verification roles are nested in config, so they are recorded under dotted names — `exploit_verification.classify`, `.mapper`, `.attacker`, `.judge` — with the same fields, and only for the roles the profile defines. |
| `effective_scan_controls` | The non-secret config values that materially change scan output (per-step caps, specialists, validation panel, SHA-256 fingerprints of injected input files). `validation_panel` entries record `id`, `via`, `provider`, and `resolved_route`, with the route fields inherited from the orchestrator — a persona-level `via`/`provider` is ignored and warned about at validate start. |
| `target_git_sha` | `HEAD` of the `--repo` target, `null` when not a git checkout. |
| `exit_code`, `errors_by_stage` | The process exit code — see [Exit codes](#exit-codes) above for what each value means — and per-stage non-fatal error counts from the error log. `errors_by_stage` counts every logged record, **including errors the pipeline recovered from**, so a non-zero count beside a clean console does not mean coverage was lost; in batch mode it reflects only the **last repo** of the batch. See [errors.md](errors.md). |
| `stages`, `totals` | The per-stage duration/token/cost table (below). |
| `pricing`, `pricing_status` | Provenance of the pricing table the cost columns used (`file`, `sha256`, `source`; `null` when none was configured), and a `{status, reason}` object saying whether costs are `available`, `incomplete` (a token-bearing model is missing from the table), or `unavailable` (no pricing table configured). |
| `remediation` | Validation rollup over the run's remediation cases (below). **Omitted entirely when stage 11 did not run** — absent means *unknown*, not clean. |
| `counters` | Every internal diagnostic counter, verbatim — the unfiltered engineer view. |

Each `stages.<id>` entry carries `label`, `outcome` (`completed`,
`completed_with_errors`, `error`, `not_run`, `cached`, `skipped`, or
`disabled` — there is no `failed` value; a stage that broke records `error`.
`completed_with_errors` means the stage finished but lost coverage — the console
line marks it `⚠` rather than `✓`, and nothing else branches on it),
`duration_sec`, `model`, `cost_usd`, `cost_estimated` (`true` only on s11,
whose personas may run a different model than the one costed), and a `tokens`
bucket carrying exactly five keys: `prompt`, `completion`, `cache_read`,
`cache_write`, `calls`. The in-process per-phase accounting tracks more
(`cache_unparsed`, `usd`, `turns`), but those keys are deliberately dropped
before the manifest — `cache_unparsed` counts calls whose cache accounting
arrived under names nothing parses, and an unparsed field's value can never
be trusted enough to cost, so it surfaces only run-wide as
`totals.cache_unparsed_calls`, never per stage. Do not hunt for
`stages.<id>.tokens.cache_unparsed`; it does not exist.

`totals` carries `prompt_tokens`, `completion_tokens`, `total_tokens`,
`cache_read_tokens`, `cache_write_tokens`, `calls`, `calls_with_usage`,
`completion_absent` (usage records whose completion count arrived as an
explicit null and was coerced to 0), `cache_unparsed_calls` (below),
`cost_usd`, and `unattributed` (tokens from phases outside any stage — e.g.
the preflight probe — carrying the same token keys as a stage row). The
reconciliation identity is *per key*: stage rows + `unattributed` = `totals`
for every token column.

**Token identities — read these before comparing numbers.** These have
tripped every first-time reader of a cache-heavy run:

- **`prompt_tokens` counts fresh input only** — tokens the model processed
  anew this run, *including* the portion simultaneously written to cache. It
  **excludes cache reads**. The input actually presented to the model is
  `prompt_tokens + cache_read_tokens`.
- **`total_tokens` = `prompt_tokens + completion_tokens` — it also excludes
  cache reads.** On a cache-heavy run, cache reads can be the large majority
  of the input traffic the model really saw, so `total_tokens` alone
  understates traffic badly; always read `cache_read_tokens` next to it.
  (Cache reads are excluded from the headline because they bill at ~0.1× —
  folding them in would inflate the total the costs are computed from.)
- **Cache writes are one quantity spelled differently per layer** — do not
  hunt for a missing field: `totals.cache_write_tokens` here,
  `cache_write` in the per-stage bucket, `cache_creation_input_tokens` on the
  Anthropic wire (with a typed `cache_creation` per-TTL breakdown beside it),
  `prompt_tokens_details.cache_write_tokens` on OpenAI-compatible wires, and
  `cache_creation_per_mtok` as the pricing-table rate key.
- **`cost_usd` is `null`, not `0`, when it cannot be computed** — no
  operator pricing table (`VVAHARNESS_PRICING_FILE` / `pricing.file`), or any
  token-bearing model missing from it, nulls that stage's cost and therefore
  the run total. A blank cost on a third-party model is expected.
- **`calls` vs `calls_with_usage`** counts model API requests at the same
  granularity on every route; on the `via: deepagents` route the two move
  together by construction, so their equality is *not* a usage-shortfall
  check there.
- **`cache_unparsed_calls` exists only under `totals`** — there is no
  per-stage counterpart (see the stage-bucket note above). It counts calls
  whose usage carried cache accounting
  under key names no backend parses (e.g. Bedrock's camelCase). Non-zero
  means caching may be working but is not meterable here — the cache columns
  read zero without being a measurement.

When stage 11 (validation) ran, a `remediation` block rolls up how it left
every remediation case:

```json
"remediation": {
  "cases": 5,
  "states": {"failed": 5},
  "decisions": {"not_fixed": 5}
}
```

`cases` counts the remediation cases the rollup saw. `states` tallies each
case's derived lifecycle state (`validated`, `failed`, `open`, `remediated`,
`declined`, `pending`); `decisions` tallies the raw validator decision of each
case's **latest** attempt (`fixed`, `partially_fixed`, `not_fixed`,
`inconclusive`). Only values actually observed appear — the dicts are not
padded with zeros, so an absent key reads as a count of zero.

The block's absence is its most easily misread property: the whole key is
**omitted** when stage 11 did not run — a `--stop-after s10` run, a config
with the validate step disabled, or a preflight-disabled stage. A validation
rollup with no validation is *unknown*, not clean; do not read a missing
`remediation` as "nothing failed". In batch mode the totals are
**invocation-wide** — one manifest covers the whole CLI invocation, so the
counts are summed across every repo; per-repo detail lives in
`batch_summary.md`.

`output.preserve_on_cleanup` in `config.yaml` controls which folders inside
the clone survive when cloned source is deleted. The shipped profiles preserve
`[security-scan, security-remediation]`; if the key is omitted entirely the
built-in fallback keeps the same two folders. Checkpoints live outside the
clone, so `--resume` works regardless of cleanup.

## Markdown report — finding block

Each verified finding follows this block order (metadata fields on
consecutive lines — one field per line, no blank lines between, so the
SARIF parser reads each by regex):

```
### N. [SEVERITY] Title
**Class:** <CWE-NNN: name, or the vuln-class when no CWE resolves>
**CWE:** CWE-NNN: name - https://cwe.mitre.org/...   (if a CWE resolved)
**File:** `path:start-end`
**CVSS 3.1:** score (rating) — `vector`
**VulContextSeverity:** `env-vector` - score (rating)   (if CMDB enrichment ran)
**OffensivePriority:** Pn - label | reason
**Confidence:** 0.NN (N runs agreed)
**Also at:** `file:line`, …   (if s7 dedup collapsed other call sites)

#### Description
#### Impact
#### Exploit scenario
#### Preconditions
`code snippet`
#### How to fix
**Exploitability:** notes
#### Adversarial verification
#### Exploit Verification   (only when exploit verification ran)
```

The last block appears only when exploit verification — Beta, API-only,
localhost-only, and off unless `EV_API_COLLECTION` is set — ran in the scan. It
opens with `**Exploit Verification:** <VERDICT> (beta)`; a finding exploit
verification could not live-test renders the verdict
`SAST-ONLY (beta; not live-testable)`. Every other data line in the block is
conditional — each appears only when its datum was recorded. An
`**EV Confidence:** N/10` line appears when a confidence score exists. A
confirmed verdict can add `**EV Method:**`,
`**EV CVSS:**` (advisory — the static `**CVSS 3.1:**` above still owns ranking),
a one-line `**Repro:**`, a `**Curl:**` line, and a collapsed `<details>` replay
block with the observed response — each only when captured. The non-confirming
verdicts instead carry a
`**Why:** [rule|triage|judge] …` line when a reason was recorded, and always a
note that a finding exploit
verification did not confirm is **not** a false positive — static verification
owns that verdict. When at least one reported finding was live-tested,
`## Verification` also gains an
`- Exploit verification: N confirmed live, N not confirmed, N requiring review
(N live-tested)` roll-up line, followed by an indented note that the signal is
positive-only. See [exploit-verification.md](exploit-verification.md).

## SARIF 2.1.0 mapping

`vvaharness/report/enrich.py: md_to_sarif()` parses the markdown back and
emits SARIF. Per finding:

| Markdown | SARIF |
|---|---|
| `[SEVERITY]` | `level`, `properties.severity` |
| Title + CVSS | `message.text` |
| `**Class:**` | `ruleId`, `properties.category` |
| `**CWE:**` (parsed token, else VulnClass fallback) | `properties.{cwe,cweId,cweName}`, result `taxa[]` (resolves against the CWE taxonomy) |
| `**File:**` line | `locations[0].physicalLocation.{artifactLocation.uri, region.startLine}` |
| `**CVSS 3.1:**` | `rank` (CVSS 0–10 scaled to SARIF's 0–100), `properties.{cvssVector,cvssScore,cvssRating,security-severity}` |
| `**VulContextSeverity:**` | `properties.{vulContextSeverityVector,vulContextSeverityScore,vulContextSeverityRating}` |
| `**OffensivePriority:**` | `properties.{offensivePriority,offensivePriorityLabel,offensivePriorityReason}` |
| `**Confidence:**` | `properties.confidence` (and `properties.votes` only when the line carries an explicit `N of M runs` count — the pipeline's `(N runs agreed)` form does not, so `votes` is normally absent) |
| `**Also at:**` line | `relatedLocations[]`, `properties.dedupRelatedLocationCount` |
| Description → Verification | `properties.description` (markdown body, ≤4000 chars) |

Each result also carries `partialFingerprints["vvaFindingId/v1"]` — the
finding's case id, the only identity that is stable across the SARIF file,
`findings.json`, and the remediation DTOs (the Markdown report renders no case
id). Use it, not the title or location, to join a SARIF result to the other
artifacts. The stamp is location-verified: a result the stamping pass could
not match to its finding's file and line is left without one, with a warning
on stderr.

**Verification verdicts are not in SARIF.** A result carries no exploit-verification
property at all — no verdict, no EV confidence, no EV CVSS, no repro. The
adversarial verifier's verdict has no dedicated property either, though its
`**Verdict:** …` line is not parsed and so lands verbatim inside
`properties.description`. The report's `#### Exploit Verification` lines are
parsed out of `properties.description`, but the emptied
`#### Exploit Verification` heading itself remains in it. A SARIF consumer
therefore never sees a live confirmation as a property: read it from the
Markdown report, or from the typed `ev_*` fields in `findings.json`
(`ev_status`, `ev_evidence`, `ev_reason_source`, `ev_repro`,
`ev_repro_detail`, `ev_method`, `ev_confidence` — a string proof tier,
distinct from the numeric `ev_confidence_score` — `ev_confidence_score`,
`ev_cvss_vector`, `ev_cvss_score`, `ev_cvss_rating`), which is the
machine-readable carrier. `ev_status` carries the wire values `CONFIRMED`,
`NOT_CONFIRMED`, `INCONCLUSIVE`, and `NOT_TESTED` (`null` when exploit
verification did not run at all) — deliberately different words from the
report's rendered verdict labels (`REQUIRES REVIEW`, `SAST-ONLY`). See
[exploit-verification.md](exploit-verification.md).

> **Limitation.** `findings.json` carries no Beta signal at all. The `(beta)`
> suffix exists only in the Markdown rendering and is deliberately stripped on
> the round trip, so a consumer sees a raw `ev_status: "CONFIRMED"` with no
> `schema_version`, `notes`, or `_beta` key beside it. A raw
> `ev_status == "CONFIRMED"` is the same Beta-quality signal the Markdown
> report's `(beta)` label marks — give it the same human review that label
> asks for.

Run-level `properties` always carries `applicationId`, and on a pipeline run
also `scanDegraded` and `unrankedFallback` — both booleans, always present,
`false` on a healthy run rather than omitted; `applicationName` and
`cmdbSource` are added only when a CMDB AppInfo was resolved for that
application (i.e. CMDB enrichment ran). The SARIF `tool.driver.name` is
`"Agentic SAST"`. `tool.driver.rules[]` catalogs every emitted `ruleId`, and
`tool.driver.supportedTaxonomies` references the CWE taxonomy (by a stable guid)
so each result's `taxa[]` resolves. The run carries one `invocations[]` entry.
If exploit-chain analysis falls back to an unranked report,
`executionSuccessful=false`; deep-dive chunk failures and other non-fatal
stage errors instead add `toolExecutionNotifications` while leaving that flag
true. A clean run reports `executionSuccessful=true` with no notifications.

### Scan Metrics — chunk breakdown (markdown)

The `## Scan Metrics` block's `- Chunks:` line itemises the chunk kinds the
decompose stage produced:

```
- Chunks: 84 (risk=31, catch-all=12, specialist=30, taint=9, threat-fallback=2)
```

Only kinds actually present are listed. `risk` counts the chunks the ranking
call proposed; `taint` counts deterministic entry→sink data-flow chunks and
`threat-fallback` counts deterministic chunks added to cover a threat that no
other chunk reached. Keeping those separate from `risk` is what lets the line
show whether the ranking call produced anything at all — a report where `risk=0`
but `taint` and `threat-fallback` are non-zero describes a run whose strategist
call failed and whose coverage came entirely from the deterministic passes —
which makes this line the recommended first check after repointing the
`decompose` role at a new transport.

Reports rendered before this breakdown existed, including ones reloaded from an
older checkpoint, fall back to the legacy `risk` / `catch-all` / `specialist`
trio.

### Pipeline Diagnostics (markdown)

A `### Pipeline Diagnostics` subsection inside `## Scan Metrics` reports what the
detection stages did to their own inputs — the decisions that change results but
leave no trace in the findings themselves. Lines that can appear:

| Line | Meaning |
|---|---|
| `Threat model: **degraded**` | the s2 call failed or returned no usable threats; ranking and baseline coverage fell back to the deterministic passes |
| `Chunk file references from the strategist:` | whether the model answered with ids, paths, or a mix — a mix is handled, but means half the output contract was ignored |
| `Threats identified before ranking` | how many threats s2 produced |
| `Threats truncated by the prompt cap` | how many did not reach the decompose prompt (see `step3.max_prompt_threats`) |
| `Threats re-promoted after truncation…` | threats restored so no trust boundary lost all coverage |
| `Baseline checklist items with no threat or open question disposing of them` | baseline items the model neither addressed nor explicitly deferred |
| `Repository kind(s) detected` | the classification driving baseline selection |
| `Chunk file references that matched no known file id` | ids the model invented |
| `File references dropped (no matching file found)` | references discarded outright |
| `File references repaired by a suffix match` | **worth reading** — the model named a file that did not exist as given and it was resolved by suffix; verify these did not land on the wrong file of the same name |
| `Empty chunks dropped` | chunks left with no resolvable file, dropped before any model call |
| `Files added back by the coverage backstop` | files no review pass would otherwise have reached. The backstop is best-effort, not a guarantee — see [features.md](features.md) for the skip list that can still leave a file at zero reviewers |
| `Fallback chunks skipped (already covered by a real threat)` | deterministic fallbacks suppressed as redundant |
| `Cohesion groups formed` / `Chunks packed into N bucket(s)` | packing shape |
| `Deep-dive findings discarded by the per-call cap` | **worth reading** — one or more s4 calls produced more findings than `step4.max_findings_per_run` allows, so real model output was discarded; only the highest-confidence findings from each call were kept. Caveat: the ranking uses the model's *self-reported* confidence, which is coerced to a neutral default when uninterpretable, and equal-confidence ties keep emission order. If the count is large, consider raising the cap. |
| `Calls refused as over-ceiling on the deepagents route` | **worth reading** — a `via: deepagents` prompt exceeded the route's context ceiling and was refused before dispatch (VVAH-E004), so the owning unit (an s4 chunk, a dedup or chain pass) failed loudly and its results are absent. Nothing was truncated or mutated to make the call fit; reduce what that call packs and re-run. |
| `LLM replies cut off by the output-token budget` | **worth reading** — an sdk/openai reply hit its output-token cap and the single doubled-budget retry did too (VVAH-E005), so the owning unit failed loudly and its results are absent instead of a truncated reply passing as success. Common on reasoning models whose hidden reasoning consumes the completion budget; raise the step's `max_tokens` or reduce what the call packs. |

**Every counter here defaults to zero, and a bare zero is not a measurement** —
it is indistinguishable from "the stage never ran". Each line therefore appears
only when its counter has something to report, and the whole subsection is
omitted when none of them do. An absent section means nothing was worth
reporting, not that reporting failed.

Note the division of labour with `## Scan Health` below: a degraded *threat
model* is reported here, whereas `## Scan Health`'s `DEGRADED` marker refers to
the exploit-chain pass.

### Scan Health (markdown)

When a run loses coverage — deep-dive chunks that failed or timed out, a
chain pass that could not be computed, or any stage that logged a non-fatal
error — the report adds a `## Scan Health`
section listing chunks attempted/failed, per-stage error counts, and a pointer
to the per-run `*_errors.jsonl`. The `## Scan Metrics` file-coverage figures
agree with it: a file whose every hosting chunk failed produced no findings
and is **not** counted in `Files analyzed (unique)` or the `Coverage`
percentage. A fully clean run (no failed chunks, no chain
fallback, no logged errors) omits the section entirely. Note: a
run that simply found no exploit chains is **not** degraded — that is a normal
outcome and is stated as "No exploit chains were identified".

## CMDB enrichment

Set `inject.cmdb_file` in `config.yaml` to a single CMDB export CSV to
enable AppProfile lookup and VulContextSeverity environmental scoring.
A relative path resolves against the directory of the config file that
sets it, not the working directory; the shipped profiles point at an
`inputs/cmdb.csv` beside the installed `vvaharness` package. Set an
absolute path to be safe. When unset or missing, base CVSS and
OffensivePriority are still computed; only the VulContextSeverity
adjustment is skipped.
