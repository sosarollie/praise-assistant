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

# Operational Security

> The operational security reference for VVAH operators: what the agent can
> and cannot do, how cloned repos are isolated, what gets redacted, and what
> not to scan with this tool.

> **Reporting a vulnerability in the harness itself?** See
> [`SECURITY.md`](../SECURITY.md) at the repo root.

## Execution boundary

vvaharness is a **static** analyzer: it reads source, it does not build, compile,
or run the target's code. The analysis stages reason over file *contents* and a
textual call graph.

Each backend route — and, on DeepAgents, each stage posture — grants a
different tool surface:

| Route / posture | Shell access | Filesystem tools | Scope |
|---|---|---|---|
| `cli` | Only when a `via: cli` role adds `Bash` to its `allowed_tools` — no shipped profile does | Native `claude` tools; results returned **raw** (no redaction hook) | Target directory |
| `sdk` | None | Read/Glob/Grep, results redacted | Scanned file inventory (jail, below) |
| `openai` | None | Read/Glob/Grep, results redacted | Scanned file inventory (jail, below) |
| `deepagents` — single-shot detection | None | **Zero tools** — every filesystem tool and the `task` sub-agent dispatch tool withheld from every model request | n/a — the packed prompt is the only egress |
| `deepagents` — agentic detection (S1, the static S6 verifier, S2 with `step2.agentic: true`) | None | Read-only `read_file`/`grep`/`glob`, results redacted | Scanned file inventory (jail, below) |
| `deepagents` — S10 fix mode | None | Read plus repo-confined writes (`write_file`/`edit_file`); orchestrator reads redacted, the `fixer` sub-agent's reads **not** — see below | Whole repo |
| `deepagents` — S11 validation | None | Read-only Read/Grep/Glob plus deterministic read-only helpers, results redacted | Whole repo (staged), never modified |

On the DeepAgents route the tool surface is enforced at the tool-execution
seam, not just at advertisement: a fail-closed `PermitTools` middleware
refuses any tool call whose name is outside the session's permitted set —
empty on single-shot detection, the read natives on agentic detection — so
even a forged or hallucinated `write_file`/`edit_file`/`delete`/`execute`
call is answered with an error ToolMessage instead of executing. `task` is
deliberately not permitted on the detection paths. Tool objects (including a
`general-purpose` sub-agent) are still constructed inside the graph, but they
are unreachable — un-advertised *and* refused at the executor. See
[deepagents.md](deepagents.md) for the full layered account.

Where the `cli` row's shell applies, the `claude` subprocess runs shell
commands inside the target directory for repo inventory and evidence
retrieval. If you are scanning untrusted code and want to avoid any shell
execution against it, use a profile whose agentic roles are `via: sdk` /
`via: openai` / `via: deepagents`, or keep `Bash` out of `allowed_tools`.

A second execution-adjacent path is **exploit verification (S6)**. **Beta — API only.** Exploit
verification needs a Postman/OpenAPI/Swagger collection and can only verify findings that map to an
HTTP endpoint; everything else stays the same. It is localhost-only, sends live attack traffic,
and is off unless `EV_API_COLLECTION` is set. When armed it does not compile or run the target's
*source*, but it is **not read-only**:
it sends **live HTTP requests, including real attack payloads**, to a running target you point it
at. `POST` is always permitted, so EV can create records and trigger jobs. `PUT`/`PATCH` need
`allow_state_changing_methods`, and while that is off in the built-in default, **every shipped
profile turns it on** — so on any supported configuration EV may also modify existing resources.
`DELETE` needs `safe_mode: false` on top of that, and no shipped profile sets it, so irreversible
deletes stay closed unless you open them yourself.

**Arming EV is itself live traffic, before any finding is chosen.** A reachability pass runs at
preflight — before S0 and before any model spend — and sends one request per distinct path in your
collection, using the collection's own example body and the real method. The method policy above
applies to this pass too: a method the run has not opted into is downgraded to `OPTIONS`, so a
`DELETE` route is never actually exercised here. On the shipped profiles, which all enable
`allow_state_changing_methods`, that means a collection with `POST` and `PATCH` endpoints has those
exercised even if no finding maps to any of them. Endpoints whose example body could not be parsed
are dropped before anything is sent. Budget for that when deciding what to point EV at:
the relevant question is not "which findings will it test" but "am I willing for every endpoint in
this collection to be called".

> **Note.** `vvaharness setup` and `vvaharness doctor` perform no
> exploit-verification checks at all, so a clean `doctor` says nothing about EV readiness. The
> readiness check is a scan stopped at the EV preflight: `--stop-after ev` parses the collection
> and probes the target's reachability, then stops **before S0** — no call graph and no model
> spend.

Destinations are pinned in code to a loopback host — enforced in code rather than left to
convention — which establishes **where EV sends, not what is listening there**, so confirming that
the port `EV_TARGET_URL` names is the service you mean to test, and that you are authorized to test
it, is the operator's responsibility. Two client-level controls back the URL check up, enforced by
the one hardened HTTP client factory the EV package sends its requests through: **redirects are
never followed** (a `30x` to a non-local host would otherwise carry a request past a check that
already passed) and **the process's proxy
environment is ignored** (`HTTP_PROXY`/`HTTPS_PROXY` and friends, which would otherwise take live
payloads off the machine while the URL still read as loopback). EV reads its own auth credentials
from the `EV_AUTH_*` environment variables only — never from a profile or a CLI flag — and a
collection may name the auth *scheme* but never a value. Other secrets can still reach the target on
the wire, so inventory all four channels: those `EV_AUTH_*` variables, the client-key passphrase
`EV_TARGET_CLIENT_KEY_PASSPHRASE`, any token saved inside the collection's own requests, and any
hardcoded credential the attacker agent finds in the repository and replays. EV's
out-of-band listener (used to confirm blind findings)
binds loopback by default; `EV_OOB_BIND` can widen that **inbound** listener to other interfaces,
but it does not change the addresses EV sends to. Point EV only at a disposable local instance you
are authorized to attack. See
[`exploit-verification.md` → Safety during verification](exploit-verification.md#safety-during-verification).

One EV storage property is a deliberate design decision with a data-handling consequence. The
stored replay bundle behind the `ev-replay` command keeps the request side of each confirming
exchange — the payload-side headers, query parameters, and body — **unredacted by design**: a
replay must be able to re-send the request byte-for-byte, and a rescan of the same run
deliberately preserves these bundles. Your own `EV_AUTH_*` credentials are not in that store,
because they are applied at send time and never recorded. The consequence is that whatever the
attack request itself carried — including a hardcoded secret found in the repo and replayed, or a
secret the collection supplied under a header name not recognised as a credential — persists in
the state database until the run is deleted. Treat the state directory with the same care as the
repository itself.

The detection roles that can run agentically at all are `preprocess` (S1),
`verify` (the static S6 verifier), and — **off by default** — `threatmodel` (S2) when
`step2.agentic: true` (read-only `step2.allowed_tools`, default
`[Read, Glob, Grep]`, bounded by `step2.max_turns`, default 12).

The redaction noted in the table's *Filesystem tools* column is mechanical, not
aspirational — but it is not uniform, so read it per row. `via: sdk` /
`via: openai` run Read/Grep results through `redact_counts()`
(`backends/llm/tools.py`) before they return to the model, and the **read-only**
DeepAgents postures — agentic detection and S11 validation — apply the harness's
read-redaction middleware. One row is exempt and one is split, deliberately:
`via: cli`'s native tools return raw content because they are outside the
harness, and **S10 fix mode always runs as an orchestrator plus a `fixer`
sub-agent** — the orchestrator's reads **are** redacted, but the `fixer`'s are
**not**, because an agent permitted to write cannot mask what it reads:
`edit_file` needs byte-exact text from that same read to apply a patch. Treat
S10 fix-mode prompts as carrying unmasked repository content.

> **Warning:** S2's packed doc/manifest evidence is **not** redacted. The S2
> evidence change redacts representative *config-file* contents only (capped
> by `step2.max_config_rep_chars` / `max_config_rep_bodies`); the rest of the
> packed evidence remains raw repository content. Those packed config bodies
> include any **`.env` files in the target** — `.env` is one of S2's config
> extensions — and the packing is on by default in all four shipped profiles
> (`max_config_rep_chars: 2000`, `max_config_rep_bodies: 12`). Know what the
> redaction does **not** catch: it masks known credential key names and value
> shapes, so a high-entropy secret stored under a non-matching name — e.g.
> `SALT=`, `ENCRYPTION_KEY=`, `PEPPER=`, `SIGNING_KEY=`, or a non-URL
> `DB_CONN_STRING=` — egresses **unmasked** to the operator's configured
> model endpoint. Set `max_config_rep_chars: 0` to disable config bodies
> entirely (representatives are then listed by path only).

> **Warning:** `max_budget_usd` is a **no-op** on `sdk`/`openai` (and
> forwarded but not enforced on `deepagents`), enforced only on `cli` and
> only when the binary advertises the flag — `max_turns` is the only real
> agentic bound. Do not rely on a dollar cap on the sdk/openai routes.

### Agentic allowlist validation

Detection stages also validate their agentic allowlist: `step1.allowed_tools`,
`step2.allowed_tools`, and `step6_verify.allowed_tools` are checked against
`{Read, Glob, Grep}` on every route except `via: cli`, and a profile naming
`Bash`, `Edit`, or any other tool fails closed before any model call. A
`via: cli` role is exempt — its allowlist is forwarded verbatim to the
`claude` subprocess, so `Bash` there is the shipped shell capability described
at the top of this section. The guard exists because on `via: sdk` an
unsupported or mutating tool silently delegates the whole agentic call to the
Agent SDK backend, which could modify the scanned repository.

### Config interpolation

Config interpolation is itself gated against secret egress: an environment
variable whose *name* matches a secret pattern (`API_KEY`, `APIKEY`, `TOKEN`,
`SECRET`, `PASSWORD`, `PASSWD`, `CREDENTIAL`, `PRIVATE_KEY`, or a name segment
ending in `AUTH`) may be interpolated only into the credential keys
`sdk.api_key`, `openai.api_key`, `batch.git_token`, and `output.ingest_token`.
Referencing one anywhere else — for example inside `sdk.base_url` — makes
`load()` refuse the whole profile (`ConfigPolicyError`, CLI exit code 2), even
when the variable is unset, so a secret value can never be spliced into a URL
or path that egresses to a model endpoint.

## Repo isolation / sandboxing

For the `sdk` and `openai` backends, the agentic Read/Glob/Grep tools are
implemented in `vvaharness/backends/llm/tools.py` and **confined to the
scanned file inventory, not just the repo root**. `_jail()` resolves every
requested path against the root and rejects
anything that escapes it — `..` traversal, absolute paths that resolve outside
the root, and symlinks pointing outside all return an error string instead of
file content. On top of that, s1 registers its exclusion-filtered file
inventory with the tool loop before any agentic call is dispatched, and from
then on Read/Glob/Grep refuse any path outside that inventory — so a model
cannot read `.git/config`, the pipeline's own `security-scan/` output, or
directories an operator excluded from the scan; the VCS/scan-output directory
names are refused unconditionally even before the inventory is registered
(e.g. on a resume that skipped s1). This matters because
the static s6 verifier reads attacker-influenced finding text; a prompt-injected path
must not be able to exfiltrate files outside the repo. The tools also cap output
(≈200 KB per read, 200 grep matches, 500 glob hits) so a single call can't dump
an unbounded amount of data, and Read/Grep results elide binary content and
neutralise base64 `data:` URIs (the marker as well as any payload) instead of
returning the raw bytes.

On the single-shot roles the `deepagents` detection route offers the model no
tools at all, so nothing is read back — the only egress is the prompt the
stage packs. Its agentic detection roles read through the harness's
filesystem layer, rooted at the repo and redacted on the way back to the
model — and that layer applies the same file-inventory restriction as the
`sdk`/`openai` loop above: once s1 registers its inventory, the built-in
`read_file`/`grep`/`glob` tools (the only tools these roles are granted)
refuse anything outside it, and the VCS/scan-output directory names are
refused unconditionally even before registration. The frozen post-scan stages
(S10 fix mode and S11 validation) deliberately keep their filesystem rooted
at the whole repo: applying and validating remediations legitimately needs
reach beyond the detection inventory.

Batch mode clones each repo under the `--workspace` directory and (unless
`--keep-clones`) deletes the clone after scanning, preserving only the folders in
`output.preserve_on_cleanup` (the shipped profiles and the built-in fallback
when the key is omitted both keep `[security-scan, security-remediation]`).
Pipeline checkpoints
are stored outside the clone in the SQLite state DB at
`$VVAHARNESS_STATE_DIR/vvaharness.db` (default `~/.vvaharness/state/…`).
Every directory the tool creates under that root is created owner-only (`0700`)
through one helper, so the per-run checkpoint directory and batch mode's
stage-marker directory carry the same mode as the DB's own — the latter matters
beyond confidentiality, because a stage marker is what proves a staged tree came
from the ref it claims. A loose mode on the default root is repaired rather than
only reported; a root you supplied via `VVAHARNESS_STATE_DIR` is left as you set
it, with a warning, since a shared state directory can be deliberate.
Payloads are **JSON bytes, never pickle** — loaded via pydantic
`validate_json` so there is no constructor/REDUCE opcode and therefore no
code-execution path (CWE-502). A hostile target repo cannot plant a
checkpoint that `--resume` would execute; at worst a tampered payload fails
schema validation and the stage is re-run.

A single checkpoint payload is capped at **100 MiB** (104,857,600 bytes),
enforced both before the write and by a `CHECK` constraint on the
`checkpoints.size` column, so a direct `INSERT` cannot bypass it. The cap
bounds a corrupt or deliberately inflated payload, and it is **not
configurable**. Know its failure mode, because it is quiet: an oversized
payload is **not persisted**, the stage still completes normally, and the only
signal is a `[ckpt] WARN` line on stderr — there is no error, no non-zero exit,
and no entry in the run manifest. In a long-running scan log that line is easy
to miss. The practical consequence is a stage that never resumes: on a very
large repository S1's context package can exceed the cap, and every subsequent
`--resume` then re-runs S1 from scratch. Since the limit cannot be raised, the
remedy is to reduce what the stage packs — `exclude_dirs`, `--auto-step1`, or a
narrower `--repo` subtree. See
[`USER_GUIDE.md` → `--resume`](USER_GUIDE.md) for the resume-cost detail and
for S4's separate, per-stage checkpoint granularity.

## Validation (`validate` command) trust model

`vvaharness validate` runs an agentic adversarial panel over the remediation
DTOs the `remediate` command produced. It reads the repo to judge each fix but
**never** modifies the scanned checkout, so its guard rails centre on the
agent's permission sandbox. (For the command reference — flags, gates,
verdicts — see [validation.md](validation.md); this section covers the trust
model only.)

- **Read-only sessions.** Parent and persona agents can inspect the staged repo
  with Read/Grep/Glob and dispatch personas, but receive no Write/Edit/Bash.
  DeepAgents also exposes deterministic read-only diff, changed-line, impact,
  pattern-scan, and test-inventory helpers. Agents return structured output;
  host code alone writes temporary `validation_report.json` /
  `synthesized_gates.json`, updates the DTO, and removes the workspace. No
  target build or test is executed.
- **Know which endpoint receives finding data.** `models.validate` resolves to
  `via: cli`, `via: sdk`, or `via: deepagents`, and a legacy `via: openai` value is
  routed to `via: deepagents` with the OpenAI provider when the step starts. The
  panel's egress target is therefore the *provider*, not the `via:` spelling: a
  `deepagents` role with `provider: openai` sends finding data to an
  OpenAI-compatible endpoint. **The shipped `default.yaml` stays on Anthropic**
  (`{id: claude-opus-5, via: deepagents, provider: anthropic}`), so validation
  data does not leave an Anthropic endpoint by default. To keep it that way,
  leave the validate role on `via: cli` / `via: sdk`, or on `via: deepagents`
  with `provider: anthropic`; repointing it at an OpenAI provider route changes
  the egress target. If your policy permits an approved OpenAI-compatible gateway,
  pin it with `OPENAI_BASE_URL`. `vvaharness doctor` prints the resolved backend
  and discloses routing (`via:openai routed to deepagents`).
- **Adversarial panel.** Two always-on personas — a `security-architect` and a
  `penetration-tester` — review each fix, joined by a `cross-repo-analyzer` that the
  orchestrator is instructed to spawn only when the fix spans two or more
  repositories; when it runs, the cross-repo persona returns `skip` for gates outside
  its multi-repo perspective. The
  panel's shared launch prompt is primed with per-CWE bypass cheatsheets from
  `./inputs/validator_hints.yaml` (the penetration-tester is their primary
  consumer) so weak or partial fixes are scored down rather than rubber-stamped.
- **Closed results are not silently re-graded.** A DTO whose host verdict was
  FIXED derives the terminal `validated` state, which is *not* in the
  validatable set — a repeated `validate` skips it. Non-passing or inconclusive
  verdicts derive `failed` or `open`, which **stay re-validatable** on the next
  run (so a corrected patch re-drives with no manual DTO edit). `--resume` may
  reuse a matching checkpoint only for a DTO that is still in a validatable
  state; terminal `validated` DTOs are filtered out before checkpoint lookup.
- **Read-only against the repo.** Nothing the panel produces is auto-applied;
  the verdict and weighted gate scores are written back into each DTO's
  `validation` block for human review.

## Redaction (`vvaharness/report/redact.py`)

Card data, PII, and credential material are masked at two boundaries:

- **Write boundary** — the Markdown report and the SARIF JSON are passed through
  `redact()` / `redact_tree()` before they land on disk, so every rendered field
  (description, code snippet, exploit scenario, verifier reasoning, …) is covered.
  Step-10 remediation DTOs and `evidence/diff.patch` also redact secret-bearing
  diff content at persistence while retaining the raw diff only in memory for
  policy checks. A persisted diff containing redaction markers is evidence for
  Step 11 and may not be accepted by `git apply`.
- **Outbound tool content** — `localtools` runs `Read`/`Grep` results through
  `redact_counts()` before handing them back to the model, so quoted source that
  the agent retrieves is scrubbed before it leaves the process. The same module
  also guards prompt-bound text at the packing choke point: binary file content
  collapses to a visible elision marker (never mojibake) and base64
  `data:` URIs are neutralised in place — applied to tool reads and to the
  source text s4 packs into deep-dive prompts.

Detectors are tuned for **high precision** (few false positives):

- **Card / PAN** — 13–19 digit runs gated by both the Luhn checksum *and* an
  IIN/BIN network check (Visa, Mastercard, Amex, Discover, JCB, UnionPay, Diners,
  Maestro, RuPay), so random Luhn-passing ids aren't masked. Also `CVV`/`CVC` and
  magnetic `TRACK` data.
- **PII** — SSN/ITIN, both separated (`NNN-NN-NNNN`) and keyword-gated bare
  9-digit, validated by area/group/serial rules.
- **Cloud / SaaS keys** — AWS (`AKIA…`), GitHub (`ghp_…`, `github_pat_…`), Slack,
  Stripe, Google API, Azure SAS, Twilio.
- **Tokens & keys** — JWTs, `Bearer`/`Basic` credentials, and PEM private-key
  blocks.
- **URL credentials** — the password component of a `scheme://user:secret@host`
  URL (the scheme and username are preserved, only the secret is masked).
- **Generic secrets** — values assigned after a credential keyword
  (`password`, `api_key`, `access_key`, `client_secret`, `auth_token`, …). Strong
  keywords always mask; values after prose-ambiguous keywords (`secret`, `token`)
  are left alone when they look like ordinary words or code expressions, and
  obvious placeholders (`${VAR}`, `changeme`, `xxxx`, `<redacted>`, …) are never
  masked.

Redaction is a defense-in-depth measure for the written artifacts and outbound
tool reads — it is **not** a guarantee that no sensitive token ever reaches the
model (see below).

## Report rendering — Markdown injection

Untrusted text reaching the generated Markdown reports — model output, DTO
fields, file names from the scanned repository — is neutralised consistently
at the render boundary:

- **Line separators are folded to spaces** — every separator
  `str.splitlines()` honours (not just `\r\n`: VT, FF, FS/GS/RS, NEL,
  U+2028/U+2029), so a single field cannot forge a table row, heading, or
  list item.
- **Zero-width and bidirectional format characters are stripped**
  (Trojan-Source style), so a value cannot hide rendered text or visually
  reverse it — e.g. make a failed status read as something else.
- **Backticks in paths rendered as code spans are folded to a lookalike**
  (U+02CB), because a backslash escape is inert inside a code span — a hostile
  filename cannot close the span and inject structure.

The backtick fold also closed a live correctness bug: the parsers that re-read
rendered file paths (SARIF conversion and the remediation/validation
report-augmentation stages) truncated a path at an embedded backtick, so
remediation could target the wrong file and SARIF could emit a wrong location.

> **Limitation.** The SARIF output is produced by re-parsing the rendered
> Markdown report, so content quoted into that report can steer what the
> re-parse sees. An exploit-verification finding embeds the target's verbatim
> response body in the report's collapsed replay block — credential-redacted,
> but not structurally escaped. Both block delimiters are matched as whole
> standalone lines, so a code snippet that merely quotes a `<details>` element
> cannot open a skip; but a response body containing a line that is exactly
> `</details>` can still close the block early and expose what follows it to the
> boundary and header parsing the skip exists to bypass. Treat SARIF from an
> EV-armed run against a target you do not trust as attacker-influenced, prefer
> `findings.json` as the machine-readable carrier — it is written from the typed
> report directly, not recovered from the Markdown — and reconcile the SARIF
> result count against it if the two disagree.

## Data sent to the LLM provider

To analyze a repo, the pipeline necessarily sends the **source code under scan**
to whichever provider each role is routed to: the Anthropic API (`via: sdk`),
an OpenAI-compatible endpoint (`via: openai`), or the Anthropic backend the
`claude` CLI is logged into (`via: cli`). A `via: deepagents` role — S10/S11,
any detection role that names it, and (on every shipped profile except
`sdk.yaml`, which keeps them on `via: sdk`) the four exploit-verification
roles — sends that role's context to the provider selected on the role
(`anthropic` or `openai`); among the shipped profiles, only `full.yaml`
selects `openai`, on its exploit-verification judge. Use a backend/endpoint your
organization permits for the code in question — e.g. a private Anthropic gateway
(`ANTHROPIC_SDK_BASE_URL` / `ANTHROPIC_BASE_URL`) rather than the public API —
and for sensitive code prefer one with a no-/zero-retention data policy.

The tool never prints credential *values* in `setup`/`doctor` output (only
set/unset presence), and the redaction pass scrubs quoted source before it is
written to disk or returned through the sandboxed tools. Packed source text is
additionally sanitised before it is sent: binary content is replaced by a
one-line elision marker and base64 `data:` URIs are neutralised in place
(line structure preserved), so raw binary blobs are neither egressed nor
billed as prompt tokens.

When **exploit verification (S6)** is enabled it adds one more class of data to what reaches the
provider: **the target's own responses** — real bytes off the running service you point EV at. These
reach a model on more than one path, and every one of those paths is filtered before egress — though
not to the standard the on-disk report gets. The request/response
transcript the judge model adjudicates is redacted field by field before it leaves the process — but
at **value level only** (known-secret shapes and known values), deliberately *not* the key-name layer
the storage sinks apply. The shape layer still masks values under the common credential key names, so
the residual gap is narrow: an opaque secret under a credential-ish key that the shape layer does not
recognise can be masked in the on-disk report and still reach the judge model (see
[`exploit-verification.md` → What is redacted](exploit-verification.md#what-is-redacted)). The
separate `ev-replay` command redacts on the same value-level basis before its judge sees a response.
The adaptive attacker model is filtered on the same value-level basis, on both of its sub-paths: the
short excerpts of already-sent probe responses its opening prompt embeds, and each response it reads
back afterwards as a tool result, are masked **before** they are size-capped — that order is the
point, since capping first would leave a credential straddling the cut as a fragment no layer can
then recognise. Redaction reduces exposure and does not eliminate it: every one of these paths masks
known secret shapes and known values, so the same residual gap applies to all of them. Treat any
live target EV touches as a source whose response bodies are egressed, and point EV only at data you
are willing to send to your model provider.

Prompts carry no credential, no `base_url`, and no absolute host path. The last
is deliberate: an absolute path names your filesystem layout and account without
telling the model anything it can use, so file references in prompts are always
repository-relative.

### Prompts are written to stderr under `llm_debug`

`scan_progress.style: llm_debug` — an opt-in style; no shipped profile enables
it (`default.yaml` and `full.yaml` ship `compact`, `taint.yaml` ships
`verbose`, and `sdk.yaml` ships progress off) —
prints the system and user prompt of **every** model dispatch to stderr. Since
deep-dive prompts contain the chunk's source code, this makes the local log a
second copy of the code under scan.

Payloads pass through `redact()` first, so credential- and PII-shaped strings are
masked to the same standard as the written report. The source code itself is not
masked, and cannot be — it is the analysis subject. Treat any captured stderr,
including CI job logs and shell scratch files, with the same care as the
repository. Set `style: compact` to keep stage and chunk lines without the
payloads.

### Ambient tracing variables are a third-party egress channel

**Operator action: keep `LANGSMITH_TRACING_V2`, `LANGCHAIN_TRACING_V2`,
`LANGSMITH_TRACING` and `LANGCHAIN_TRACING` unset on scanning hosts.** If one
of them is set to `true`, scanned repository source leaves the machine to an
external tracing service.

The mechanism: the DeepAgents routes are built on langchain-core, whose model
layer ships an optional tracing hook. vvaharness never enables it and it is
**off by default**, but the switch lives in the *process environment*, not in
any config this tool reads — so a scanning host can inherit it from a CI image
or a shell profile without anyone choosing it. The four variables above are
checked in that precedence order, first non-empty value wins, and only the
exact string `true` enables. Once enabled, every model prompt — which embeds
the scanned repository's source — and every completion is uploaded, on every
stage that runs a DeepAgents route: any detection role that selects it, plus
the default S10 and S11.

Two properties make this worth auditing for rather than assuming: a missing
API key does **not** prevent transmission (the client still POSTs the run
payload and the service merely rejects it with a 401 — the bytes leave either
way; the key only makes the upload *accepted*), and the `setup` / `doctor` /
scan-preflight warning never mutates the environment or blocks the run, since
an operator may be tracing deliberately. If you do trace on purpose, point it
at an approved, isolated instance.

## Hardening for less-trusted or sensitive targets

The boundaries above (tool jail, redaction, approved endpoint) assume the
implicit threat model: an **authorized operator**, running with **elevated
privilege**, against a repository they **trust**. The further a target is from
that — third-party code, an unreviewed fork, a dependency, anything an outside
party can influence — the more these compensating controls matter. They build on,
rather than repeat, the sections above; layer them.

- **Add host-level isolation around the in-process jail — for a less-trusted
  target, this is the control that actually bounds reads.** The *Repo
  isolation* jail above is enforced by the tool's own process, not by the
  operating system, and it does not bound host CPU, memory, or disk. Run scans
  in a disposable container or VM that exposes only the workspace, so that
  what the process can read is bounded by the OS even if an in-process check
  is bypassed; add resource and file-count/inode quotas, and run as a
  least-privileged user whose write access is confined to the workspace — so a
  pathological repository (e.g. a huge file inventory) can't exhaust the host,
  and any unexpected write or deletion lands on throwaway storage rather than
  a sensitive host path.
- **Scan a copy, not a live working tree.** Point the tool at a fresh checkout or
  snapshot, and don't run a fix-mode scan while other processes are modifying the
  same files. Review applied fixes as a diff before merging — vvaharness does not
  build or test the patched tree.
- **Enforce the endpoint and git-host choice at the perimeter.** *Data sent to the
  LLM provider* covers picking an approved endpoint in config; for a less-trusted
  target also restrict the scanner host at an egress proxy or firewall to only
  that endpoint and the git host(s) you intend to clone from, and use short-lived,
  minimally-scoped clone tokens — so a crafted repository reference or batch
  manifest can't redirect a credentialed clone, or finding data, to an
  attacker-chosen host.
- **Treat manifests and injected context as trusted configuration.** The
  `--repo-file` / repos CSV and any injected files (CMDB, CVE, controls) decide
  what gets cloned and where credentials are sent. Never run ones supplied by an
  untrusted party; review them before a batch run.
- **Verify scan coverage.** Confirm the run analyzed the trees you care about by
  reviewing the excluded/skipped paths it reports. A deterministic veto already
  rejects model-proposed exclusions that would erase an entire source language
  (see [configuration.md → step1](configuration.md#step1--repo-intake--file-inventory)),
  but for sensitive or less-trusted repositories, disable AI auto-exclusion
  (`--no-auto-step1`) and set scope explicitly, so repository content can't
  quietly narrow what gets scanned and drop a vulnerable tree.
- **Remember findings can be steered both ways.** Beyond being triage candidates
  to verify (see below), results can be influenced by prompt injection in the
  repo — to *suppress* real issues or *fabricate* false ones. Independently
  confirm expected high-risk components were covered, and don't feed raw output
  into automated gating, ticketing, or merge decisions without human review.

## What not to scan

- Code you are **not authorized** to test, or that you may not share with the
  configured LLM provider/endpoint.
- Data you must not egress — secrets, customer data, PII/PHI, financial data, or
  trade secrets. Redaction reduces but does not eliminate exposure, so do not
  point the tool at a repository whose contents may not leave your environment
  under the backend you've configured. This applies to **realistic test
  fixtures** too: synthetic or sample card numbers, keys, and tokens can still
  reach the model, because the detectors deliberately favour precision over
  masking clearly-fake values — scrub or synthesize them out before scanning.

> Findings are LLM-generated **triage candidates, not confirmed vulnerabilities**
> — human review is required.
