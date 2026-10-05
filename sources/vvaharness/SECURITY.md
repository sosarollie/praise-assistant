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

# Security Policies and Procedures

This document outlines security procedures and general policies for the
Visa Vulnerability Agentic Harness (`vvaharness`) project.

- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Scope](#scope)
- [Disclosure Policy](#disclosure-policy)
- [Security considerations](#security-considerations)
  - [Exploit verification (S6) — a second egress path](#exploit-verification-s6--a-second-egress-path)
    — including [a stale `EV_API_COLLECTION` re-arms it silently](#a-stale-ev_api_collection-re-arms-it-silently)
  - [How the tool handles your data](#how-the-tool-handles-your-data)
    — the per-route redaction table
  - [Credential handling](#credential-handling)
  - [Deployment recommendations](#deployment-recommendations)

---

## Reporting a Vulnerability

Thank you for improving the security of our software. We appreciate your
efforts and responsible disclosure and will make every effort to acknowledge
your report.

Please report security vulnerabilities by emailing the security team at:

- **`vvaharness@visa.com`**

For coordinated disclosure and additional reporting channels, see:

- Visa Vulnerability Disclosure Program: https://usa.visa.com/about-visa/vulnerability-disclosure.html

GitHub issues are open — and welcome — for bugs, documentation problems, and
setup questions. Please do **not** report security vulnerabilities there:
issues are public, and vulnerability reports belong on the private channels
above.

The security team will acknowledge your email and follow up with next steps
in handling your report. We will keep you informed of progress toward a fix
and full announcement, and may ask for additional information or guidance.

When reporting, please include as much of the following as you can to help us
triage quickly:

- The version (or commit) of `vvaharness` affected.
- The profile/backend in use (`via: cli`, `via: sdk`, `via: openai`, or
  `via: deepagents` plus its provider) and OS.
- A description of the issue and its security impact.
- Step-by-step instructions to reproduce.
- Proof-of-concept or exploit code, if available.
- Any known mitigations or workarounds.

Report security vulnerabilities in **third-party dependencies** to the party
that maintains the affected component.

---

## Scope

This policy covers vulnerabilities **in `vvaharness` itself**. It does **not**
cover vulnerabilities that `vvaharness` *finds in a repository it scans* —
those are delivered through the tool's own report/SARIF output to whoever ran
the scan, and are owned by the team that owns the scanned repository under
their own disclosure program. If a public issue describes a vulnerability VVAH
found in someone else's code, maintainers redirect the reporter to the correct
owner; VVAH does not process or disclose third-party findings through this
tracker.

---

## Disclosure Policy

When the security team receives a vulnerability report, it is assigned to a
primary handler. This person coordinates the fix and release process, involving
the following steps:

- Confirm the problem and determine the affected versions.
- Audit code to find any potential similar problems.
- Prepare fixes for all releases still under maintenance. These fixes are
  released as quickly as possible.

Public disclosure is coordinated with the reporter; please give us reasonable
time to remediate before any public discussion of the issue.

---

## Security considerations

**TL;DR:** `vvaharness` reads repository content and forwards excerpts to the
configured model endpoint. Tool results are scrubbed before they reach the
model on some routes, but redaction is not a universal pre-egress guarantee
for every prompt or backend — on-disk reports, by contrast, are redacted on
every backend (see the table below). Keep scan credentials and config outside
the repositories you scan, restrict tool access in CI/CD, and scope batch jobs
to repositories your team is authorized to scan.

### Exploit verification (S6) — a second egress path

**What this means for you:** the optional exploit-verification feature (Beta — API only, off by
default) is the one part of `vvaharness` that generates traffic rather than reading code. If you are
deciding whether to allow it in your environment, these five properties are the ones to weigh. Full
model: [`docs/exploit-verification.md`](docs/exploit-verification.md).

#### Where it can send: loopback only, enforced in code

The destination is pinned in code to a loopback host — enforced in code rather than left to
convention, so a misconfigured profile cannot point it at a remote host. That control establishes
*where* EV sends, not *what* is listening there: enable it only against a disposable local instance
you are authorized to attack.

#### Arming it is already live traffic

There is no dry-run mode. As soon as EV is armed, a reachability pass calls every distinct path in
your collection with its example body, before any finding is selected — so traffic reaches the
target even if nothing in the repository maps to an endpoint. A method the run has not opted into is
downgraded to `OPTIONS` for this pass, so a `DELETE` route is never actually exercised here.

#### A stale `EV_API_COLLECTION` re-arms it silently

This is the failure mode to guard against operationally. EV arms whenever `EV_API_COLLECTION` is
set — including a value left behind in `.env` from an earlier session, which re-arms live attack
traffic on every later scan, and a `--resume` run re-arms from the checkpointed collection even with
the variable unset. An armed run announces itself on stderr (a collection-gate line, then per-path
probe lines), but there is no confirmation prompt and no CLI flag either way, so nothing stops it
before the first live request. Unset the variable when you are done, and see the exploit-verification
bullet under [Deployment recommendations](#deployment-recommendations) for the one profile switch
that turns a stale value into a startup error instead.

#### The target's responses come back into the run, filtered

EV is not a one-way channel: what the target returns reaches the model endpoint too, so the target's
data is egressed along with the repository's. It is filtered on the way. The transcript the judge
adjudicates is redacted, and the adaptive attacker loop reads responses back as tool results that
are likewise masked **before** they are size-capped — masking first so that a credential cannot
straddle the cut and survive as a fragment no layer would then recognise. Filtered, not absent: this
is the TL;DR's "not a universal pre-egress guarantee" caveat in practice. See
[`docs/security.md` → Data sent to the LLM provider](docs/security.md#data-sent-to-the-llm-provider).

#### Which credentials can reach the target

More than one channel carries a secret to the target, so inventory all four before you arm it: the
`EV_AUTH_*` environment variables (clear text in `.env`), the client-key passphrase
`EV_TARGET_CLIENT_KEY_PASSPHRASE`, any token saved inside the collection you supply, and any
hardcoded credential the attacker agent finds in the scanned repository and replays. EV's own auth
credentials are never read from a profile or a CLI flag — see
[Credential handling](#credential-handling) below.

### How the tool handles your data

**Why we publish the table below.** Where redaction applies is a per-route
property, not a product-wide promise, and that difference decides which routes
you can safely point at sensitive code. We would rather you make that call from a
stated, auditable matrix than from a marketing claim — so the table names every
route we ship, including the two places where pre-egress redaction does **not**
apply. Every row is verified against the code, not against intent.

Repository content can leave the host at two boundaries: tool results returned
to the model during a scan (pre-egress), and the reports written to disk
afterward. Redaction — masking of credentials, private keys, and payment card
data — is always applied at the report write boundary (Markdown, SARIF and
`findings.json`, on every backend). Whether it is also applied *before* content
reaches the model depends on the route:

| Route | Pre-egress (tool results → model) | Report boundary |
|---|---|---|
| `cli` | **No** — the `claude` CLI's native tools return raw content | Yes |
| `sdk` | Yes — tool results scrubbed before returning to the model (best effort) | Yes |
| `openai` | Yes — tool results scrubbed before returning to the model (best effort) | Yes |
| `deepagents` — single-prompt detection | n/a — the model gets no tools; the prompt is the only egress | Yes |
| `deepagents` — agentic detection (the S1 explorer, the static S6 verifier, and S2 when `step2.agentic` is on) and S11 validation | Yes — filesystem reads masked by read-only session middleware (best effort) | Yes |
| `deepagents` — S10 fix mode | **Split** — fix mode always runs as an orchestrator plus a `fixer` sub-agent: the orchestrator's reads **are** redacted (best effort), the `fixer`'s are **not**, because an agent permitted to write cannot mask what it reads — `edit_file` needs the byte-exact `old_string` from that same read. Treat S10 fix-mode prompts as carrying unmasked repository content | Yes |
| exploit verification (S6) — Beta, API only | Yes — the target's live responses are masked at value level before they reach the judge and attacker models (best effort) | Yes |

On the single-prompt `deepagents` detection path, tools are withheld from
every model request *and* a fail-closed executor gate refuses any tool call
outside the permitted set (empty on this path) — so the graph's built-in
general-purpose sub-agent and every other registered tool are unreachable
even to a forged tool_call (see
[`docs/deepagents.md`](docs/deepagents.md)).

**One more egress path, off by default.** After S9 the run can POST the finished
Markdown report and SARIF file — the complete finding set — to a report-ingest
endpoint with a bearer token. It is armed only by setting both
`VVAHARNESS_INGEST_URL` and `VVAHARNESS_INGEST_TOKEN`; every shipped profile
leaves both empty, and with either unset the upload is skipped. Three properties
to weigh before arming it: the destination is not restricted to any host or
scheme, unlike exploit verification's loopback-only envelope; the upload honours
ambient proxy environment variables; and TLS verification follows
`output.ingest_verify`, which `default.yaml` ships as `false` while the other
three profiles ship `true`. A configured CA-bundle path that does not exist
warns and then proceeds without verification. `--stop-after s9` does not avoid
the upload, and a successful one is checkpointed so `--resume` will not repeat
it.

**If you arm it, do these three things.** Turn verification on explicitly —
set `output.ingest_verify: true` (or `VVAHARNESS_INGEST_VERIFY=true`) rather than
inheriting `default.yaml`'s `false`. Behind a private CA, give `ingest_verify`
the CA-bundle **path** instead of `true`, and confirm that path resolves on the
scanning host, because an unresolvable one warns and then falls back to *no*
verification rather than failing the upload. And restrict the destination
yourself — pin `VVAHARNESS_INGEST_URL` to a host your team controls, and enforce
it at the network layer, since nothing in the tool constrains that URL the way
EV's loopback envelope constrains its target.

Filesystem access is fenced independently of redaction. File reads through
vvaharness's own tool loop (`via: sdk` / `via: openai`) and the s1 inventory
are confined to the repository root — symlinks and path traversals that point
outside it are rejected — and, once s1 registers it, further restricted to the
scan's exclusion-filtered file inventory, with VCS metadata and the scanner's
own output directories refused unconditionally. DeepAgents detection sessions
apply that same inventory restriction to their built-in filesystem tools; the
frozen post-scan remediation and validation stages deliberately keep
repository-root-wide reads, which applying and validating fixes requires. On
`via: cli` the harness sets the `claude` subprocess's working directory and
forwards the role's allowed-tool and permission-mode flags, but adds no path
jail of its own for that subprocess. For full detail see
[`docs/security.md`](docs/security.md).

One ambient-environment hazard deserves its own callout: if a
`LANGSMITH_TRACING*` / `LANGCHAIN_TRACING*` environment variable is set to
`true`, the DeepAgents routes' langchain-core layer uploads every prompt
(which embeds scanned repository source) and completion to an external tracing
service — even without an API key set, because the request is still sent and
merely rejected. `vvaharness` never sets these variables, and `setup` /
`doctor` / scan preflight warn when one is enabled. Keep them unset on scanning
hosts; the full variable-precedence and behavior detail is in
[`docs/security.md` → ambient tracing variables](docs/security.md#ambient-tracing-variables-are-a-third-party-egress-channel).

Batch mode clones each repository into an isolated workspace directory and
scans it. Unless you pass `--keep-clones`, the clone is removed when the scan
completes, preserving only folders listed in `output.preserve_on_cleanup`.
All shipped profiles currently preserve both `security-scan` and
`security-remediation`. See
[`docs/security.md`](docs/security.md) for details.

### Credential handling

API keys and git tokens are kept in environment variables and sent as request
credentials rather than prompt text. The config loader backs this
with a hard rule: an environment variable whose name matches a secret pattern
may interpolate only into the four credential keys (`sdk.api_key`,
`openai.api_key`, `batch.git_token`, `output.ingest_token`) — any other
placement fails the load with a `ConfigPolicyError`. **Why this gate exists:**
those four keys are the only ones the tool treats as credential-bearing — it
sends them as request credentials and keeps them out of its own diagnostics: the
config-provenance banner prints only whether such a key is *set*, and the run
manifest's config snapshot omits them entirely. A secret interpolated anywhere
else is handled as ordinary
configuration and can travel wherever that key travels, including into a request
URL or header that reaches your model endpoint. Rather than let a misplaced secret
become an egress, the loader refuses to start: the run fails at config-load time,
before a single request is made. Two properties of that
gate are easy to miss. It keys on the variable **name**, not its value, so a
secret written literally into another key still loads. And it fails closed
even when the variable is unset, so a profile fails the same way on every
machine instead of only where the secret is present.

Exploit verification carries its own credential class, separate from these four
config keys and never interpolated into a profile. It reads its auth credentials
from the `EV_AUTH_*` environment variables and the target client-key passphrase
from `EV_TARGET_CLIENT_KEY_PASSPHRASE` — never from a profile or a CLI flag.
Those are not the only channels by which a secret can reach the target; see
the exploit-verification note under **Deployment recommendations** below.

For a full description of redaction patterns and credential handling, see
[`docs/security.md`](docs/security.md); backend TLS settings (CA bundles,
mTLS, `verify_ssl`) are covered in
[`docs/SETUP_GUIDE.md`](docs/SETUP_GUIDE.md#endpoints--tls--base-urls-and-certificates)
and [`docs/configuration.md`](docs/configuration.md#backend-transport-sdk--openai--cli).

### Deployment recommendations

- **Only scan repositories you trust.** The scanned repository is an input to
  the pipeline; treat it with the same caution as any other untrusted input
  to a privileged process.
- **Keep scan infrastructure separate from scan targets.** Store config and
  credentials in directories outside the repositories you scan. Run scans from
  a working directory that is **not** inside the target repository.
- **Restrict tool access in CI/CD.** Review and restrict tool access, and
  ensure sandboxing to reduce risk.
- **Keep batch manifests under security-team control** and restrict the git
  host to your internal domain.
- **Treat exploit verification (S6) as live testing, not analysis** — schedule and
  authorize it the way you would a pen test, not a scan. It is Beta — API only,
  and off by default. When armed it sends live payloads to the target
  `EV_TARGET_URL` names — `POST` always, and `PUT`/`PATCH` too, because every
  shipped profile enables `allow_state_changing_methods` — so an armed run can
  create records, trigger jobs, and modify existing resources. The five
  properties to weigh before allowing it, including the stale-`EV_API_COLLECTION`
  hazard, are in
  [Exploit verification (S6) — a second egress path](#exploit-verification-s6--a-second-egress-path)
  above. Two additions specific to deployment: setting
  `step6_exploit_verification.enabled: false` in your profile turns a stale
  `EV_API_COLLECTION` into a startup error rather than a silent arm, which is the
  control to standardise on for hosts that must never arm it — but it is **not** a
  global off switch. It gates only the scan path and `--stop-after ev`; the
  `ev-replay` command does not consult it and still re-sends stored payloads at
  the target, so control replay separately by not invoking it and by managing the
  stored payloads and target it would reuse. Full model:
  [`docs/exploit-verification.md`](docs/exploit-verification.md).
- **Pin model versions in config.** All four shipped profiles already pin
  explicit model ids; keep it that way rather than floating to a provider's
  newest, so model upgrades are tested before they roll out to CI.
- **Rotate provider credentials on a regular cadence.** Treat the scanner's
  API keys and git tokens like any other service credential.

### Input handling

As with any analysis tool, `vvaharness` processes repository content as part
of its normal operation. Findings and artifacts are produced for human review.
The packaged default skips S10 remediation and S11 validation. Remediation
enabled by `--remediate` or the effective config (as in `sdk`/`full`) can edit
target source when S10 has findings, credentials, and a successful fix-mode
session. Use `--stop-after s9` to explicitly skip S10/S11 with any profile.
Apply the same judgement to SARIF and generated patches that you would to any
automated tool result.

### What not to scan

- Repositories your team is not authorized to scan.
- **Repositories whose committers you do not fully trust.**
- Large monorepos without first scoping the scan using `vvaharness estimate`,
  `--stop-after`, or `--auto-step1`.
- Directories containing only binaries, generated code, or vendored
  dependencies — exclude these via `exclude_dirs` in your config to keep
  results focused.
- **Any target you point exploit verification at without authorization to attack it.** EV replays
  real attack payloads against a running service; treat the target as production-hostile and
  confirm you own it.

### Operator responsibility and authorized use

- **Scan only code you own or are explicitly authorized to scan.** This is an
  advisory requirement — nothing in the tool verifies or enforces it. The
  operator is responsible for having that authorization.
- **Run targets under container or VM isolation**,
  with scan credentials and config stored outside the scanned tree; see
  [`docs/security.md` → Hardening](docs/security.md#hardening-for-less-trusted-or-sensitive-targets).
- **Review all findings and fixes before acting on them.** Output is
  LLM-generated and can be influenced by the scanned repository; the operator
  is responsible for that review and for any edits a fix-mode scan applies.

Security is a collaboration. Responsible reports — a vulnerability emailed to
`vvaharness@visa.com`, or a bug or documentation gap filed in the issue
tracker — make the tool safer for everyone who runs it. Thank you for working
with us to keep `vvaharness` and the code it scans secure.
