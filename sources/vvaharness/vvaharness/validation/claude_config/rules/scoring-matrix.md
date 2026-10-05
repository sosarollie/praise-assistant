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
# Scoring Matrix (PRD Section 8.6 -- Fix Validation)

## Four Criteria

| Criterion | Weight | Description | PRD Reference |
|-----------|--------|-------------|---------------|
| root_cause | 0.43 | The applied diff modifies the vulnerable code path with proper mitigation | FC1 |
| instance_coverage | 0.2467 | All affected files in the diff; no remaining vulnerable code paths | FC2 |
| no_new_vulnerabilities | 0.1867 | Code review shows fix doesn't introduce new security issues | FC3 |
| security_best_practices | 0.1366 | Fix uses framework-recommended patterns (parameterized queries, encoding, etc.) | FC4 |

Weights sum to 1.00. The git-oriented `branch_targeting` gate (formerly 0.10) is removed: s11 validates a pre-applied diff on a dirty tree with no release-branch concept. The remaining four weights are renormalized to sum to 1.0.

## Status Multipliers

| Status | Multiplier |
|--------|------------|
| pass | 1.0 |
| partial | 0.5 |
| fail | 0.0 |
| skip | 0.0 |

Synthesized gates should normally be `pass`/`partial`/`fail`. A `skip` marks an *unevaluated*
gate: it is excluded from scoring entirely -- dropped from BOTH the numerator and the
denominator -- so it is weight-neutral (it neither earns nor drags credit). The score is
**renormalized** over the gates actually evaluated; a skip's weight is redistributed across
the evaluated gates, not counted as a failure (see Scoring Execution).

## Decision Thresholds

| Condition | Fix Status |
|-----------|-----------|
| raw_score >= 0.80 | Fixed |
| raw_score >= 0.50 | Partially Fixed |
| raw_score < 0.50 | Not Fixed |
| Missing/duplicate criteria, or evaluated coverage < 0.50 | UNVERIFIABLE |

`no_new_vulnerabilities` is a **critical gate**: if its status is `skip` or `invalid`, the
verdict is forced to `UNVERIFIABLE` regardless of the numeric score (non-waivable, cannot be
out-weighted). If its status is `partial` or `fail`, the numeric score stands but the verdict
label is capped one step below Fixed — a score ≥ 0.80 that would otherwise be Fixed becomes
Partially Fixed.

## Merge Readiness

| Fix Status | Merge Readiness |
|-----------|----------------|
| Fixed | Ready |
| Partially Fixed | Ready with Conditions |
| Not Fixed | Not Ready |
| UNVERIFIABLE | Not Ready |

## Scoring Execution

The orchestrator returns its synthesized gates in its structured response — it has no Write tool and the host persists them — and **computes the verdict directly from this matrix** — there is no Bash/shell in the session, so do the arithmetic yourself. Apply this exact algorithm (it mirrors the canonical scoring engine):

1. **Validate the gate set.** Exactly the four gates `root_cause`, `instance_coverage`, `no_new_vulnerabilities`, `security_best_practices` must be present, each exactly once. Any missing or duplicated gate → `fix_status = UNVERIFIABLE`, `raw_score = 0.0`, `gate_scores = {}` — stop here.
2. **Per-gate weighted score (evaluated gates only).** A `skip` gate is *unevaluated* — exclude it from BOTH numerator and denominator (weight-neutral). An `invalid` gate (any non-str or unrecognised status) is *evaluated* but scores 0.0 and its weight IS counted in the denominator (fail-closed, not weight-neutral). For each evaluated gate (`pass`/`partial`/`fail`/`invalid`): `weighted_score = weight × status_multiplier` (`pass=1.0`, `partial=0.5`, `fail=0.0`, `invalid=0.0`). Round each to 4 decimal places (this is the per-gate value shown in `gate_scores`).
3. **`raw_score` (renormalized).** `raw_score = (Σ evaluated weighted_scores) ÷ (Σ evaluated gate weights)`, clamped to a maximum of `1.0`, rounded to 4 decimal places. Skipped gates are dropped from BOTH sums, so the score is normalized over the gates actually evaluated (a skip's weight is redistributed, never counted as a failure). When no gate is skipped the denominator is `1.0` and this reduces to the plain weighted sum.
4. **Coverage floor.** If the evaluated (non-skip) weights sum to less than `0.50`, coverage is too low to trust a verdict → `fix_status = UNVERIFIABLE`, `raw_score = 0.0` (stop here).
5. **Critical gate.** If `no_new_vulnerabilities` is `skip` or `invalid` → `fix_status = UNVERIFIABLE`, `raw_score = 0.0` (stop here — this check precedes scoring in the engine and cannot be waived by a high numeric score). If it is `partial` or `fail`, the numeric score from step 3 stands, but the verdict label is capped: a score ≥ 0.80 becomes Partially Fixed, not Fixed.
6. **`fix_status`** from the Decision Thresholds table (`>=0.80` Fixed, `>=0.50` Partially Fixed, else Not Fixed).
7. **`merge_readiness`** from the Merge Readiness table.
8. Apply the secret-exposure rotation cap below if and only if that section applies.

Show the per-gate arithmetic (`weight × multiplier = weighted_score`) and the renormalized division (`Σ weighted_score ÷ Σ evaluated weight = raw_score`) in the report `justification`.

### Input schema (`synthesized_gates.json`)

Top-level array of one finding per entry. Each gate object requires `gate_name` and `status`; `summary`, `evidence`, and `details` are recommended for traceability but not required.

```json
[
  {
    "tracking_id": "FINDING-XXXXXXX",
    "gates": [
      {"gate_name": "root_cause",              "status": "pass", "summary": "...", "evidence": [], "details": ""},
      {"gate_name": "instance_coverage",       "status": "pass", "summary": "...", "evidence": [], "details": ""},
      {"gate_name": "no_new_vulnerabilities",  "status": "pass", "summary": "...", "evidence": [], "details": ""},
      {"gate_name": "security_best_practices", "status": "pass", "summary": "...", "evidence": [], "details": ""}
    ]
  }
]
```

All four gates must be present. Missing gates produce `UNVERIFIABLE`. Valid `status` values are `pass`, `partial`, `fail`, `skip`, `invalid`. A `skip` gate is weight-neutral (excluded from the denominator). An `invalid` gate (the engine maps any non-str or unrecognised value here) scores 0.0 and stays in the denominator. If `no_new_vulnerabilities` is `skip` or `invalid`, the verdict is UNVERIFIABLE regardless of all other gates.

### Output

The output JSON contains `fix_status`, `raw_score`, `justification`, `merge_readiness`, and a `gate_scores` dict keyed by `gate_name`.

## Session Markers

All posted results include an idempotency marker:
- JIRA comments: `<!-- validation-session:{SESSION_ID} -->`

These markers identify which validation run posted each comment. The host (not the agent) posts results after the session exits.

## JIRA Status Transitions

After scoring, the agent transitions the JIRA ticket:

| Fix Status | Target Status |
|-----------|--------------|
| Fixed | Accepted/Done |
| Partially Fixed | In Progress |
| Not Fixed | In Progress |
| UNVERIFIABLE | In Progress |

Transition failures are non-fatal warnings.

## Code-level signals only

Applies to all Path A findings, regardless of class.

The agent assesses fix completeness from code-level signals: the applied diff (`diff.patch`), source files in the patched workspace tree, build/config files committed to the repo, and the framework's standard security idioms. Operational and process controls do NOT count toward gate scoring and must NOT appear in `recommendations`.

The following do NOT downgrade any gate (`root_cause`, `instance_coverage`, `no_new_vulnerabilities`, `security_best_practices`) and must NOT be surfaced as recommendations, for any finding class:

- Manual cyber validation / out-of-band cyber review.
- Document or process verification (governance documents, change-management approvals, sign-off workflows, ADR documentation).
- Runtime monitoring / alerting / anomaly detection / SIEM / IDS rules.
- WAF / IPS / network-layer controls configured outside the codebase.
- GHAS push-protection or secret-scanning enablement (already enabled at the org level).
- Pre-commit hooks (gitleaks, detect-secrets, husky, etc.).
- Attestations or process commitments from teams outside the dev (Cyber, IAM, Compliance) when used as gating evidence.
- Any control that does not modify the code being validated.

These items MAY be mentioned in passing in `justification` if directly relevant to the finding's narrative, but they cannot be the basis for a partial/fail gate status, and they cannot appear in the `recommendations` array.

`recommendations` is reserved for code-level hardening genuinely missing from the fix (e.g., the env-var read lacks error handling; the parameterized query has a fallback path that string-interpolates; another vulnerable instance remains in a sibling file).

## Secret-exposure handling

A specific instance of "Code-level signals only" for the hardcoded-credential / API-key / token / password / private-key / connection-string / OAuth-secret class, where the verification commands and the rotation attestation are well-defined. Path A only. Does not apply to injection / auth-bypass / similar findings even if titles contain "credential."

### Verification (non-negotiable)

Persisted remediation diffs are secret-redacted. Use their paths, hunk ranges, redaction markers, and non-sensitive replacement lines as change evidence; never reconstruct, persist, or place a removed plaintext credential in a search query.

- Inspect the patched source at every reported location and confirm that no literal credential remains and the replacement reads from a config-time source (env var / Vault / AWS Secrets Manager / equivalent) or removes the credential entirely.
- Run the deterministic `PatternScan("secret_exposure")` fact tool over the patched workspace when it is present in the persona's granted tools. It scans in-scope production files for conservative secret shapes and excludes the redacted `diff.patch`; match records expose only paths and line numbers, followed by a count/limits/truncation summary. Review every candidate relevant to the finding's credential class and affected paths. If the summary reports truncation or skipped files, do not describe the scan as clean; inspect the affected paths with the available read-only tools and state the coverage limit. On a backend without `PatternScan`, use `Read` and credential-name or delimiter searches that do not contain the removed value, and do not claim that PatternScan ran.
- Treat a complete scan with no relevant candidates as supporting evidence alongside inspection of the reported locations, not as proof that every opaque credential shape is absent. Do not downgrade a gate merely because exact-value `grep -F` verification is intentionally unavailable.
- Record only an abstract result in `justification`; never copy candidate snippets or secret-bearing tool output into persisted narrative.

Repository-history hygiene is NOT a gating concern. This workspace has no version-control history -- do not attempt to inspect or rewrite it, and do not recommend history rewriting or history-scrubbing. Once no literal credential remains at the patched locations, the conservative workspace scan has no relevant candidates, and rotation attestation is present, the historical exposure is neutralized by rotation; the residual cryptographic value is zero.

### Gate mapping

When this section applies:

- `root_cause` passes when the patched workspace tree is clean and the replacement reads from a config-time source (env var / Vault / AWS Secrets Manager / equivalent) or removes the credential entirely.
- `security_best_practices` passes when the replacement pattern follows the framework's standard secret-loading idiom.
- `instance_coverage`, `no_new_vulnerabilities` evaluate normally.

(Per "Code-level signals only" above, missing rotation attestation, missing monitoring, missing pre-commit hooks, and missing ADR docs do NOT downgrade these gates. Repository-history state does NOT downgrade these gates either -- see "Verification" above. Rotation attestation is handled separately as a verdict gate, below.)

### Rotation attestation

Look in (a) developer-authored Jira comments (already in the prefetch payload), (b) the PR description, (c) PR comments. Accept any plausible developer statement that the credential has been -- or has been concretely committed to be -- rotated, revoked, regenerated, replaced, or deactivated. Two forms of attestation count:

1. **Done-state.** Past-tense statement that the credential has been rotated, revoked, regenerated, replaced, or deactivated.
2. **Scheduled commitment.** Forward-tense statement that pins the rotation to a concrete execution context: a specific date, a scheduled change window, or a tracked change identifier (CRQ, CHG, RFC, INC, ServiceNow number, or equivalent auditable ticket -- which by definition references a real schedule). Any one of these markers is sufficient; multiple environments covered separately (e.g., distinct SBX and PROD entries) strengthen the attestation but are not required.

The following do NOT count, regardless of phrasing: vague intentions ("we should rotate", "TODO: rotate", "will rotate eventually"), unscheduled future-tense with no date, window, or tracking identifier, bot/orchestrator-authored text, and screenshot-only comments without a text body.

### Verdict and recommendations

Standard threshold scoring computes a base verdict from `raw_score` (>=0.80 Fixed, 0.50-0.79 Partially Fixed, <0.50 Not Fixed). Rotation attestation then applies as a verdict cap, independent of which gates passed:

- Attestation present -> base verdict stands.
- Attestation missing -> verdict is capped at `Partially Fixed`. A `Fixed` base verdict downgrades to `Partially Fixed`; a `Partially Fixed` or `Not Fixed` base verdict is unchanged.

When attestation is missing, the `recommendations` array MUST include this exact item: `"Reply with text confirming that the leaked credential has been rotated, revoked, or regenerated -- or with a scheduled rotation date, change window, or tracked change identifier (e.g., CRQ/CHG/RFC number)."` Code-level recommendations driven by standard gate failures (per the standard matrix) sit alongside it; the rotation request neither replaces them nor is replaced by them.

When attestation is present, recommendations follow the standard matrix for any failed/partial gates.

### Audit line in `justification`

When this section applies, include one truthful audit line based on the tools actually used:

- With PatternScan: "Secret-exposure handling applied. Patched locations inspected -> <N> clean, <N> with a remaining literal. PatternScan(secret_exposure) -> <count> relevant candidate locations; complete (or: truncated: <safe summary reasons>). Rotation attestation: `<source + brief quote>` (or: not found)."
- Without PatternScan: "Secret-exposure handling applied. Patched locations inspected with available Read/Grep/Glob tools using credential names or delimiters -> <N> clean, <N> with a remaining literal; deterministic PatternScan unavailable. Rotation attestation: `<source + brief quote>` (or: not found)."

Do NOT include candidate snippets, secret-bearing command output, or actual secret values; describe verification abstractly per the "Never echo plaintext secrets" rule.
