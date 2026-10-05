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

# Errors and Exit Codes

VVAH reports a process exit code for the overall command and may also record a
named `VVAH-E00x` error in the terminal output or the per-run `*_errors.jsonl`
file; the run manifest carries per-stage error counts (`errors_by_stage`), not
named codes. A non-fatal stage error does not necessarily make the process exit
non-zero; check the scan health and error artifact as well as the exit code.

## Process exit codes

| Code | Meaning | Operator action |
|---|---|---|
| `0` | The command completed successfully. | Review findings and scan health. |
| `1` | The pipeline or command failed before completing its work. For `ev-replay` only, a **completed** replay also exits `1` when at least one finding is still vulnerable; see the note below. | Read the terminal error and `*_errors.jsonl`; fix the reported condition and rerun, using `--resume` where appropriate. For `ev-replay`, check whether a `*_ev-replay.md` report was written before treating `1` as a failure. |
| `2` | The command refused to start or continue because of an invocation, configuration, scope, or validation gate. Most exploit-verification (Beta — API only) preflight refusals also land here — see [Exploit-verification refusals (exit 2)](#exploit-verification-refusals-exit-2) below. | Correct the command, configuration, or scope, then rerun. |
| `3` | The run completed, no remediation was validated as fixed, and at least one case failed validation. A run of only inconclusive cases exits `0`; see [validation.md](validation.md). | Review the validation results and remediate or revalidate the affected cases. |
| `130` | The user interrupted the command with SIGINT or Ctrl-C. | Rerun when ready. |

Scope: this table is the contract for `scan`, `remediate`, `validate` and
`batch`. Other commands map their outcomes onto codes in their own terms:
`doctor` exits `1` for a completed diagnostic that found a blocking item or a
failed probe; `setup` exits `1` when its readiness checks find blocking items;
`estimate` exits `2` when `--repo` is missing but `1` when the given path does
not exist; a configuration-policy refusal is reported with different codes —
and in one case an unhandled traceback — depending on the entry point; and
`validate`'s refusal of a network (UNC) path or a non-empty workspace exits
`1` where its sibling gates exit `2`. For commands outside the table's scope,
read the terminal message, not just the code.

Exit code `3` is a completed run with an unsuccessful remediation outcome; it
is different from exit code `1`, which for those commands means the harness
itself failed. `ev-replay` reuses code `1` the way `3` is used elsewhere: a
replay that ran to completion exits `1` when at least one finding is still
vulnerable — the same code a failed `ev-replay` command reports (a
configuration or `EV_AUTH_*` mistake, which ends in a traceback). The two are
told apart by the artifact, not the code: a written `*_ev-replay.md` report
under `<repo>/security-scan/` means the replay completed and `1` is its
verdict; a traceback with no report means the command failed.

A scan can also finish with non-fatal stage errors while retaining exit code
`0`; use `run_manifest_*.json` and `*_errors.jsonl` to inspect those errors.
Exit `0` also covers one refusal: a scan that refuses `--resume` because the
checkpoint directory resolves inside the scanned repository prints the refusal
and exits `0` without running any stage, and in batch mode that repo is
counted "OK" in the "all N repos OK" summary. Check that a report was written
under `<repo>/security-scan/` — not just the exit code — before treating a
run as clean.

Exit `2` is a refusal rather than a failure, but it is not a promise that the
run spent nothing overall: the validation step has its own preflight, so a
configuration it rejects — a cross-vendor persona, for instance — surfaces as
`2` at the end of a scan whose detection stages have already run and billed.

### Batch exit codes

A batch run (`--repo-file`) reports one exit code for the whole invocation
and maps refusals onto it differently from a single-repo run. Refusals that
exit `2` on a single-repo run — an empty scan scope, an exploit-verification
input or reachability refusal, a validation gate — are recorded as an
ordinary per-repo failure and surface as batch exit `1`; read
`batch_summary.md` and each repo's terminal output to see which repos were
refused rather than broken. An authentication (VVAH-E001) or proxy/network
(VVAH-E002) failure aborts the whole batch with a bare traceback, and no
`*_errors.jsonl` record or run manifest is written for it — when a batch ends
in a traceback, diagnose from the terminal output.

### Exploit-verification refusals (exit 2)

Exploit verification (Beta — API only) refuses in more ways than the table row
can list; most of its preflight refusals exit `2`. The families:

- the collection file is missing or cannot be parsed;
- the collection gate fails — the refusal reads "cannot run as configured —
  fix and re-run:" with one line per failed check;
- a declared auth strategy is missing its credential, or an
  `EV_AUTH_STRATEGY` / `EV_AUTH_API_KEY_LOCATION` value is not one of the
  accepted ones;
- an unrecognized `step6_exploit_verification.on_unreachable` or
  `.on_auth_failure` value in the profile;
- mTLS client material that cannot be loaded — a missing file, non-PEM
  material, or a missing or wrong `EV_TARGET_CLIENT_KEY_PASSPHRASE`. These
  are reported through the collection gate's refusal, so read the itemized
  lines under it rather than assuming the collection itself is at fault;
- a `models.exploit_verification` role that is unusable or missing its
  backend credential. Exploit verification re-checks its roles at its own
  preflight and refuses with exit `2`, naming the role — the check that
  covers what the startup credential probe cannot see, such as a `--resume`
  run's checkpointed collection or a role on a transport its purpose cannot
  use. A gap the startup probe does see — a fresh run with the collection
  set and the role's backend credential missing — is reported there instead
  and exits `1`, like any other backend-credential gap found before a scan
  starts. Either exit is a configuration problem to fix up front, not the
  in-flight VVAH-E001 authentication failure described below;
- nothing in the collection reachable at the probe. This is also how a
  non-local `EV_TARGET_URL` surfaces: the configuration error is reported as
  unreachability ("no collection endpoint is reachable — every endpoint was
  skipped by the safety envelope — exploit verification only targets
  localhost"), so fix the URL rather than the network.

For a symptom-by-symptom table, see the
[troubleshooting section of exploit-verification.md](exploit-verification.md#troubleshooting).

## Named errors

### VVAH-E001: Authentication failure

The configured LLM provider rejected or could not use the credential. This is
a halt error and normally ends the command with exit code `1`.

Run `vvaharness doctor`, check the credential and endpoint for the selected
backend, then rerun. Use `--resume` to continue a scan after the credential
problem is corrected.

### VVAH-E002: Proxy, TLS, or network configuration failure

The request could not reach the configured provider because of a proxy, TLS,
certificate, gateway, or related network configuration problem. This is a halt
error and normally ends the command with exit code `1`.

Check the configured endpoint, proxy, and CA settings, then run
`vvaharness doctor`. See [SETUP_GUIDE.md](SETUP_GUIDE.md) for backend-specific
TLS settings. Retry only after correcting the configuration.

### VVAH-E003: Degenerate LLM response

The provider returned a response that fell below the response-quality floor:
too short or empty by characters or output tokens, or a long, well-formed
reply that is missing an expected marker. It is recorded as a non-fatal stage
error when the owning stage can continue; a stage may fail if its error
handling cannot recover. The first two consecutive failures for a stage only
log a `WARN VVAH-E003` line; the third consecutive failure for the same stage
raises. A `WARN VVAH-E003` on stderr during an otherwise healthy run is
expected, not a fault.

Review `*_errors.jsonl`, check the model and stage configuration, and consider
reducing prompt size or increasing the relevant output budget.

### VVAH-E004: Prompt exceeds the context ceiling

The prompt was rejected before dispatch because it exceeded the DeepAgents
context ceiling. The affected unit, such as a chunk or model pass, can fail
while the pipeline continues.

Reduce the scope or prompt payload, lower the relevant context limits, or split
the work into smaller units. See [configuration.md](configuration.md).

### VVAH-E005: Truncated LLM response

The provider response reached its output-token limit and the retry also failed
to produce a complete response. The affected unit can fail while the pipeline
continues.

Increase the relevant stage `max_tokens`, reduce the prompt payload, or choose
a model with lower reasoning overhead. See [configuration.md](configuration.md).

VVAH-E005 is raised on the `sdk` and `openai` transports. The `via:
deepagents` route — which carries the exploit-verification roles in every
shipped profile except `sdk.yaml`, where they run `via: sdk` — does not
detect or name a truncated response, so the absence of VVAH-E005 there is
not evidence that responses were complete.

## The error log (`*_errors.jsonl`)

Each record is one JSON object per line: `ts`, `stage`, `unit`, `error`, plus
any extra context fields the logging site adds (including an `error_code` such
as `VVAH-E003` when one applies). A record may carry `recovered: true`,
marking a transient the pipeline recovered from, and exception records carry
a `traceback` — redacted, and capped to its final 4000 characters.

Only `scan` (including each repo of a batch) writes the per-run
`*_errors.jsonl`; `remediate`, `validate`, and `ev-replay` write no error-log
records at all. Before a scan has resolved its per-run path — during
preflight, and for all of `doctor` — records are appended to
`pipeline-errors.jsonl` in the current working directory instead.

The manifest's `errors_by_stage` counts every logged record for a stage,
including transients the pipeline recovered from, so a non-zero count beside
a clean console does not mean coverage was lost. Cross-check `*_errors.jsonl`
(records the pipeline survived are stamped `recovered: true`) and the
report's Scan Health section, which reflects actual coverage. In batch mode
the manifest's `errors_by_stage` reflects only the last repo of the batch,
not the whole invocation.

## Where to look

- Terminal output gives the immediate error and recovery hint.
- `*_errors.jsonl` contains per-stage non-fatal errors when they are recorded.
- `run_manifest_*.json` contains stage health, timing, and error summaries for
  scans that write a manifest.
- `vvaharness doctor` checks configured backend readiness; it does not replace
  reviewing scan artifacts.
