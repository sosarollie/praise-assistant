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

# `repos.csv` — Batch Scan Input

The `--repo-file repos.csv` flag drives batch mode: every row is cloned (or
read from a local path) and scanned. With `--group-by-app`, all repos that
share an `AppId` are staged under one directory and scanned **once**, producing
one report per application instead of one per repo.

A worked example ships at `inputs/repos.example.csv`. Note: the CSV parser does
**not** support `#` comment lines or a leading blank line — the very first row
of the file must be the header. (Unlike the `.txt` batch format, which skips
`#`-comment and blank lines.)

## Columns

| Column | Required | Aliases (case-insensitive) | Meaning |
|---|---|---|---|
| `AppId` | **yes** | `application_id`, `app_id`, `applicationid` | Your application / project / asset identifier. Free-form string; used for grouping, CMDB lookup, and tagged into SARIF `run.properties.applicationId`. |
| `RepoName` | **yes** | `repository_name`, `repo_name`, `repo` | Repo slug (e.g. `org/project` or `project`). Used as the module name in report filenames and, when `Path` is blank, to build the clone URL. |
| `Path` | no | `url`, `repo_url`, `ref` | Where to get the code. Either a **git URL** (`https://…`, `http://…`, `ssh://…`, `git@…`, or anything ending in `.git`) or an **existing local directory**. If blank/absent, the URL is derived as `{batch.git_base_url}/{RepoName}.git`. |

Any other columns in the file are **ignored** — you can keep owner, tier,
notes, etc. alongside and the parser won't care.

## Rules

- **The header must be the literal first row** of the file. Column names are
  matched case-insensitively against the aliases above; column order is free.
  `#` comment lines and leading blank lines are **not** skipped before the
  header (unlike the `.txt` batch format), so the file must start with the
  column header.
- Encoding: UTF-8 (BOM tolerated).
- Availability limits: the file may be at most **64 MiB** on disk and contain
  at most **200,000 data rows**. Larger batches must be split into multiple
  manifests. Parsing is streamed under both limits.
- Blank rows are skipped. Rows where both `AppId` and `RepoName` are empty
  are skipped; a row with only one of them is a validation error.
- Whenever a row needs its URL derived — there is **no `Path` column at all**,
  or the column exists but a row leaves it **blank** — `config.yaml:
  batch.git_base_url` (or env `GIT_BASE_URL`) **must** be set. If it is unset
  and a blank/absent `Path` needs derivation, the batch aborts before cloning.
- A non-empty `Path` that is neither a recognisable git URL nor an existing
  local directory is a validation error.
- A `Path` that begins with `-` is rejected (it would otherwise be read by
  `git clone` as an option rather than a URL).
- Duplicate clone targets across rows are rejected. The check applies to the
  **resolved** location: an explicit `Path`, or — when `Path` is blank — the
  URL derived from `RepoName`. So two rows that resolve to the same URL
  (e.g. the same `RepoName` with blank `Path`) are rejected as duplicates.

> The batch list is a **trust boundary**: it is assumed to be authored by a
> trusted operator. Restrict it to HTTPS URLs on hosts you control, and never
> accept a list from an untrusted source — a `Path` URL determines which host
> receives the configured git token. Any inline `user:token@host` credential in
> a `Path` is masked from the logs and `batch_summary.md`, but is still sent to
> that host at clone time, so only point rows at hosts you trust.
- The whole file is validated up-front; **any** error aborts the batch before
  the first clone.

## Filtering

`config.yaml: batch.skip_repo_patterns` is a list of case-insensitive
`fnmatch` globs applied to `RepoName`. Matching rows are dropped before
cloning — use it to exclude test-automation / fixture repos, e.g.:

```yaml
batch:
  skip_repo_patterns:
    - "*-automation*"
    - "*-karate*"
    - "*e2e*"
```

## Examples

**Minimal — two columns, URLs derived from `batch.git_base_url`:**
```csv
AppId,RepoName
10001,payments-core
10001,payments-gateway
```

**Explicit paths — mix of remote URLs and local checkouts:**
```csv
AppId,RepoName,Path
10001,payments-core,https://github.com/example-org/payments-core.git
10001,payments-admin-ui,/opt/checkouts/payments-admin-ui
10002,auth-service,git@github.com:example-org/auth-service.git
```

**Aliased headers + extra ignored columns:**
```csv
application_id,repo_name,url,Owner,Tier
10003,risk-engine,https://github.com/example-org/risk-engine.git,team-risk,1
```

## Running

```sh
vvaharness scan --repo-file repos.csv --workspace ./scans --group-by-app --auto-step1 --keep-clones
```

Outputs for **cloned (remote) repos** land in `./scans/<AppId>/security-scan/`
(grouped) or `./scans/<RepoName>/security-scan/` (ungrouped; the `RepoName` is sanitised for filesystem use, so a slug like `org/project` becomes `org_project`). In **ungrouped**
mode a row whose `Path` is an **existing local directory** is scanned in place,
so its `security-scan/` is written **inside that source directory**, not under
`./scans/`. Under `--group-by-app`, a local directory is instead **copied**
(`.git` excluded) into `./scans/<AppId>/<slug>/` and scanned there, so its
`security-scan/` lands under `./scans/`. Pipeline checkpoints always go to the SQLite state DB at
`$VVAHARNESS_STATE_DIR/vvaharness.db` (default `~/.vvaharness/state/…`),
never inside the source. Either way a `./scans/batch_summary.md` is written.

---
