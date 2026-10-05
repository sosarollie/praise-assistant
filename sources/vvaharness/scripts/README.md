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

# Developer helper scripts

These are **maintainer/debug utilities**, not part of the installed package
(`pip install .` installs only the `vvaharness` console command). Run them from
a source checkout with the package importable on `PYTHONPATH` (e.g. after
`pip install -e .`):

```bash
python3 scripts/<script>.py [args]
```

| Script | What it does |
|---|---|
| `show_exclusions.py` | Print the effective Step-1 exclusion sets (dirs / extensions / globs) and the size gate, tagging each entry as built-in vs config-supplied. Resolves config the same way the CLI does — `./config.yaml` if present, else the packaged default profile. Useful for understanding why a file was or wasn't scanned. |
| `inspect_chunks.py` | Inspect a scanned target's Step-1/2/3 checkpoints — list chunks, their files, risk ranks, threat coverage, and taint reachability (orphaned-sink BFS; tune depth with `--max-hops`, default 12). `--file <path>` reports which chunk(s) contain a file (and whether it was in scope or excluded by s1); `--json [path]` dumps the context, orphaned sinks, and chunks as JSON to a file, or to stdout if no path is given. Run with `--repo <target>`; checkpoints are read from the SQLite state DB at `$VVAHARNESS_STATE_DIR/vvaharness.db` (default `~/.vvaharness/state/vvaharness.db`), keyed by `run_id`, **not** from the target repo. The `run_id` is derived from the absolute `--repo` path — pass `--run-id` if the scan ran against a different path, and `--state-dir` to override the state root. Run the pipeline with `--stop-after s3` first so the checkpoints exist. Checkpoints are JSON validated against the package's per-step pydantic schema (size-capped). |
| `backfill_cwe.py` | Backfill / normalise CWE identifiers on an existing findings set. |

They are intentionally dependency-light. `show_exclusions.py` and
`inspect_chunks.py` are read-only with respect to scan outputs.
`backfill_cwe.py` is the exception: it **modifies the findings markdown in
place** (`md_path.write_text(...)`), saving a `<report>.md.bak` copy on first
run; it also (re)writes a SARIF file. Use its `--dry-run` flag to preview
changes without writing. Because all three live outside the `vvaharness`
package they are excluded from the wheel by design; treat them as repo-local
tooling.
