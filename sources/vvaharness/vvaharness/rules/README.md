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

# vvaharness/rules

First-party rule assets and the external-artifact contract for the taint-first
pipeline.

## Canonical Artifact Model

This project uses a provenance-preserving artifact model:

- Shipped baseline: the first-party `generic.kb.yaml` asset for S4
  confirm/refute guidance. Rules-mode S0 has no bundled source/sink baseline.
- Optional external artifacts: maintainers may compile public corpora and local
  overlays into `sources.generated.yaml` / `sinks.generated.yaml`, then point S0
  at their absolute paths. Those generated third-party corpora are not bundled.
- Runtime: no corpus clone is required to run; rules-mode S0 returns an empty
  seed unless applicable source/sink artifacts are configured.

Design goals:

- deterministic behavior for a fixed set of configured artifacts
- offline-friendly runtime (no registry dependency)
- explicit provenance and licensing for externally generated corpora
- extensibility via custom overlays without code changes

| File | Consumer | Purpose |
|---|---|---|
| `sources.generated.yaml` / `sinks.generated.yaml` *(external, optional)* | `s0_seed` callgraph engine | Source/sink callsite patterns compiled from operator-selected corpora. Configure them through `step0.sources_yaml` / `step0.sinks_yaml`; they are not distributed with vvaharness. |
| `generic.kb.yaml` | `s4_deepdive` | User-facing **OWASP/CWE starter pack**. Broad, curated entries for the common attack shapes most users want out of the box. Can be written directly with `python -m vvaharness.rules.build_kb --generic-out ...`. |
| `cwe_kb.yaml` *(external legacy name, optional)* | `s4_deepdive` | Additional per-CWE taint knowledge. Loaded when present in an explicitly selected rules directory; it is not distributed. |
| `*.kb.yaml` | `s4_deepdive` | **Extension corpora (external only).** Additional curated entries are loaded **only** when passed explicitly via `CweKB.load(overlays=[...])`. They are **not** auto-merged from this directory and **must not** be committed here or packaged — org-specific reviewer memory has to live OUTSIDE the distribution and be referenced by path. |

Rule planes are intentionally separate:

- s0 callgraph seed plane:
   optional external `sources.generated.yaml` + `sinks.generated.yaml`
   (source/sink callsite matching). In `callgraph_detection: llm` mode only,
   deterministic observed-call heuristics may supplement sparse model output;
   rules mode does not apply that supplement.
- s4 confirm/refute plane:
   shipped `generic.kb.yaml` plus explicitly configured external overlays
   (sanitizers, non-sanitizers, fp-checks)

The `*.kb.yaml` files are not transformed into `sources.generated.yaml` or
`sinks.generated.yaml`; they are consumed directly by the CWE KB loader.

## Artifact Provenance And Versioning

Generated source/sink artifacts should include a top-level provenance block
(`vvah_artifact`) recording:

- artifact_type (`sources` or `sinks`)
- generated_at_utc
- builder_version
- strict_callgraph mode used
- callgraph_languages included
- source inputs (corpus paths + git SHAs when available)
- optional overlay inputs (`--llm-sources-in`, `--llm-sinks-in`)
- artifact_sha256 (of normalized `rules` payload)

This metadata is for traceability only. Runtime matching consumes `rules` and
ignores unrelated top-level keys.

## Build Workflow

The canonical release workflow is:

1. Write or refresh `generic.kb.yaml` for the shipped OWASP/CWE starter pack.
2. Optionally apply organization overlays or an LLM polish pass.
3. Run `build_kb` in strict mode to produce `generic.kb.yaml` and any optional
   external callgraph artifacts.
4. Keep third-party-derived callgraph artifacts outside the distribution and
   retain their provenance/licensing metadata alongside them.

End users do not need corpus clones to run the pipeline. To obtain a non-empty
rules-mode S0 seed, configure source/sink artifacts explicitly; otherwise S0
returns an empty seed and normal downstream discovery continues.

## LLM-Produced Rule Inputs

`build_kb` supports optional LLM inputs:

- `--llm-sources-in`
- `--llm-sinks-in`
- `--llm-generic`

These are treated as overlays and normalized through the same callgraph rule
validation path as corpus-derived rules. In strict mode, missing required
metadata (for example `metadata.cwe`) fails the build.

When `--generic-out` is used, the builder writes the small OWASP/CWE starter
pack directly. Passing `--llm-generic` asks the low-cost Haiku model to polish
the text before it is written. That path is intentionally fixed to Haiku so the
rule-creation experience stays cheap by default.

OWASP attack patterns and antipatterns are related but not the same thing.
Attack patterns describe the exploit shape; antipatterns describe the unsafe
coding or design habit that tends to create the exploit. The generic starter
pack includes both kinds of guidance so users can spot the bug and the bad
practice that caused it.

Recommended policy:

- use strict mode in release builds
- keep non-strict mode for local exploration only
- require review for LLM-originated overlays before artifact publication

## Runtime Loading Contract

- s0 rules mode loads explicitly configured source/sink artifacts and returns
   an empty seed when neither artifact exists or no rules apply. S0 LLM mode
   can supplement sparse successful model classifications with deterministic
   API heuristics over AST-observed calls; an LLM failure falls back to rules.
- s0 does not require an LLM to consume rule artifacts.
- s4 loads CWE KB entries from shipped `generic.kb.yaml` by default; the legacy
   `cwe_kb.yaml` name is loaded only if present, and additional `*.kb.yaml`
   corpora are opt-in via `rules.kb_overlays`.

The shipped S4 knowledge baseline is independent of local corpus clones.
External S0 artifacts intentionally change seed coverage and should carry
their own provenance.

## Conventions

- Rule id: `vvah.<source|sink>.<lang>.<slug>` — the trailing slug becomes
  `Sink.function` / `EntryPoint.function` when no snippet is available.
- `metadata.ep_kind`: one of `network | ipc | file | cli | deserialization` —
  maps onto `EntryPoint.kind`.
- `severity: INFO` — these are *seeds*, not findings; they never reach the
  report on their own. s4/s6 decide whether a seeded path is exploitable.

## Adding a framework entry point (s0)

1. Add a rule to an external source artifact and configure its absolute path in
   `step0.sources_yaml`.
2. Run `vvaharness scan --config vvaharness/config/profiles/taint.yaml
   --repo <fixture> --stop-after s1` and confirm the new entry points appear
   in the s1 checkpoint.

## Generic Starter Pack

```bash
python -m vvaharness.rules.build_kb \
   --generic-out vvaharness/rules/generic.kb.yaml
```

Add `--llm-generic` if you want the builder to polish the pack with the
low-cost Haiku model before writing it.

Corpus-based compilation remains available for maintainers who want broader
external source/sink coverage, but it is not the primary user path and its
outputs are not bundled in the distribution.

## Adding a CWE-KB corpus (s4)

Org-specific corpora must live **outside** this package (never committed here,
never packaged into the wheel — see the explicit allowlist in `pyproject.toml`).

1. Emit `<name>.kb.yaml` with the `entries:` schema demonstrated by
   `generic.kb.yaml` somewhere outside `vvaharness/`. Set `origin: <name>` on
   each entry.
2. List items may be language-scoped with a `lang:` prefix, e.g.
   `"java: PreparedStatement.setString"`; unprefixed items apply everywhere.
3. Reference the file explicitly via `CweKB.load(overlays=["/path/to/<name>.kb.yaml"]).
   Files in this directory are **not** auto-discovered; only `cwe_kb.yaml`
   (legacy) and `generic.kb.yaml` load by default.
