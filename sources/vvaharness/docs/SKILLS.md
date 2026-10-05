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
# vvaharness — Security Analysis Skills

This catalogs the security-analysis capabilities ("skills") built into the
pipeline, with the source file and prompt size for each. These are
**prompt-defined lenses**, not separately-trained detectors: the configured LLM
applies whichever lens(es) a code chunk matches. Depth varies by lens.

> Regenerate the numbers after prompt edits — sizes below reflect the current
> source tree.

## Summary

| Skill category | Count | Prompt lines (approx) |
|---|---|---|
| Scan-pipeline stages (s1–s9) | 9 (7 LLM + s9 deterministic; s5 gates deterministic, plus a default-on LLM pre-dedup reusing the s7 prompt) | ~558 |
| Specialist security lenses | 11 | ~619 |
| Language security lenses | 42 | ~650 |
| Threat-model baselines | 5 repo-kinds + STRIDE | 30 items |
| Shared prompt fragments | 4 | ~101 |
| Remediation Agent (s10, `remediate` cmd) | 1 LLM skill | 49 ln (5,016 ch) |
| Validation panel subagents (s11, `validate` cmd) | 2 always-on + 1 conditional | `security-architect` + `penetration-tester` (+ `cross-repo-analyzer`, only on 2+ repo fixes) |
| **Total distinct scan-side skills** | **~66** | **~1,928 prompt lines** |

(The **66** is the scan-side total: 9 scan-pipeline stages + 11 specialists +
42 languages + 4 fragments. The prompt-line total (1,928) sums the LLM-stage
system prompts (558), specialist lenses (619), language lenses (650), and shared
fragments (101); baseline items are counted separately. The stage figures are the
composed system prompt each stage sends, so a fragment interpolated into s4 or
s6 is counted in both its own row and that stage's. Stage numbers run to s11:
**s10 — Remediate** (the `remediate` command, an LLM skill on `models.remediate`)
and **s11 — Validate** (the `validate` command's agentic panel) are post-scan
command stages — listed separately above, not folded into the 66. Both run
automatically at the end of `scan` in sdk/full, but are disabled in
default/taint. Standalone commands remain available. Exploit
verification — Beta, API-only, localhost-only, and off unless
`EV_API_COLLECTION` is set — carries its own model roles (`classify`, `mapper`,
`attacker`, `judge`) and is not counted here: it adds six prompts, ~221 raw /
~236 composed lines (roughly 11-12% on top of the counted 1,928). See
[exploit-verification.md](exploit-verification.md).)

---

## 1. Pipeline analysis stages
`vvaharness/pipeline/stages/*.py` (s9 in `vvaharness/report/enrich.py`)

| # | Skill | File | Code LOC | System prompt | Purpose |
|---|---|---|---|---|---|
| s1 | Pre-process / recon | `s1_preprocess.py` | 1,998 | 81 ln (4,659 ch) | File inventory, call-graph (LLM seed + regex supplement), entry points & sinks |
| s2 | Threat modeling | `s2_threatmodel.py` | 1,546 | 66 ln (3,614 ch) | STRIDE threats, assets, trust boundaries, baseline checklists |
| s3 | Decompose | `s3_decompose.py` | 2,707 | 44 ln (2,032 ch) | Taint chunks, catch-all sweep, specialist scoping |
| s4 | Deep-dive (discovery) | `s4_deepdive.py` | 2,093 | 163 ln (8,850 ch) | Per-chunk vulnerability discovery + research lens |
| s5 | Pre-filter | `s5_prefilter.py` | 335 | — (deterministic gates; the default profile's pre-verify pass reuses the s7 dedup prompt) | Confidence + evidence gates |
| s6 | Adversarial verify | `s6_verify.py` | 710 | 113 ln (6,077 ch) | Second-opinion reviewer; false-positive suppression |
| s7 | Dedup | `s7_dedup.py` | 468 | 40 ln (1,965 ch) | Semantic + deterministic dedup |
| s8 | Exploit-chain | `s8_chain.py` | 565 | 51 ln (2,289 ch) | Multi-hop chains, severity ranking |
| s9 | SARIF / CVSS / CWE | `report/enrich.py` | — | — (deterministic) | CVSS 3.1, CWE mapping, SARIF 2.1.0 emit |

Two further stages run **after** the scan, each owned by a standalone command —
and also run at the end of `scan` when their respective
`step_remediate.enabled` / `step_validate.enabled` settings are true (sdk/full).
Both settings are false in default/taint. `--remediate` enables in-scan S10
only; S11 requires its own config opt-in, or standalone `validate`:

- **s10 — Remediate** (`remediate` command · `vvaharness/remediation_agent/`).
  An LLM skill on the `models.remediate` role — system prompt **49 ln (5,016 ch)**
  (`remediation_agent/prompts.py`); fix mode substitutes a 56-line orchestrator
  prompt and adds a 21-line fixer sub-agent prompt from the same module. It
  walks the verified findings and proposes a
  minimal fix per finding, writing per-finding DTOs under
  `<repo>/security-remediation/`. In fix mode (the in-scan path forces it) it
  applies the edits to the repo; an opt-in deny-list/playbook policy gate can
  post-filter forbidden-path edits.
- **s11 — Validate** (`validate` command · DeepAgents runtime by default ·
  `vvaharness/validation/`). A deterministic discovery pass (no model spend) locates DTOs awaiting
  validation, then an
  agentic adversarial panel — two always-on personas, a `security-architect`
  and a `penetration-tester` (the shared exploration brief passed to the panel
  is augmented with per-CWE bypass cheatsheets from
  `./inputs/validator_hints.yaml`, available to all personas), plus a
  `cross-repo-analyzer` the orchestrator is instructed to spawn only when the
  fix spans two or more repositories, returning `skip` for gates outside its
  multi-repo perspective — scores each fix against weighted
  gates (root_cause, instance_coverage, no_new_vulnerabilities,
  security_best_practices) and writes a Fixed / Partially Fixed / Not Fixed /
  Inconclusive verdict into the DTO. The default runtime is the DeepAgents
  backend (`via: deepagents`, as shipped in `default.yaml`); the `cli` and
  `sdk` backends run the bundled Claude Agent SDK instead. On either runtime
  the panel is read-only against the repo — no patch application, no Docker.

An optional **`autoexclude`** role (`s1_autoexclude.py`, 511 LOC) runs ahead of
s1 when `--auto-step1` is passed **or** when `step1.auto_exclude` is truthy in
the active profile. All four shipped profiles set `auto_exclude: true`, so the
role runs by default on every one of them — the registered code default is
`false`, so each profile is an explicit opt-in. It can be disabled with
`--no-auto-step1` (which wins over both) or by supplying `--step1-config` (an
explicit Step-1 overlay also suppresses the auto-derivation). It is a cheap
one-shot survey that
derives a per-target Step-1 exclusion overlay. Its proposals pass a
deterministic language-erasure veto before being applied — see
[configuration.md → step1](configuration.md#step1--repo-intake--file-inventory).

## 2. Specialist security lenses
`vvaharness/lang/hints.py` → `SPECIALIST_HINTS` (selected via `config…step3.specialists`)

| Specialist | Prompt LOC | Chars | Focus |
|---|---|---|---|
| injection | 106 | 5,223 | Injection (SQL, command, LDAP, XPath, XML/XXE, SSRF, path traversal, SSTI, open redirect, header injection, ReDoS) |
| iac | 83 | 4,624 | Terraform / Dockerfile / k8s / Helm / GH-Actions / Ansible |
| sensitive-data | 82 | 4,517 | Error-message leakage, PII in logs/responses, plaintext storage |
| csrf | 79 | 4,267 | State-changing endpoints missing CSRF token / SameSite |
| hardcoded-creds | 53 | 3,261 | Literal secrets in source and config |
| log-injection | 58 | 3,134 | Attacker-controlled data in log calls; missing security-event logging |
| access-control | 40 | 2,526 | AuthZ, IDOR, privilege escalation, forced browsing |
| batch-etl | 36 | 2,174 | Batch/ETL pipeline & data-flow issues |
| logic-bug | 31 | 1,856 | Business-logic flaws, race conditions, TOCTOU |
| deserialization | 28 | 1,725 | Unsafe deserialization / object injection |
| crypto | 23 | 1,301 | Weak/missing crypto, key & secret handling |

Default-active in all four shipped profiles: all eleven. Ten of the eleven are
surface-gated before any model call — `logic-bug` has no gate entry and always
runs — and the ten gates are not equally narrow: `deserialization`,
`hardcoded-creds` and `iac` drop out entirely on a repository without that
surface, while `csrf` runs on any authorization surface and `sensitive-data` /
`log-injection` on any repository with entry points.

## 3. Threat-model baselines (s2)
`vvaharness/pipeline/stages/s2_threatmodel.py` → `_BASELINES`, `_STRIDE_BY_KIND`

| Repo kind | Items | Standard |
|---|---|---|
| web-api | 10 | OWASP Top 10 (A01–A05/A07/A08/A10 + XSS, CSRF) |
| native | 6 | CWE memory-safety (119/787, 416, …) |
| mobile | 5 | OWASP MASVS / Mobile (M1–M9) |
| iac | 5 | IaC misconfiguration |
| library | 4 | API / supply-chain |

STRIDE mapping over 7 entry-point kinds: `network, framework, ipc, file, cli, deserialization, other`.

## 4. Language security lenses (42)
`vvaharness/lang/hints.py` → `LANG_HINTS` (42 languages); `EXT_TO_LANG` maps 132 extensions; `LANG_DISPLAY` 47 kinds.

Languages: ABAP, Ansible, Assembly, Batch, C/C++, Clojure, COBOL, Crystal, C#,
Dart, Elixir, Erlang, F#, Go, Groovy, Haskell, Java, JavaScript, JCL, Julia,
Kotlin, Lua, Nim, Objective-C, OCaml, Perl, PHP, PowerShell, Python, R, Ruby,
Rust, Scala, Shell, Solidity, SQL, Swift, Terraform, TypeScript, VB.NET,
web-templates, Zig.
(Richest: python 45 ln, c-cpp 28, typescript 25, java 23. Thinnest: scala/erlang/groovy/lua ≈ 8.)

## 5. Shared prompt fragments
`vvaharness/util/prompts.py`

| Fragment | LOC | Used by |
|---|---|---|
| `EXCLUSION_RULES` | 53 | s4, s6 (what NOT to flag) |
| `SEVERITY_GUIDANCE` | 24 | s4 |
| `SELF_VERIFICATION` | 17 | s4 |
| `EXHAUSTIVENESS` | 7 | s4 |

---

## 6. Taint analysis engine
`vvaharness/pipeline/stages/callgraph_engine/` — structured dataflow evidence layered on top of the s1/s3 call graph.

The engine produces **typed transfer edges** (not just reachability hops) that trace how tainted data moves through code. Evidence is attached to each finding as a labelled step sequence so s4 and s6 reason over full paths, not summaries.

### Transfer edge types

| Edge type | Meaning |
|---|---|
| `assign` | Direct assignment or local alias (`x = tainted`) |
| `arg_to_param` | Argument passed into a callee — interprocedural |
| `return_to_local` | Callee return value captured — interprocedural |
| `field_write` | Taint stored to an object field or attribute |
| `field_read` | Taint loaded from an object field or attribute |
| `container_put` | Taint inserted into a list, dict, set, or array |
| `container_get` | Taint extracted from a container |
| `sanitize` | Explicit neutralization — flow is suppressed from findings |
| `condition` | Branch-gated taint. The type is defined in the models, but the current scanner does not emit condition transfers (see [models.md](models.md)) |
| `reflect` | Dynamic dispatch via reflection. **Java:** `getMethod`/`getDeclaredMethod`/`getDeclaredField`/`forName`/`invoke`/`newInstance`/`MethodHandles.lookup()`. **Python:** `getattr`/`setattr`/`__import__`/`eval`/`exec`/`compile`/`vars`/`type`. **C#:** `GetMethod`/`GetType`/`Invoke`/`CreateDelegate`/`Activator.CreateInstance`/`Assembly.Load`/`Type.InvokeMember`. |
| `framework` | Framework lifecycle source — parameter injected by the runtime |
| `source` | Marks the initial taint source |
| `return_to_sink` | Return value flowing directly to a sink |
| `local_to_sink` | Local variable flowing directly to a sink |

### Source detection — automatic, no annotation required

| Source type | Detected in |
|---|---|
| HTTP request parameters | Django (`request.GET`/`POST`), Spring (`@RequestParam`, `@PathVariable`, `@RequestBody`), ASP.NET (`Request.QueryString`, `Request.Form`, `Request["…"]`) |
| URL route parameters | Spring `@GetMapping`/`@PostMapping` path variables, Django `urlpatterns` captures, ASP.NET `[HttpGet("{id}")]` route templates |
| Response output | Django `HttpResponse`/`JsonResponse`, Spring `ResponseEntity`/`@ResponseBody`, ASP.NET `Content`/`Write` sinks — flagged as potential XSS risk |

**Sanitized paths are suppressed.** When the engine detects an explicit sanitizer on a flow (e.g. `escape()`, `sanitize()`, encoder calls), the flow is removed from findings rather than surfaced as a false positive.

**Reflection and dynamic dispatch** are identified with `reflect` edges so the LLM can assess whether reflection bypasses a sanitizer or widens attack surface.

**Field and container flow** — taint is tracked through object attributes, dict/list put/get, and local aliases so multi-hop paths through data structures are not silently dropped.

**Languages: Python, Java, C#** for all of the above.

---

### Known limitation
The call graph is a textual/AST-hybrid — it resolves plain calls and
interprocedural flows well for direct and attribute-chained calls. Highly
dynamic patterns (runtime class loading, bytecode manipulation, interface/OOP
dispatch through deep polymorphism) remain partially modelled. Treat findings
as triage candidates requiring human review.