# Changelog

## Unreleased

- Remove `lead` from the configured and delegable roles. The main session is now the lead and runs on the terminal-selected model, registering only as the `main` identity label with no selector, dispatch, or identity check. `startLeadAgent` no longer injects a `--model` and passes native arguments through unchanged; specialist roles keep their configured models and worker identity checks.
- Replace eight overlapping specialists with `investigator`, `scout` and `analyst`: GPT-5.6 Sol at `xhigh` handles difficult reasoning and controlled reproduction, while DeepSeek V4.1 Flash handles broad exploration and narrow evidence processing.
- Limit a native delegation wave to four distinct tasks, make the main session own the hypothesis registry and final acceptance, and require hypothesis, evidence, expected-signal and disproof framing.
- Require fast-role candidates to receive a fresh investigator challenge without claiming model-family-independent review; human review remains final.
- Migrate role catalogs and engagement history to schema 4. Installation backs up schema-3 catalogs and removed role files, while runtime migration preserves direct history and archives removed role topics.
- Print `getAgents` as aligned role and participant tables by default—role, provider, model, effort and specialization, with changed roles naming their packaged default—and keep the schema-4 JSON object behind `getAgents --json`.

## 0.2.0 — 2026-10-14

- Make `praise.json` the persistent source of truth for fixed-role model selections, dispatch, and lead startup; preserve selections on reinstallation.
- Consolidate the public commands into `install`, `setAgent`, `getAgents`, and `startLeadAgent`; initialize or resume the exact requested engagement before launching its configured lead.
- Install all nine specialist definitions with native delegation tools, canonical role topics, host-observed model provenance, and parent–child lineage.
- Route native tasks and register workers automatically; deliver durable peer messages and parent lifecycle notifications without manual CLI coordination.
- Replace the obsolete methodology and learning runtime with bounded JSON messaging, transactional schema-3 history migration, idempotent writes, and incremental audit recovery.
- Package integration assets in the wheel and back up reversible legacy-file removals while preserving unrelated OMP settings.
- Replace obsolete workflow tests with model persistence, scope isolation, delegation, delivery recovery, provenance, and installer rollback regressions.

## Earlier development notes

- Remove the active-scope tool-surface guard: shell, eval, write, edit, browser, network and filesystem access stay available inside an engagement. Scope tracking is retained for routing, data injection and the CLI-backed tools; the operator reviews agent actions.
- Allow `read` to reach harness-internal read-only resources (`omp://`, `artifact://`, `agent://`, `history://`) that the path gate previously misclassified as out-of-scope host paths.
- Drop the `headers_file` local-root confinement; the path resolves relative to the session cwd and the CLI still validates the JSON.
- Add independently written, VulnHunter-inspired source-review guidance to the existing crew: bounded coverage ledgers, input-free sensitive endpoints, indirect/stored/response dataflow, downstream scope propagation, shared-defense checks, and root-cause instance sweeps.
- Keep coverage in existing addressed messages and preserve runtime scope, request controls, model routing, proof/independence gates, and root-cause deduplication; add no VulnHunter runtime or publishing dependency.
- Replace prose chat APIs with addressed JSON messages, scoped short agent IDs, correlated replies, idempotency keys, and incremental durable inboxes.
- Share one resident JSONL runtime per engagement within an OMP process; push only addressed notifications at safe step boundaries without polling or automatic write replay.
- Emit workflow and reviewed-learning handoffs in the owning state transaction; keep scope, request budgets, evidence integrity, and independent approval authoritative.
- Reduce model context to compact valid JSON, artifact references, explicit full-detail reads, and freshly validated bounded approved lessons.
- Preserve schema-1 events and case history in the transactional schema-2 migration; retain append-only audit rendering outside the reply hot path.
- Cover isolation, crash/delivery recovery, bounded frames, stale learning artifacts, rollback, and failure paths with deterministic regressions.
- Load the generated crew catalog from the installed agent root, not the extensions directory, so a real installation authorizes routed spawns without catalog injection.
- Bound deep/expert/review task bodies together with shared scope instructions; reject transcript-shaped shared context while still allowing bounded scope framing.
- Require observed predecessor and reviewer identities to match the configured selector exactly, so an explicit `:max` identity cannot claim a `:high` lane while an effort-stripped SDK identity still matches.
- Re-invalidate review readiness when the recorded reviewer is no longer the configured review lane, and direct the reviewer to author its own assessment packet.

## 0.1.0 — 2026-10-05

- Introduce PraiseAssistant as a runnable, dependency-free evidence and execution control program rather than a machine snapshot.
- Use explicit work stages and one authoritative role catalog; preserve generic coding tasks outside scoped engagements.
- Separate source candidates, mechanical gates, runtime reproduction, independent final judgment, and patch validation.
- Add scoped target requests, shared request budgets, throttling, and evidence integrity checks.
- Add durable structured case state and serialized multi-agent chat with observed model identities.
- Add evidence-backed learning proposals, paired baseline evaluation, explicit independent promotion, retrieval, and rollback.
- Add conflict-aware OMP integration installation with backups and restoration.
- Keep local dependencies, legacy snapshots, credentials, and operational artifacts outside the tracked distribution.
- Replace personal backup documentation with architecture, role distribution, communication, learning, and installation guides.
