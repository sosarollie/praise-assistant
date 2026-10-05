# Standing rules — authorized security testing

Applies to bug bounty and penetration testing work. Load the matching skill
before acting; each is one `read` away. Do not work from memory of them.

| Situation | Load first |
|---|---|
| Any live target, authorized or not yet confirmed | `skill://bounty-report` |
| Source-code scan, SAST, taint, PoC against a local app | `skill://frame-scan` |
| Whole-repo audit, authz/business-logic review, remediation, S11 | `skill://vvaharness-scan` |
| Scoring a finding, checking if a bug class pays, prior-art check | `skill://hackerone-prior-art` |
| A patch exists and needs an independent check | `skill://vva-validation-scoring` |

## Hard requirements

1. **Confirm authorization before any active testing.** State the program, the
   asset, and the in-scope basis in one line. If that basis is missing or the
   target is not covered, stop and say what is needed. Never probe to find out.
2. **Only in-scope assets.** Out-of-scope domains, sibling properties, and
   third-party SaaS (support vendors, status pages, CDN-hosted apps) are out
   unless named in scope.
3. **Non-destructive.** No denial-of-service, no persistence, no bulk data
   access. Prove impact with the smallest artifact that demonstrates it — one
   record, one request. A finding that is not reproducible from a clean state
   twice is not ready to report.
4. **Credentials you find are not yours.** Report the location, never use or
   paste the value.
5. **Rate-limit yourself** and keep traffic unremarkable.
6. **Never present a finding as proven without proof.** Distinguish what was
   observed from what was inferred, and say which check failed to confirm.

## Evidence discipline

Anchor every claim to `file:line`, an exact request/response, or an observed
command result. Name a blocked bypass as driver-, framework-, or
app-level-blocking — the difference decides whether a finding survives triage.
Triage candidates are not findings; say so plainly rather than inflating.

## Pentest model workflow

The crew router in `extensions/crew-router.js` pins subagent models and takes
precedence over `task.agentModelOverrides`. Keep both mappings aligned. Reload
extensions with `/reload` or restart OMP after changing the router; already-running
agents retain their existing model.

- Recon stays on Space Bunny; ordinary source discovery stays on DeepSeek Flash.
- Mimo gates candidates before expensive work. A rejected gate does not go to a
  PoC lane.
- Routine planning uses DeepSeek V4.1 Flash at high reasoning. The lead uses
  Codex Daybreak Blue at high reasoning; slow reasoning uses DeepSeek V4 Pro
  at max. No explicit Sol selector is assigned to a pentesting role.
- Gated ordinary PoCs use DeepSeek V4 Pro at high reasoning. Unresolved deep
  source analysis and gated chain escalation use Pro at max reasoning.
  Include the prior Flash pass's evidence and specific unresolved gap.
- A bounded defensive source review uses Daybreak Blue through
  `security-reviewer`; this is analysis, not an independent final verdict.
- Routine verdicts and patch checks stay on GLM Flash; deep adjudication uses
  GLM at max, with a different-family alternate when needed. Flash and Pro
  share the DeepSeek family and cannot independently judge one another.
  The router filters against the parent; checkers must also verify the actual
  producer model in `agentschat.md` before issuing a verdict.

Capacity policy:

- `providers.maxInFlightRequests.openai-codex: 3` limits concurrent provider
  requests across local OMP processes sharing this configuration root. It is
  not a three-agent limit and does not increase account entitlement.
- Budget Blue against Codex's reported account windows; budget DeepSeek Flash
  and Pro against OpenCode Go's windows, including its monthly allowance.
- Read `omp usage --redact` before and after a bounded work batch. Percentage
  remaining is not a request count, token budget, or billing estimate.
- Start with Flash/free lanes for routine work and escalate only gated evidence
  or a bounded unresolved analysis question. Observe quota per accepted
  candidate, wall time, and errors before expanding; preserve at least 20% in
  the active quota windows of both providers as an operating target.
  This reserve is procedural, not an automatic preflight block.
- Do not move bulk recon to Codex or increase target traffic because model
  capacity increased. Keep target authorization, rate limits, and proof bars.

Use the added reasoning capacity for role/resource authorization matrices,
cross-file trust-boundary closure, and minimal reproduction design. Blue traces
defensive mitigations; DeepSeek Pro turns gated evidence into a minimal proof;
a different-family checker adjudicates artifacts rather than model prose.

## Engagement workspace

- Linux/Kali engagements live in `/home/kali/pentest-workspace/<target>/`.
  Use one real engagement slug per program/scope boundary, with
  `agentschat.md` and `evidence/` inside that directory. No workspace-root log.
- Launch OMP with `--cwd /home/kali/pentest-workspace/<target>` so the workspace
  `AGENTS.md` is discovered. If starting elsewhere, read that file before
  engagement work and use absolute engagement paths.
- Pass the engagement directory, log path, evidence path, and authorized scope
  to every delegated task. The additional workspace root does not authorize
  testing or access to another engagement's records.
- Initialize a target directory only for an identified engagement. Record the
  program, assets, and in-scope basis before active testing. Do not invent a
  target or create an empty global log to initialize the workspace.
