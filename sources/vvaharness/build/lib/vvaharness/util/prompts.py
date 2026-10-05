# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Shared prompt blocks used by s4 (researchers), s6 (verifiers), and s8 (chain analysis).

SAST triage criteria, consolidated for this pipeline — groups exclusions
by rationale (A–E) and folds the evidence gate into the self-verification
checklist.
"""

EXCLUSION_RULES = """\
OUT OF SCOPE — do not report:

A. NO REAL ATTACKER
   - Code that is unreachable in production: tests, fixtures, samples, dead branches,
     build/tooling scripts run only on a developer's own workstation.
   - Inputs that can only be set by someone who already has shell or deploy access
     to the same host (local argv, local env). Exception: if the value crosses a
     boundary — CI/CD job parameters, scheduler args, shared config in a repo or
     mount that a different team or service can write — treat it as untrusted and
     report (usually LOW).

B. NO SECURITY IMPACT
   - Crashes from bad config, missing keys, import failures, or null derefs that
     don't expose data or grant access.
   - Functionality working as designed (legacy crypto kept for migration,
     compression, intentional wildcard CORS on a public asset, etc.).
   - Non-security randomness or placeholder secrets (jitter, test seeds,
     dev-profile fallbacks) when the prod value is injected from Vault/HSM/KMS.

C. WRONG LAYER
   - Server-side bug classes (SSRF, authZ, path traversal) raised against pure
     client/browser code — enforcement belongs to the service.
   - Memory-corruption findings in managed languages (Java, C#, Go, Python, JS)
     unless the code drops into JNI / cgo / unsafe / native bindings.
   - "../" in object-store or blob keys where the key space is flat and no
     filesystem boundary exists to cross.
   - SSRF where only the path is influenced; attacker must steer host or scheme.

D. HANDLED ELSEWHERE
   - Vulnerable third-party library versions — covered by the SCA/dependency
     pipeline, not this scan.
   - Pure volumetric / rate-limit DoS — infra concern. Still report
     input-driven complexity blowups (regex backtracking, recursive expansion,
     unbounded allocation from a single request).

E. NOISE FLOOR
   - Log injection / log forging with no downstream parser.
   - Prompt text passed to an LLM (tracked under the AI-governance program,
     not SAST).
   - Theoretical best-practice gaps with no demonstrated path to data exposure,
     auth bypass, or code execution.
     
F. INTENTIONALLY VULNERABLE TARGET (benchmark/training/CTF corpora)
   - If the target repository is itself a known vulnerability benchmark,
     CTF, or training corpus (self-documented "intentionally vulnerable" /
     "for teaching purposes" comments, OWASP-style labs, etc.), Rule A's
     "no real attacker" and Rule B's "working as designed" do NOT apply on
     the basis of that intent alone. The deliberate vulnerability is the
     object of the scan, not a mitigating context — report it exactly as
     you would in a production codebase, using the same reachability/impact
     analysis. Only drop a finding under A–E for a reason independent of
     "this is a training app" (e.g., genuinely unreachable/dead code,
     already-neutralized by a framework control)."""

SELF_VERIFICATION = """\
GATE EVERY FINDING ON THESE FIVE CHECKS — drop it if any fail:

1. REACHABLE   An external or lower-privileged caller can actually hit this
               code path. Walk backward from the sink and name the entry point.
2. UNMITIGATED No validation, encoding, allow-list, or framework control
               between source and sink already neutralizes it.
3. CONCRETE    You can state the exact payload and the exact effect in one
               sentence. "Could potentially" = not a finding.
4. IN SCOPE    It does not match any exclusion group A–F above.
5. CITED       Both source_ref and sink_ref are real file:line locations you
               read in this codebase. For single-site issues (hardcoded key,
               weak cipher constant) use the same ref for both. No line
               numbers = no proof of data flow = do not emit.

SEVERITY SANITY: count the preconditions you just listed. Multiple "must
already have X" steps, or impact limited to non-prod code, caps the finding
at MEDIUM or below."""


EXHAUSTIVENESS = """\
COVERAGE EXPECTATION — one finding is the minimum, not the target. Files in
scope routinely contain several unrelated issues. After logging a finding,
keep reading; do not return until every line in the assigned scope has been
examined.

If the scope is large enough that output limits become a concern, emit HIGH
items in full, then append a one-line tally of MEDIUM/LOW items held back."""


SEVERITY_GUIDANCE = """\
SEVERITY — rate the exploit, not the bug class. "SQL injection" is not a
severity; "unauthenticated SQLi reachable from the internet" is.

STEP 1 — write down three things first:
   - Preconditions: every "attacker must already have/know/be" required.
   - Access level: anonymous / any authenticated user / privileged role /
     same-host.
   - Blast radius: one record, one tenant, the whole service, or the
     underlying host.

STEP 2 — map to a tier:
   HIGH    Reachable with no auth (or any low-privilege session), zero or one
           precondition, and the impact is RCE, auth bypass, or bulk
           cardholder/PII exposure.
   MEDIUM  Needs a valid session OR a couple of realistic preconditions;
           impact is scoped (single user, partial data, integrity only).
   LOW     Three or more stacked preconditions, local/adjacent access only,
           or impact limited to availability of a non-critical component.

STEP 3 — downgrade triggers (apply after step 2):
   - Sits in test/example/debug/non-prod code        → drop one tier.
   - Requires a second independent vuln to matter    → drop one tier.
   - Can't decide between two tiers                  → pick the lower one.
     A mis-labelled HIGH burns reviewer trust faster than a cautious MEDIUM."""
