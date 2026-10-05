---
name: bounty-report
description: End-to-end bug bounty and authorized penetration testing workflow - scope and authorization checks, recon, hypothesis-driven testing, evidence capture, CVSS 4.0 scoring, and a HackerOne-ready report. Use when hunting a live target, turning a finding into a submission, writing a pentest/PoC deliverable, or deciding what to report versus what to discard.
---

# Bug bounty hunting and reporting workflow

Covers authorized testing and report production. Orchestration companions:
`praiseassistant-workflow` (the staged multi-model pipeline), `agents-chat`
(cross-role coordination), `praiseassistant-learning` (evidence-backed workflow
learning), and `patch-validation` (adversarial validation of a proposed fix).

## 0. Authorization is a gate, not a formality

Before any active testing, state in one line: the program, the asset, and the
in-scope basis (explicit scope list, engagement letter, or CTF). If the target or
test type is not covered, stop and say what is missing — do not probe to find out.

Hard rules that keep a hunt inside the lines:

- Only the assets in scope. Out-of-scope domains, sibling properties, third-party
  SaaS (status pages, support vendors, CDNs with their own programs), and shared
  infrastructure are all out unless named.
- Rate-limit yourself and keep traffic boring. No denial-of-service testing, no
  destructive payloads, no persistence, no data exfiltration beyond the minimum
  proof, no accessing other users' data beyond what demonstrates impact.
- Proof over proof-of-proof: demonstrate the vulnerability with the smallest
  possible artifact (one record, one message, one request), never bulk harvest.
- Secrets you find are not yours. Stop, report the location, do not use the
  credential.
- Rate-limit test accounts only, and use accounts you own or were given.

## 1. Map the surface before attacking it

Build the map first; the bugs live in the seams of the map, not in the middle of
any feature.

1. **Scope inventory** — subdomains, endpoints, APIs, mobile apps, source repos,
   cloud storage, exposed `.git`, `sitemap.xml`, `security.txt`, JS bundles.
2. **Authentication and roles** — enumerate every distinct role/tenant and what
   each can reach. Authorization bugs are found by comparing roles, not by
   attacking one.
3. **Business objects** — list the resources (users, orders, files, invoices,
   tokens) and note which are addressed by a client-supplied identifier.
4. **Trust boundaries** — where does untrusted input cross into a privileged
   context: file upload, webhook, import, template render, deserialization,
   outbound request, background job.

## 2. Hypothesis-driven testing

Work a class at a time, with a written hypothesis and a falsification test.

| Hypothesis | How you falsify it |
|---|---|
| IDOR/BOLA | Swap the object identifier while keeping the same session. If the object is scoped server-side, it 403/404s. |
| Broken auth on secondary flows | Change the email/username during password reset, email change, invite accept, MFA enrollment. |
| Mass assignment | Add unexpected fields to a JSON update. If a privilege field is settable, it's a bug. |
| SQL/NoSQL injection | Send a benign delimiter probe (`'`), then a boolean/time differential. Non-destructive only. |
| XSS | Confirm contextually: does the payload execute in a victim's session or an admin's? Reflected in your own session only is usually informational. |
| SSRF | Use a controlled canary endpoint; do not touch link-local metadata beyond proving reachability. |
| Path traversal / file read | Prove with a known-harmless file, never `/etc/shadow` or application keys. |
| Subdomain takeover | Confirm the dangling record **and** the provider's unclaimed-resource page. A dangling DNS record alone is often informational. |
| OAuth/OIDC flaws | Test `redirect_uri` validation, `state` binding, and token audience. |
| Race conditions | Prove a real double-spend or duplicate-benefit effect, not a 500. |
| Business logic | Quantify the abuse: credits, refunds, coupons, invites, rate limits, referral chains. |

## 3. Evidence capture as you go

For every candidate, keep a reproducible trail before you write anything:

- exact request (curl or raw HTTP) and exact response, with redactions of any
  real user data,
- the account/role used on each side, and the object IDs involved,
- a screenshot or raw output for anything graphical,
- timestamps in UTC,
- how to reproduce from a clean session, and how to clean up after.

The `praiseassistant-workflow` skill tracks this evidence through a candidate
lifecycle: a candidate with concrete evidence and a source/sink reference (or a
named boundary invariant) is gated before a proof of concept is built, and a
final confirmation requires two distinct clean-state reproductions with evidence
artifacts.

## 4. Severity

Use CVSS 4.0 (or the program's own scale) and be able to justify the vector.
Anchor on impact, not novelty:

- **Critical** — unauthenticated RCE, auth bypass to admin, mass access to
  sensitive records at scale, key/credential compromise.
- **High** — authenticated privilege escalation, IDOR exposing another user's
  sensitive data, stored XSS reaching staff/admin, SSRF reaching internal
  services, SQLi in an authenticated path.
- **Medium** — limited-scope information disclosure, open redirect on a trusted
  domain, CSRF on a meaningful state change, self-XSS with a realistic path.
- **Low / Informational** — missing headers, verbose errors with no secrets,
  dangling DNS with no claim, version disclosure.

Adjust honestly: report chains at the chain's impact, not the last link's. Avoid
inflating — a report whose severity is inflated reads as noise and costs the
program's trust in the whole submission.

## 5. Report structure

HackerOne-style, and the same skeleton works for a pentest deliverable:

1. **Title** — impact-first and specific: `IDOR on /api/v2/invoices/{id} exposes
   any user's PII` beats `Broken access control`. Include the class keyword
   triagers filter on.
2. **Summary** — 2–4 sentences: what the flaw is, what an attacker gets, where.
3. **Severity** — CVSS 4.0 vector + a plain-language impact statement.
4. **Preconditions** — role, account type, any setup the triager must do.
5. **Steps to reproduce** — numbered, from a clean state, copy-pasteable.
6. **Proof of concept** — the raw request/response or PoC code, redacted.
7. **Impact** — who is affected, how many, what the business consequence is.
8. **Timeline** — UTC timestamps from first test to report.
9. **Remediation** — the specific fix, not "sanitize input". Name the code path
   and the invariant to enforce (e.g. scope every query by the authenticated
   principal's tenant id).
10. **References** — CWE, OWASP, prior art for the class.

Attach all impact in **one** report. Splitting a chain into several reports
reads as padding and usually gets the extras closed as duplicates.

## 6. Before you submit

- [ ] In scope, authorized, rate limits respected
- [ ] Reproduced from a clean state, twice, with distinct clean-state evidence
- [ ] Impact proven with the minimum artifact; no unnecessary user data included
- [ ] Title carries the class keyword and the concrete impact
- [ ] Severity justified by a CVSS vector, not vibes
- [ ] Remediation is specific and actionable
- [ ] Duplicates disclosed — check the program's existing reports
- [ ] Nothing destructive done, nothing left behind on the target

## Anti-patterns that cost real money

Reporting without proof of impact; reporting the same root cause in five
endpoints as five reports; inflating to Critical; including other users' real
data in the PoC; testing out-of-scope assets "just to see"; a remediation
section that only says "validate input".
