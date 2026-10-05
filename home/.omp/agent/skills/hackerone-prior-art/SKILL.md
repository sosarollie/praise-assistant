---
name: hackerone-prior-art
description: Query a vendored corpus of ~10.2k public HackerOne reports (program, title, bounty, upvotes, vuln class) to calibrate a bug-bounty finding before reporting - which bug classes actually get paid, at which programs, typical bounty and upvote levels, and duplicate/prior-art checks. Use when triaging a candidate vulnerability, estimating severity or payout, or checking whether a class of bug is worth reporting on a given program.
---

# HackerOne prior-art corpus

Vendored snapshot of ~10.2k public HackerOne reports from
`InsiderPhD/hackerone-reports`. Fields per report: `program`, `title`, `link`,
`upvotes`, `bounty`, `vuln_type` (125 distinct values).

Data: `skill://hackerone-prior-art/corpus/data.csv` (also browsable as
`corpus/tops_by_bug_type/*.md`, `corpus/tops_by_program/*.md`,
`corpus/tops_100/*.md`).

**What this is for:** deciding whether a candidate finding is worth writing up,
and how to frame it. A real accepted report for the same bug class at the same
program is strong evidence the class is in scope and priced; a class with only
zero-bounty history at that program usually is not worth the time. It is a
historical snapshot — current program policy always wins over corpus statistics.

## Query tool

`h1_query.py` (stdlib only, no install). In **bash** the `skill://` URI does not
expand — use the real path. `read skill://hackerone-prior-art/h1_query.py` works
if you want the source.

```bash
Q=~/.omp/agent/skills/hackerone-prior-art/h1_query.py
python3 "$Q" stats --type "Insecure Direct Object Reference"
python3 "$Q" bounty --type "SQL Injection" --percentile 75
python3 "$Q" top --limit 15 --by-bounty
python3 "$Q" programs --limit 20
python3 "$Q" programs --type "SSRF" --min-reports 5
python3 "$Q" search "account takeover email verification" --limit 10
python3 "$Q" json --type "Open Redirect" --limit 25
```

- `stats` — count, median/mean/max bounty, median upvotes, top programs for a class.
- `bounty` — percentile ladder for a class (p50 vs p75/p90) plus example reports.
- `top` — most upvoted (default) or highest-paid (`--by-bounty`).
- `programs` — programs ranked by volume, with median/max bounty.
- `search` — AND-substring over title + vuln_type + program (multi-word narrows).
- `json` — machine-readable rows for further slicing.

Only `read` resolves `skill://`; never pass that URI to a shell.

## How to use it on a candidate finding

1. **Name the class precisely, then query it.** `stats --type "<class>"`. If the
   class matches ~0 reports, either the taxonomy term is wrong (retry with a
   synonym — `IDOR` vs `Insecure Direct Object Reference` vs `Improper Access
   Control`) or the class has little demonstrated value.
2. **Check the target program.** `programs --type "<class>" --min-reports 3`.
   Reports at the same program = precedent; global history only = weak signal.
3. **Set an expectation, not a promise.** Report `p50` and the program's median;
   quote the tail only as an outlier. Upsvotes are a better predictor of triage
   attention than bounty.
4. **Duplicate/prior-art check.** `search "<the distinctive part of your title>"`
   — a near-identical accepted report on the same surface usually means
   informative, not a duplicate, only if your instance is a different endpoint or
   a different impact. Say explicitly what is new.
5. **Read the top reports' titles.** Tops titles reveal what triagers reward:
   concrete impact ("Account Takeover", "read any user's invoices"), a named
   endpoint, and a demonstrated chain. Copy that concreteness, not the wording.

## Reading the corpus honestly

- ~11% of rows have an empty `vuln_type`; `stats --type` excludes them by design,
  `stats` without `--type` includes them.
- Duplicated report IDs in the raw CSV are collapsed by the tool.
- Bounty is the accepted amount at submission time, not the maximum the program
  advertises.
- Program naming is as it appeared on HackerOne at scrape time; treat program
  identity as approximate.
- This corpus is public report metadata only. It contains titles and payouts, no
  private program scope, no credentials, and nothing that authorizes testing a
  target.
