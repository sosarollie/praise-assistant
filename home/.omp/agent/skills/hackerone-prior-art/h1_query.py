#!/usr/bin/env python3
"""Query the vendored HackerOne report corpus (data.csv) for prior art.

The corpus is a snapshot of ~10.2k public HackerOne reports: program, title,
link, upvotes, bounty, vuln_type. Use it to calibrate expectations before
writing a finding - what has actually been accepted, for which bug classes,
at which programs, and at what bounty/upvote levels.

Examples:
    h1_query.py stats --type "Insecure Direct Object Reference (IDOR)"
    h1_query.py top --limit 15
    h1_query.py programs
    h1_query.py search "subdomain takeover" --limit 10
    h1_query.py bounty --type "SQL Injection" --percentile 90
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import sys
from collections import Counter, defaultdict

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus", "data.csv")


def load() -> list[dict]:
    if not os.path.exists(DATA):
        sys.exit(f"corpus missing: {DATA}")
    with open(DATA, newline="", encoding="utf-8", errors="replace") as fh:
        rows = list(csv.DictReader(fh))
    out = []
    seen = set()
    for r in rows:
        try:
            bounty = float(r.get("bounty") or 0)
        except ValueError:
            bounty = 0.0
        try:
            upvotes = int(r.get("upvotes") or 0)
        except ValueError:
            upvotes = 0
        report_id = (r.get("link") or "").strip().rstrip("/").rsplit("/", 1)[-1]
        if report_id and report_id in seen:
            continue
        if report_id:
            seen.add(report_id)
        out.append(
            {
                "program": (r.get("program") or "").strip(),
                "title": (r.get("title") or "").strip(),
                "id": report_id,
                "upvotes": upvotes,
                "bounty": bounty,
                "vuln_type": (r.get("vuln_type") or "").strip(),
            }
        )
    return out


def match_type(row_type: str, needle: str) -> bool:
    return needle.lower() in row_type.lower()


def fmt_bounty(v: float) -> str:
    return f"${v:,.0f}"


def cmd_stats(rows, args) -> None:
    subset = [r for r in rows if r["vuln_type"]] if args.type else rows
    if args.type:
        subset = [r for r in subset if match_type(r["vuln_type"], args.type)]
    counts = Counter(r["vuln_type"] or "(unlabeled)" for r in rows)
    print(f"corpus: {len(rows)} reports, {len(counts)} distinct vuln_type values")
    print(f"matching '{args.type or '*'}': {len(subset)} reports")
    if not subset:
        return
    bounties = sorted(r["bounty"] for r in subset if r["bounty"] > 0)
    upvotes = sorted(r["upvotes"] for r in subset)
    print(f"  with a nonzero bounty: {len(bounties)}")
    if bounties:
        print(
            f"  bounty median {fmt_bounty(statistics.median(bounties))}"
            f" | mean {fmt_bounty(statistics.fmean(bounties))}"
            f" | max {fmt_bounty(max(bounties))}"
        )
    if upvotes:
        print(f"  upvotes median {statistics.median(upvotes)} | max {max(upvotes)}")
    progs = Counter(r["program"] for r in subset if r["program"])
    print("  top programs:")
    for name, n in progs.most_common(10):
        pb = sorted(r["bounty"] for r in subset if r["program"] == name and r["bounty"] > 0)
        med = fmt_bounty(statistics.median(pb)) if pb else "no paid reports"
        print(f"    {n:4d}  {name}  (median bounty {med})")


def cmd_top(rows, args) -> None:
    subset = rows
    if args.type:
        subset = [r for r in rows if match_type(r["vuln_type"], args.type)]
    key = (lambda r: (r["bounty"], r["upvotes"])) if args.by_bounty else (lambda r: (r["upvotes"], r["bounty"]))
    subset.sort(key=key, reverse=True)
    for r in subset[: args.limit]:
        tag = r["vuln_type"] or "-"
        print(f"{r['upvotes']:5d} upvotes  {fmt_bounty(r['bounty']):>10}  [{tag}]")
        print(f"          {r['title'][:110]}")
        print(f"          {r['program']} - https://hackerone.com/reports/{r['id']}")


def cmd_programs(rows, args) -> None:
    agg = defaultdict(lambda: {"n": 0, "bounties": [], "upvotes": []})
    for r in rows:
        if not r["program"]:
            continue
        a = agg[r["program"]]
        a["n"] += 1
        if r["bounty"] > 0:
            a["bounties"].append(r["bounty"])
        a["upvotes"].append(r["upvotes"])
    ranked = sorted(agg.items(), key=lambda kv: kv[1]["n"], reverse=True)
    if args.type:
        ranked = sorted(
            ((p, a) for p, a in ranked if a["n"] >= args.min_reports), key=lambda kv: kv[1]["n"], reverse=True
        )
    else:
        ranked = ranked[: args.limit]
    for name, a in ranked[: args.limit]:
        b = a["bounties"]
        med = fmt_bounty(statistics.median(b)) if b else "-"
        top = fmt_bounty(max(b)) if b else "-"
        print(f"{a['n']:5d} reports  median {med:>9}  max {top:>9}  {name}")


def cmd_search(rows, args) -> None:
    terms = " ".join(args.query).lower().split()
    hits = [
        r
        for r in rows
        if all(t in (r["title"] + " " + r["vuln_type"] + " " + r["program"]).lower() for t in terms)
    ]
    hits.sort(key=lambda r: (r["bounty"], r["upvotes"]), reverse=True)
    print(f"{len(hits)} matches for {' '.join(terms)!r}\n")
    for r in hits[: args.limit]:
        tag = r["vuln_type"] or "-"
        print(f"{r['upvotes']:5d} up  {fmt_bounty(r['bounty']):>10}  [{tag}]  {r['program']}")
        print(f"          {r['title'][:110]}")
        print(f"          https://hackerone.com/reports/{r['id']}")


def cmd_bounty(rows, args) -> None:
    subset = [r for r in rows if match_type(r["vuln_type"], args.type) and r["bounty"] > 0]
    if not subset:
        sys.exit(f"no paid reports match '{args.type}'")
    vals = sorted(r["bounty"] for r in subset)
    def pct(p: float) -> float:
        return vals[min(len(vals) - 1, int(round((p / 100) * (len(vals) - 1))))]

    print(f"{args.type!r}: {len(vals)} paid reports")
    print(f"  p50 {fmt_bounty(pct(50))}")
    if args.percentile != 50:
        print(f"  p{args.percentile} {fmt_bounty(pct(args.percentile))} (requested percentile)")
    print(f"  max {fmt_bounty(vals[-1])}")
    examples = sorted(
        (r for r in subset if r["bounty"] >= pct(args.percentile)), key=lambda r: -r["bounty"]
    )[:5]
    for r in examples:
        print(f"    {fmt_bounty(r['bounty']):>10}  {r['title'][:80]} ({r['program']})")


def cmd_json(rows, args) -> None:
    subset = rows
    if args.type:
        subset = [r for r in rows if match_type(r["vuln_type"], args.type)]
    print(json.dumps(subset[: args.limit], indent=2))


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("stats", help="aggregate stats, optionally filtered by vuln type")
    s.add_argument("--type", help="substring match on vuln_type")
    s.set_defaults(fn=cmd_stats)

    s = sub.add_parser("top", help="highest bounty or most upvoted reports")
    s.add_argument("--type")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--by-bounty", action="store_true")
    s.set_defaults(fn=cmd_top)

    s = sub.add_parser("programs", help="programs ranked by report count")
    s.add_argument("--type", help="filter aggregation to this vuln type")
    s.add_argument("--min-reports", type=int, default=3)
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(fn=cmd_programs)

    s = sub.add_parser("search", help="full-text search titles/types/programs")
    s.add_argument("query", nargs="+")
    s.add_argument("--limit", type=int, default=10)
    s.set_defaults(fn=cmd_search)

    s = sub.add_parser("bounty", help="bounty distribution percentile for a vuln type")
    s.add_argument("--type", required=True)
    s.add_argument("--percentile", type=int, default=75)
    s.set_defaults(fn=cmd_bounty)

    s = sub.add_parser("json", help="dump matching rows as JSON")
    s.add_argument("--type")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(fn=cmd_json)

    args = p.parse_args()
    try:
        args.fn(load(), args)
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)


if __name__ == "__main__":
    main()
