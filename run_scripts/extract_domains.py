#!/usr/bin/env python3
"""
Extract domains from Unbound query log (or any text file with DNS queries).
Writes a newline-separated list of domains (optionally base domains) suitable
for use as a protected-domain list for the realtime detector.

Usage examples:
  .venv/bin/python extract_domains.py --input /var/log/unbound/unbound.log --output protected.txt --top 100
  .venv/bin/python extract_domains.py --input unbound.log --min-count 5 --base

Outputs to stdout (top N by default) and optionally to --output file.
"""

import argparse
import collections
import os
import re
import sys
from typing import Iterable

QNAME_PATTERNS = [
    re.compile(r"query\[[^\]]+\]\s+(?P<qname>[A-Za-z0-9._-]+)\.", re.IGNORECASE),
    re.compile(r"query:\s+(?P<qname>[A-Za-z0-9._-]+)\.", re.IGNORECASE),
    re.compile(r"QNAME\s+(?P<qname>[A-Za-z0-9._-]+)\.", re.IGNORECASE),
    re.compile(r"\b(?P<qname>[A-Za-z0-9._-]+)\.\s+[A-Z]{1,10}\s+IN\b", re.IGNORECASE),
]

CLIENT_PATTERN = re.compile(r"(?P<client>\d+\.\d+\.\d+\.\d+)")


def normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def base_domain(domain: str) -> str:
    parts = normalize_domain(domain).split(".")
    if len(parts) < 2:
        return normalize_domain(domain)
    return ".".join(parts[-2:])


def extract_qname_from_line(line: str) -> Iterable[str]:
    """Yield any qnames found in the line (may be 0 or 1)."""
    for p in QNAME_PATTERNS:
        m = p.search(line)
        if m:
            yield normalize_domain(m.group("qname"))
            return


def process_file(path: str, use_base: bool = False):
    counter = collections.Counter()
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            for q in extract_qname_from_line(line):
                dom = base_domain(q) if use_base else q
                counter[dom] += 1
    return counter


def write_list(path: str, items):
    with open(path, "w", encoding="utf-8") as fh:
        for it in items:
            fh.write(it + "\n")


def main():
    parser = argparse.ArgumentParser(description="Extract domains from Unbound-style logs")
    parser.add_argument("--input", "-i", required=True, help="Input log file")
    parser.add_argument("--output", "-o", default=None, help="Write newline domain list to this file")
    parser.add_argument("--top", type=int, default=100, help="Print top-N domains (default: 100)")
    parser.add_argument("--min-count", type=int, default=1, help="Only include domains with >=min-count occurrences")
    parser.add_argument("--base", action="store_true", help="Use eTLD+1 (base domain) instead of full qname")
    parser.add_argument("--unique-only", action="store_true", help="Write unique domains only (no counts) to output file")
    args = parser.parse_args()

    try:
        counts = process_file(args.input, use_base=args.base)
    except FileNotFoundError:
        print(f"Input not found: {args.input}", file=sys.stderr)
        sys.exit(2)

    # Filter by min-count
    filtered = ((dom, c) for dom, c in counts.items() if c >= args.min_count)
    # Sort by count desc
    sorted_items = sorted(filtered, key=lambda kv: kv[1], reverse=True)

    # Print top-N to stdout
    top_n = args.top if args.top and args.top > 0 else len(sorted_items)
    selected_items = sorted_items[:top_n]
    for dom, c in selected_items:
        print(f"{dom}\t{c}")

    # Optionally write output file (just domains, one per line)
    if args.output:
        # Keep file output consistent with displayed top-N selection.
        to_write = [d for d, _ in selected_items]
        write_list(args.output, to_write)
        print(f"Wrote {len(to_write)} domains to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
