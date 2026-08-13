#!/usr/bin/env python3
import argparse
import csv
from datetime import datetime
import json
from pathlib import Path
from typing import Dict, List, Tuple

from realtime_dns_detector import extract_log_epoch, normalize_domain, parse_unbound_line


def read_unbound_first_seen(unbound_log: Path) -> Tuple[Dict[str, datetime], int, int]:
    first_seen: Dict[str, datetime] = {}
    total_lines = 0
    parsed_queries = 0

    with unbound_log.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            total_lines += 1
            parsed = parse_unbound_line(line)
            if not parsed:
                continue

            _client_ip, qname = parsed
            event_epoch = extract_log_epoch(line)
            if event_epoch is None:
                # This analysis requires timestamps from Unbound lines.
                continue

            parsed_queries += 1
            domain = normalize_domain(qname)
            ts = datetime.fromtimestamp(event_epoch)
            prev = first_seen.get(domain)
            if prev is None or ts < prev:
                first_seen[domain] = ts

    return first_seen, total_lines, parsed_queries


def read_alert_first_detected(alerts_jsonl: Path) -> Tuple[Dict[str, datetime], int]:
    first_detected: Dict[str, datetime] = {}
    tunnel_alerts = 0

    with alerts_jsonl.open("r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue

            try:
                alert = json.loads(line)
            except Exception:
                continue

            if str(alert.get("detector", "")).upper() != "DNS_TUNNELING":
                continue

            domain_raw = alert.get("dns_domain_name")
            detected_at_raw = alert.get("detected_at")
            if not domain_raw or not detected_at_raw:
                continue

            try:
                detected_at = datetime.fromisoformat(str(detected_at_raw))
            except Exception:
                continue

            tunnel_alerts += 1
            domain = normalize_domain(str(domain_raw))
            prev = first_detected.get(domain)
            if prev is None or detected_at < prev:
                first_detected[domain] = detected_at

    return first_detected, tunnel_alerts


def compute_delay_rows(
    first_seen: Dict[str, datetime],
    first_detected: Dict[str, datetime],
) -> List[dict]:
    rows: List[dict] = []
    for domain in sorted(first_seen.keys() & first_detected.keys()):
        seen_ts = first_seen[domain]
        det_ts = first_detected[domain]
        delay_s = (det_ts - seen_ts).total_seconds()
        if delay_s < 0:
            continue
        rows.append(
            {
                "domain": domain,
                "first_seen_at": seen_ts.isoformat(timespec="seconds"),
                "first_detected_at": det_ts.isoformat(timespec="seconds"),
                "first_seen_to_detected_seconds": round(delay_s, 6),
            }
        )
    rows.sort(key=lambda r: r["first_seen_to_detected_seconds"], reverse=True)
    return rows


def percentile(sorted_values: List[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    i = int((len(sorted_values) - 1) * p)
    return sorted_values[i]


def print_summary(rows: List[dict], overlap_domains: int, seen_domains: int, detected_domains: int) -> None:
    print(f"domains_in_unbound={seen_domains}")
    print(f"domains_in_tunnel_alerts={detected_domains}")
    print(f"domains_overlap={overlap_domains}")
    print(f"domains_with_valid_delay={len(rows)}")

    if not rows:
        print("No valid delays computed.")
        return

    values = sorted(float(r["first_seen_to_detected_seconds"]) for r in rows)
    print("delay_seconds_stats:")
    print(f"  min={values[0]:.3f}")
    print(f"  p50={percentile(values, 0.50):.3f}")
    print(f"  p90={percentile(values, 0.90):.3f}")
    print(f"  p95={percentile(values, 0.95):.3f}")
    print(f"  p99={percentile(values, 0.99):.3f}")
    print(f"  max={values[-1]:.3f}")


def save_csv(rows: List[dict], output_csv: Path) -> None:
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "domain",
                "first_seen_at",
                "first_detected_at",
                "first_seen_to_detected_seconds",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compute time from first seen tunnel domain (Unbound log) to first tunneling alert"
    )
    parser.add_argument("--unbound-log", required=True, help="Path to Unbound query log")
    parser.add_argument("--alerts-jsonl", required=True, help="Path to alerts JSONL file")
    parser.add_argument("--output-csv", default=None, help="Optional output CSV path")
    parser.add_argument("--top", type=int, default=20, help="How many slowest domains to print (default: 20)")
    args = parser.parse_args()

    unbound_log = Path(args.unbound_log)
    alerts_jsonl = Path(args.alerts_jsonl)

    if not unbound_log.exists():
        raise SystemExit(f"Unbound log not found: {unbound_log}")
    if not alerts_jsonl.exists():
        raise SystemExit(f"Alerts JSONL not found: {alerts_jsonl}")

    first_seen, total_lines, parsed_queries = read_unbound_first_seen(unbound_log)
    first_detected, tunnel_alerts = read_alert_first_detected(alerts_jsonl)

    rows = compute_delay_rows(first_seen, first_detected)

    print(f"unbound_lines_total={total_lines}")
    print(f"unbound_queries_parsed_with_timestamp={parsed_queries}")
    print(f"tunnel_alert_rows_parsed={tunnel_alerts}")

    overlap = len(first_seen.keys() & first_detected.keys())
    print_summary(rows, overlap, len(first_seen), len(first_detected))

    if rows:
        print("slowest_domains:")
        for r in rows[: max(0, args.top)]:
            print(
                f"  {r['first_seen_to_detected_seconds']:8.3f}s  {r['domain']}"
                f"  seen={r['first_seen_at']} detected={r['first_detected_at']}"
            )

    if args.output_csv:
        out = Path(args.output_csv)
        save_csv(rows, out)
        print(f"saved_csv={out}")


if __name__ == "__main__":
    main()
