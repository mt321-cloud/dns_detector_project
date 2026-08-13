#!/usr/bin/env python3
import argparse
from datetime import datetime
import json
import joblib
import pandas as pd
import signal
import sys
import time
import os

from realtime_dns_detector import poll_flow_csv
from alert_metrics import add_detection_delay, add_pipeline_stage_delays, normalize_timestamp


def log_stderr(message: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {message}", file=sys.stderr)


def emit_alert(alert: dict, alerts_file_handle=None):
    line = json.dumps(alert)
    print(line)
    sys.stdout.flush()
    if alerts_file_handle is not None:
        alerts_file_handle.write(line + "\n")
        alerts_file_handle.flush()


class TunnelDetector:
    def __init__(self, model_path: str, threshold: float, verbose: bool = False):
        bundle = joblib.load(model_path)
        self.model = bundle["model"]
        self.encoder = bundle.get("label_encoder")
        self.scaler = bundle.get("scaler")
        self.feature_columns = bundle.get("feature_columns", [])
        self.threshold = float(threshold)
        self.verbose = bool(verbose)

    def _prepare_features(self, df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
        if not self.feature_columns:
            raise ValueError("Tunnel model bundle does not contain feature_columns")

        prepared = df.copy()
        missing_columns = [c for c in self.feature_columns if c not in prepared.columns]
        for col in missing_columns:
            prepared[col] = 0.0

        prepared = prepared[self.feature_columns]
        for col in prepared.columns:
            prepared[col] = pd.to_numeric(prepared[col], errors="coerce")
        prepared = prepared.fillna(-1.0)
        return prepared, missing_columns

    def detect(self, flow_df: pd.DataFrame, base_index: int = 0):
        if flow_df.empty:
            return []

        x_df, missing_columns = self._prepare_features(flow_df)

        x = x_df
        if self.scaler is not None:
            scaled = self.scaler.transform(x_df.values)
            x = pd.DataFrame(scaled, columns=self.feature_columns)

        alerts = []
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(x)
            classes = self.model.classes_

            if self.encoder is not None:
                try:
                    classes = self.encoder.inverse_transform(classes)
                except Exception:
                    pass

            classes = [str(c) for c in classes]
            lowered = {c.lower(): i for i, c in enumerate(classes)}

            malicious_idx = None
            for candidate in ["malicious", "attack", "dns_tunneling", "tunnel"]:
                if candidate in lowered:
                    malicious_idx = lowered[candidate]
                    break

            if malicious_idx is None and probs.shape[1] == 2:
                malicious_idx = 1
            if malicious_idx is None:
                return alerts

            for i, row_probs in enumerate(probs):
                malicious_score = float(row_probs[malicious_idx])
                if malicious_score < self.threshold:
                    continue

                row = flow_df.iloc[i]
                if self.verbose:
                    log_stderr(
                        f"[verbose] tunnel_model input row_index={base_index + i} dns_domain_name={row.get('dns_domain_name', '')}"
                    )

                # Prefer Unbound log timestamp if present, otherwise fall back to
                # the ALFlowLyzer CSV `timestamp` column when available.
                unbound_val = None
                if "unbound_logged_at" in row and row.get("unbound_logged_at") is not None:
                    unbound_val = row.get("unbound_logged_at")
                elif "timestamp" in row and row.get("timestamp") is not None:
                    unbound_val = row.get("timestamp")
                unbound_ts = normalize_timestamp(unbound_val)
                row_seen_at = datetime.now().isoformat(timespec="microseconds")

                alerts.append(
                    add_pipeline_stage_delays(
                        add_detection_delay(
                            {
                                "detector": "DNS_TUNNELING",
                                "row_index": base_index + i,
                                "score": round(malicious_score, 4),
                                "src_ip": str(row.get("src_ip", "")),
                                "dst_ip": str(row.get("dst_ip", "")),
                                "dns_domain_name": str(row.get("dns_domain_name", "")),
                                "unbound_logged_at": unbound_ts,
                                "flow_row_seen_at": row_seen_at,
                                "detected_at": datetime.now().isoformat(timespec="microseconds"),
                                "missing_feature_columns": missing_columns,
                            }
                        )
                    )
                )
        else:
            preds = self.model.predict(x)
            if self.encoder is not None:
                try:
                    labels = self.encoder.inverse_transform(preds)
                except Exception:
                    labels = preds
            else:
                labels = preds

            for i, label in enumerate(labels):
                if str(label).lower() not in {"malicious", "attack", "dns_tunneling", "tunnel"}:
                    continue

                row = flow_df.iloc[i]
                unbound_val = None
                if "unbound_logged_at" in row and row.get("unbound_logged_at") is not None:
                    unbound_val = row.get("unbound_logged_at")
                elif "timestamp" in row and row.get("timestamp") is not None:
                    unbound_val = row.get("timestamp")
                unbound_ts = normalize_timestamp(unbound_val)
                row_seen_at = datetime.now().isoformat(timespec="microseconds")

                alerts.append(
                    add_pipeline_stage_delays(
                        add_detection_delay(
                            {
                                "detector": "DNS_TUNNELING",
                                "row_index": base_index + i,
                                "score": 1.0,
                                "label": str(label),
                                "src_ip": str(row.get("src_ip", "")),
                                "dst_ip": str(row.get("dst_ip", "")),
                                "dns_domain_name": str(row.get("dns_domain_name", "")),
                                "unbound_logged_at": unbound_ts,
                                "flow_row_seen_at": row_seen_at,
                                "detected_at": datetime.now().isoformat(timespec="microseconds"),
                                "missing_feature_columns": missing_columns,
                            }
                        )
                    )
                )

        return alerts


def handle_signal(signum, _frame):
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Tunnel-only detector (polls ALFlowLyzer CSV)")
    parser.add_argument("--flow-csv", required=True)
    parser.add_argument("--tunnel-model", default=None)
    parser.add_argument("--tunnel-threshold", type=float, default=0.5)
    parser.add_argument("--poll-interval", type=float, default=0.1)
    parser.add_argument("--alerts-file", default=None, help="Optional path to append JSON alerts as JSONL")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    # Resolve model path relative to script directory if not absolute
    script_dir = os.path.dirname(os.path.realpath(__file__))
    if args.tunnel_model is None:
        args.tunnel_model = os.path.join(script_dir, "../models/dns_tunnel_random_forest_model.pkl")
    elif not os.path.isabs(args.tunnel_model):
        args.tunnel_model = os.path.join(script_dir, args.tunnel_model)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    if not os.path.exists(args.tunnel_model) or not os.access(args.tunnel_model, os.R_OK):
        log_stderr(f"Tunnel model not found or unreadable: {args.tunnel_model}")
        sys.exit(1)

    alerts_file_handle = None
    if args.alerts_file is not None:
        try:
            alerts_file_handle = open(args.alerts_file, "a", encoding="utf-8")
        except Exception as e:
            log_stderr(f"Failed to open alerts file: {args.alerts_file} ({e})")
            sys.exit(1)

    try:
        detector = TunnelDetector(
            model_path=args.tunnel_model,
            threshold=args.tunnel_threshold,
            verbose=args.verbose,
        )
    except Exception as e:
        log_stderr(f"Failed to initialize detector: {e}")
        sys.exit(1)

    log_stderr(f"[Tunnel Detector] Starting... Polling: {args.flow_csv}")
    log_stderr(f"[Tunnel Detector] Threshold: {args.tunnel_threshold}")
    log_stderr(f"[Tunnel Detector] Poll interval: {args.poll_interval}s")
    if args.alerts_file is not None:
        log_stderr(f"[Tunnel Detector] Alerts file: {args.alerts_file}")
    log_stderr("[Tunnel Detector] JSON alerts will be printed to stdout")

    last_rows = 0
    poll_count = 0
    while True:
        df = poll_flow_csv(args.flow_csv)
        poll_count += 1
        if not df.empty and len(df) > last_rows:
            new = df.iloc[last_rows:].copy()
            if args.verbose:
                log_stderr(f"[TUNNEL] Poll #{poll_count}: {len(new)} new rows (total: {len(df)})")
                for row_index, row in new.iterrows():
                    log_stderr(
                        f"[TUNNEL] Processing row_index={row_index} dns_domain_name={row.get('dns_domain_name', '')}"
                    )
            alerts = detector.detect(new, base_index=last_rows)
            for alert in alerts:
                emit_alert(alert, alerts_file_handle)
            last_rows = len(df)
        elif args.verbose and poll_count % 10 == 0:
            log_stderr(f"[TUNNEL] Poll #{poll_count}: waiting for new rows (current: {len(df)})")
        time.sleep(max(0.0, args.poll_interval))


if __name__ == "__main__":
    main()
