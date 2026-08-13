#!/usr/bin/env python3
import argparse
from datetime import datetime
import json
import joblib
import numpy as np
import signal
import sys
import time
import os

from alert_metrics import add_detection_delay
from realtime_dns_detector import tail_file, parse_unbound_line, extract_log_epoch

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dga.dga_features import extract_features as extract_dga_features


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


class DgaDetector:
    def __init__(self, model_path: str, threshold: float, verbose: bool = False):
        bundle = joblib.load(model_path)
        self.model = bundle["model"]
        self.encoder = bundle.get("label_encoder")
        self.scaler = bundle.get("scaler")
        self.threshold = float(threshold)
        self.verbose = bool(verbose)

    def detect(self, domain: str):
        if self.verbose:
            log_stderr(f"[verbose] dga_model input domain={domain}")

        x = np.array([extract_dga_features(domain)], dtype=float)
        if self.scaler is not None:
            x = self.scaler.transform(x)

        if not hasattr(self.model, "predict_proba"):
            return None

        probs = self.model.predict_proba(x)[0]
        classes = self.model.classes_

        if self.encoder is not None:
            classes = self.encoder.inverse_transform(classes)

        score_map = {str(c): float(p) for c, p in zip(classes, probs)}
        dga_score = score_map.get("dga", 0.0)
        if dga_score < self.threshold:
            return None

        return {
            "detector": "DGA",
            "domain": domain,
            "score": round(dga_score, 4),
            "scores": score_map,
        }


def handle_signal(signum, _frame):
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="DGA-only detector (tails Unbound log)")
    parser.add_argument("--log-file", default="/var/log/unbound/unbound.log")
    parser.add_argument("--dga-model", default=None)
    parser.add_argument("--dga-threshold", type=float, default=0.95, help="DGA malicious score threshold (default: 0.95)")
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--log-batch-size", type=int, default=200)
    parser.add_argument("--client-ip", default="127.0.0.1")
    parser.add_argument("--alerts-file", default=None, help="Optional path to append JSON alerts as JSONL")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    # Resolve model path relative to script directory if not absolute
    script_dir = os.path.dirname(os.path.realpath(__file__))
    if args.dga_model is None:
        args.dga_model = os.path.join(script_dir, "../models/dga_xgboost_model.pkl")
    elif not os.path.isabs(args.dga_model):
        args.dga_model = os.path.join(script_dir, args.dga_model)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    if not os.path.exists(args.dga_model) or not os.access(args.dga_model, os.R_OK):
        log_stderr(f"DGA model not found or unreadable: {args.dga_model}")
        sys.exit(1)

    try:
        detector = DgaDetector(
            model_path=args.dga_model,
            threshold=args.dga_threshold,
            verbose=args.verbose,
        )
    except Exception as e:
        log_stderr(f"Failed to initialize detector: {e}")
        sys.exit(1)

    if not os.path.exists(args.log_file):
        log_stderr(f"Log file not found: {args.log_file}")
        sys.exit(1)

    alerts_file_handle = None
    if args.alerts_file is not None:
        try:
            alerts_file_handle = open(args.alerts_file, "a", encoding="utf-8")
        except Exception as e:
            log_stderr(f"Failed to open alerts file: {args.alerts_file} ({e})")
            sys.exit(1)

    log_stderr(f"[DGA Detector] Starting... Tailing: {args.log_file}")
    log_stderr(f"[DGA Detector] Threshold: {args.dga_threshold}")
    if args.alerts_file is not None:
        log_stderr(f"[DGA Detector] Alerts file: {args.alerts_file}")
    log_stderr("[DGA Detector] JSON alerts will be printed to stdout")

    log_iter = tail_file(args.log_file)
    query_count = 0

    while True:
        for _ in range(max(1, args.log_batch_size)):
            line = next(log_iter)
            if line is None:
                break
            try:
                parsed = parse_unbound_line(line)
            except Exception:
                parsed = None
            if parsed:
                query_count += 1
                _client_ip, qname = parsed
                if args.verbose:
                    log_stderr(f"[DGA] Processing query #{query_count}: {qname}")
                alert = detector.detect(qname)
                if alert is not None:
                    event_epoch = extract_log_epoch(line)
                    alert["unbound_logged_at"] = (
                        datetime.fromtimestamp(event_epoch).isoformat(timespec="seconds")
                        if event_epoch is not None
                        else None
                    )
                    alert["detected_at"] = datetime.now().isoformat(timespec="seconds")
                    add_detection_delay(alert)
                    emit_alert(alert, alerts_file_handle)

        time.sleep(max(0.0, args.poll_interval))


if __name__ == "__main__":
    main()
