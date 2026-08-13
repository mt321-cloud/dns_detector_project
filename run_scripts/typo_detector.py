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

from realtime_dns_detector import tail_file, parse_unbound_line, extract_log_epoch
from alert_metrics import add_detection_delay

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from typo.typo_features import extract_features as extract_typo_features


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


class TypoDetector:
    def __init__(
        self,
        model_path: str,
        threshold: float,
        protected_list_path: str,
        protected_top_n: int = 50,
        verbose: bool = False,
    ):
        bundle = joblib.load(model_path)
        self.model = bundle["model"]
        self.threshold = float(threshold)
        self.verbose = bool(verbose)
        self.protected_top_n = int(protected_top_n)

        with open(protected_list_path, "r", encoding="utf-8", errors="ignore") as fh:
            self.protected_domains = [l.strip().lower() for l in fh if l.strip()]
        if not self.protected_domains:
            raise ValueError(f"Protected domains file is empty: {protected_list_path}")

        self._use_rapidfuzz = False
        self._rf_choices = None
        try:
            from rapidfuzz import process as _rf_process  # type: ignore
            if self.protected_domains:
                self._use_rapidfuzz = True
                self._rf_choices = self.protected_domains
        except Exception:
            self._use_rapidfuzz = False
            self._rf_choices = None

    def detect(self, domain: str):
        best_score = 0.0
        best_target = None
        best_class = None

        candidates = self.protected_domains
        if self._use_rapidfuzz and self._rf_choices is not None and len(self._rf_choices) > self.protected_top_n:
            try:
                from rapidfuzz import process, fuzz  # type: ignore

                matches = process.extract(domain, self._rf_choices, scorer=fuzz.ratio, limit=self.protected_top_n)
                candidates = [m[0] for m in matches]
            except Exception:
                candidates = self.protected_domains

        if self.verbose:
            log_stderr(f"[verbose] typo_model candidates for domain={domain}: {len(candidates)}")

        for protected in candidates:
            if self.verbose:
                log_stderr(f"[verbose] typo_model input target={protected} query={domain}")

            x = np.array([extract_typo_features(protected, domain)], dtype=float)
            if not hasattr(self.model, "predict_proba"):
                continue

            probs = self.model.predict_proba(x)[0]
            class_names = [str(c) for c in self.model.classes_]
            score_map = dict(zip(class_names, probs))

            for class_name, score in score_map.items():
                if class_name == "none":
                    continue
                if score > best_score:
                    best_score = float(score)
                    best_target = protected
                    best_class = class_name

        if best_score < self.threshold or not best_target:
            return None

        return {
            "detector": "TYPOSQUATTING",
            "domain": domain,
            "score": round(best_score, 4),
            "target": best_target,
            "predicted_class": best_class,
        }


def handle_signal(signum, _frame):
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Typosquatting-only detector (tails Unbound log)")
    parser.add_argument("--log-file", default="/var/log/unbound/unbound.log")
    parser.add_argument("--typo-model", default=None)
    parser.add_argument("--typo-threshold", type=float, default=0.98, help="Typosquatting malicious score threshold (default: 0.98)")
    parser.add_argument("--protected-list", required=True)
    parser.add_argument("--protected-top-n", type=int, default=50, help="Top-N fuzzy matches for protected domains (default: 50)")
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--log-batch-size", type=int, default=200)
    parser.add_argument("--client-ip", default="127.0.0.1")
    parser.add_argument("--alerts-file", default=None, help="Optional path to append JSON alerts as JSONL")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    # Resolve model path relative to script directory if not absolute
    script_dir = os.path.dirname(os.path.realpath(__file__))
    if args.typo_model is None:
        args.typo_model = os.path.join(script_dir, "../models/typosquatting_multiclass_model_brf.pkl")
    elif not os.path.isabs(args.typo_model):
        args.typo_model = os.path.join(script_dir, args.typo_model)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    if not os.path.exists(args.typo_model) or not os.access(args.typo_model, os.R_OK):
        log_stderr(f"Typosquatting model not found or unreadable: {args.typo_model}")
        sys.exit(1)
    if not os.path.exists(args.protected_list) or not os.access(args.protected_list, os.R_OK):
        log_stderr(f"Protected list not found or unreadable: {args.protected_list}")
        sys.exit(1)

    try:
        detector = TypoDetector(
            model_path=args.typo_model,
            threshold=args.typo_threshold,
            protected_list_path=args.protected_list,
            protected_top_n=args.protected_top_n,
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

    log_stderr(f"[Typo Detector] Starting... Tailing: {args.log_file}")
    log_stderr(f"[Typo Detector] Protected list: {args.protected_list}")
    log_stderr(f"[Typo Detector] Threshold: {args.typo_threshold}, Top-N: {args.protected_top_n}")
    if args.alerts_file is not None:
        log_stderr(f"[Typo Detector] Alerts file: {args.alerts_file}")
    log_stderr("[Typo Detector] JSON alerts will be printed to stdout")

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
                    log_stderr(f"[TYPO] Processing query #{query_count}: {qname}")
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
