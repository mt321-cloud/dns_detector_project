#!/usr/bin/env python3
"""Shared alert timing metrics."""

from datetime import datetime
from typing import Optional


def normalize_timestamp(value) -> Optional[str]:
    if value is None or value is False:
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value)).isoformat(timespec="microseconds")
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return None
            if stripped.isdigit():
                return datetime.fromtimestamp(float(stripped)).isoformat(timespec="microseconds")
            return datetime.fromisoformat(stripped).isoformat(timespec="microseconds")
    except Exception:
        return str(value)
    return str(value)


def add_detection_delay(alert: dict) -> dict:
    logged_at = normalize_timestamp(alert.get("unbound_logged_at"))
    detected_at = normalize_timestamp(alert.get("detected_at"))
    alert["unbound_logged_at"] = logged_at
    alert["detected_at"] = detected_at

    alert["detection_delay_seconds"] = None
    if not logged_at or not detected_at:
        return alert

    try:
        delay = (datetime.fromisoformat(detected_at) - datetime.fromisoformat(logged_at)).total_seconds()
    except Exception:
        return alert

    if delay >= 0:
        alert["detection_delay_seconds"] = round(delay, 6)
    return alert


def add_pipeline_stage_delays(alert: dict) -> dict:
    """Attach best-effort stage delay metrics to an alert.

    Fields expected (optional):
    - unbound_logged_at
    - flow_row_seen_at
    - detected_at
    """
    logged_at = normalize_timestamp(alert.get("unbound_logged_at"))
    row_seen_at = normalize_timestamp(alert.get("flow_row_seen_at"))
    detected_at = normalize_timestamp(alert.get("detected_at"))

    alert["unbound_logged_at"] = logged_at
    alert["flow_row_seen_at"] = row_seen_at
    alert["detected_at"] = detected_at

    stage_delays = {
        "source_to_row_seen_seconds": None,
        "row_seen_to_detected_seconds": None,
        "source_to_detected_seconds": alert.get("detection_delay_seconds"),
    }

    try:
        if logged_at and row_seen_at:
            source_to_row = (datetime.fromisoformat(row_seen_at) - datetime.fromisoformat(logged_at)).total_seconds()
            if source_to_row >= 0:
                stage_delays["source_to_row_seen_seconds"] = round(source_to_row, 6)
    except Exception:
        pass

    try:
        if row_seen_at and detected_at:
            row_to_detected = (datetime.fromisoformat(detected_at) - datetime.fromisoformat(row_seen_at)).total_seconds()
            if row_to_detected >= 0:
                stage_delays["row_seen_to_detected_seconds"] = round(row_to_detected, 6)
    except Exception:
        pass

    alert["pipeline_stage_delays"] = stage_delays
    return alert
