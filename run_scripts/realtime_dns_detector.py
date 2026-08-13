#!/usr/bin/env python3
"""
Shared realtime DNS utilities.

This module intentionally contains only common helpers used by dedicated
detector entry scripts.
"""

import os
import re
import sys
import time
from typing import Optional

import pandas as pd

# Ensure project root is on sys.path so local packages (dga, typo, etc.) import correctly
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

CLIENT_PATTERNS = [
    re.compile(r"(?P<client>\d+\.\d+\.\d+\.\d+)")
]

QNAME_PATTERNS = [
    re.compile(r"query\[[^\]]+\]\s+(?P<qname>[A-Za-z0-9._-]+)\.", re.IGNORECASE),
    re.compile(r"query:\s+(?P<qname>[A-Za-z0-9._-]+)\.", re.IGNORECASE),
    re.compile(r"QNAME\s+(?P<qname>[A-Za-z0-9._-]+)\.", re.IGNORECASE),
    re.compile(r"\b(?P<qname>[A-Za-z0-9._-]+)\.\s+[A-Z]{1,10}\s+IN\b", re.IGNORECASE),
]



def normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def parse_base_domain(domain: str) -> str:
    parts = normalize_domain(domain).split(".")
    if len(parts) < 2:
        return normalize_domain(domain)
    return ".".join(parts[-2:])


def parse_unbound_line(line: str) -> Optional[tuple[str, str]]:
    client = None
    qname = None

    for pattern in CLIENT_PATTERNS:
        match = pattern.search(line)
        if match:
            client = match.group("client")
            break

    for pattern in QNAME_PATTERNS:
        match = pattern.search(line)
        if match:
            qname = normalize_domain(match.group("qname"))
            break

    if client and qname:
        return client, qname
    return None


def extract_log_epoch(line: str) -> Optional[float]:
    # Supports Unbound lines starting with epoch in brackets, e.g. [1777046448]
    m = re.search(r"\[(\d+(?:\.\d+)?)\]", line)
    if not m:
        return None
    try:
        return float(m.group(1))
    except Exception:
        return None


def tail_file(path: str):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                # Non-blocking poll tick so caller can process other sources.
                yield None
                time.sleep(0.02)


def poll_flow_csv(path: str):
    if not os.path.exists(path):
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception:
        return pd.DataFrame()


# Module exports parsing and stream helpers for dedicated detector scripts.
