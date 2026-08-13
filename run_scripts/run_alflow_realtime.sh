#!/usr/bin/env bash
set -euo pipefail

# Near-real-time ALFlowLyzer pipeline:
# 1) Capture DNS traffic into rotating pcap chunks
# 2) Run ALFlowLyzer on completed chunks
# 3) Append chunk CSV outputs into one live CSV
#
# Then point realtime_dns_detector.py to --flow-csv LIVE_CSV.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BASE_CONFIG="$SCRIPT_DIR/../tunnel/alflowlyzer_config.json"
IFACE="eth0"
BPF_FILTER='(udp port 53 or tcp port 53)'
CHUNK_SECONDS=1
WORK_DIR="/tmp/alflow_rt"
ALFLOW_CMD="alflowlyzer"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --iface <name>            Capture interface (default: ${IFACE})
  --chunk-seconds <n>       Pcap chunk duration in seconds (default: ${CHUNK_SECONDS})
  --work-dir <path>         Working directory (default: ${WORK_DIR})
  --base-config <path>      Base ALFlowLyzer config (default: ${BASE_CONFIG})
  --alflow-cmd <cmd>        ALFlowLyzer executable (default: ${ALFLOW_CMD})
  --tcpdump-cmd <cmd>       tcpdump executable (default: tcpdump)
  --bpf <expr>              tcpdump filter (default: ${BPF_FILTER})
  -h, --help                Show this help

Outputs:
  <work-dir>/alflow_live.csv
  <work-dir>/chunks/*.csv
  <work-dir>/pcap/*.pcap
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface)
      IFACE="$2"; shift 2 ;;
    --chunk-seconds)
      CHUNK_SECONDS="$2"; shift 2 ;;
    --work-dir)
      WORK_DIR="$2"; shift 2 ;;
    --base-config)
      BASE_CONFIG="$2"; shift 2 ;;
    --alflow-cmd)
      ALFLOW_CMD="$2"; shift 2 ;;
      --tcpdump-cmd)
        TCPDUMP_CMD="$2"; shift 2 ;;
    --bpf)
      BPF_FILTER="$2"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1 ;;
  esac
done

if [[ ! -f "$BASE_CONFIG" ]]; then
  echo "Base config not found: $BASE_CONFIG" >&2
  exit 1
fi

if ! command -v "$ALFLOW_CMD" >/dev/null 2>&1; then
  echo "ALFlowLyzer command not found: $ALFLOW_CMD" >&2
  exit 1
fi

TCPDUMP_CMD="${TCPDUMP_CMD:-tcpdump}"
if ! command -v "$TCPDUMP_CMD" >/dev/null 2>&1; then
  echo "tcpdump not found in PATH: $TCPDUMP_CMD" >&2
  exit 1
fi

mkdir -p "$WORK_DIR/pcap" "$WORK_DIR/chunks" "$WORK_DIR/tmp"
LIVE_CSV="$WORK_DIR/alflow_live.csv"

if [[ ! -f "$LIVE_CSV" ]]; then
  : > "$LIVE_CSV"
fi

declare -A SEEN
CAPTURE_PID=""

cleanup() {
  if [[ -n "$CAPTURE_PID" ]] && kill -0 "$CAPTURE_PID" 2>/dev/null; then
    kill "$CAPTURE_PID" 2>/dev/null || true
    wait "$CAPTURE_PID" 2>/dev/null || true
  fi
  echo "Stopped." >&2
}
trap cleanup EXIT INT TERM

process_chunk() {
  local pcap_file="$1"
  local stem
  stem="$(basename "$pcap_file" .pcap)"

  local out_csv="$WORK_DIR/chunks/${stem}.csv"
  local cfg_json="$WORK_DIR/tmp/config_${stem}.json"
  local err_log="$WORK_DIR/tmp/alflow_${stem}.log"
  local chunk_start_epoch
  local chunk_start_iso
  local alflow_start_epoch
  local alflow_end_epoch
  local append_start_epoch
  local append_end_epoch

  chunk_start_epoch="$(python3 - <<'PY'
import time
print(time.time())
PY
)"
  chunk_start_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "[TIMING] chunk_start pcap=$(basename "$pcap_file") at=${chunk_start_iso}" >&2

  python3 - <<PY
import json
from pathlib import Path

base_path = Path(${BASE_CONFIG@Q})
out_path = Path(${out_csv@Q})
pcap_path = Path(${pcap_file@Q})
cfg_path = Path(${cfg_json@Q})

cfg = json.loads(base_path.read_text())
cfg["pcap_file_address"] = str(pcap_path)
cfg["output_file_address"] = str(out_path)

# Lower buffering for near-real-time chunk processing
cfg["feature_extractor_min_flows"] = 10
cfg["writer_min_rows"] = 10
cfg["check_flows_ending_min_flows"] = 50
cfg["capturer_updating_flows_min_value"] = 50
cfg["read_packets_count_value_log_info"] = 1000

cfg_path.write_text(json.dumps(cfg, indent=2))
PY

  alflow_start_epoch="$(python3 - <<'PY'
import time
print(time.time())
PY
)"
  if "$ALFLOW_CMD" -c "$cfg_json" >"$err_log" 2>&1; then
    alflow_end_epoch="$(python3 - <<'PY'
import time
print(time.time())
PY
)"
    if [[ -s "$out_csv" ]]; then
      append_start_epoch="$(python3 - <<'PY'
import time
print(time.time())
PY
)"
      if [[ ! -s "$LIVE_CSV" ]]; then
        cp "$out_csv" "$LIVE_CSV"
      else
        tail -n +2 "$out_csv" >> "$LIVE_CSV"
      fi
      append_end_epoch="$(python3 - <<'PY'
import time
print(time.time())
PY
)"
      python3 - <<PY
from datetime import datetime, timezone

chunk_start = float(${chunk_start_epoch@Q})
alflow_start = float(${alflow_start_epoch@Q})
alflow_end = float(${alflow_end_epoch@Q})
append_start = float(${append_start_epoch@Q})
append_end = float(${append_end_epoch@Q})

def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds")

print(
    "[TIMING] chunk_done "
    f"pcap={${pcap_file@Q}.split('/')[-1]} "
    f"chunk_started_at={iso(chunk_start)} "
    f"alflow_started_at={iso(alflow_start)} "
    f"alflow_finished_at={iso(alflow_end)} "
    f"append_started_at={iso(append_start)} "
    f"append_finished_at={iso(append_end)} "
    f"alflow_seconds={alflow_end - alflow_start:.3f} "
    f"append_seconds={append_end - append_start:.3f} "
    f"total_chunk_seconds={append_end - chunk_start:.3f}"
)
PY
      echo "[OK] processed $(basename "$pcap_file") -> $(basename "$out_csv")" >&2
    else
      echo "[SKIP] no rows from $(basename "$pcap_file")" >&2
    fi
  else
    echo "[ERR] ALFlowLyzer failed on $(basename "$pcap_file")" >&2
    echo "[ERR] config: $cfg_json" >&2
    echo "[ERR] log: $err_log" >&2
    tail -n 40 "$err_log" >&2 || true
  fi
}

echo "Starting capture on interface: $IFACE" >&2
echo "Chunk seconds: $CHUNK_SECONDS" >&2
echo "Live CSV: $LIVE_CSV" >&2

# NOTE: You usually need root privileges for packet capture.
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "tcpdump usually needs root privileges. Run: sudo $0 ..." >&2
fi

"$TCPDUMP_CMD" -i "$IFACE" -nn -s0 -G "$CHUNK_SECONDS" -w "$WORK_DIR/pcap/dns_%Y%m%d_%H%M%S.pcap" "$BPF_FILTER" &
CAPTURE_PID="$!"

sleep 1
if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
  echo "tcpdump exited immediately. Check interface name, privileges, and BPF filter." >&2
  wait "$CAPTURE_PID" 2>/dev/null || true
  exit 1
fi

while true; do
  mapfile -t pcaps < <(ls -1 "$WORK_DIR/pcap"/dns_*.pcap 2>/dev/null | sort || true)
  count="${#pcaps[@]}"

  # Skip newest file because tcpdump may still be writing to it.
  if (( count > 1 )); then
    for ((i=0; i<count-1; i++)); do
      pcap_file="${pcaps[$i]}"
      if [[ -n "${SEEN[$pcap_file]:-}" ]]; then
        continue
      fi
      process_chunk "$pcap_file"
      SEEN["$pcap_file"]=1
    done
  fi

  sleep 1
done
