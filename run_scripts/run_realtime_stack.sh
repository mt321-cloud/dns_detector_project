#!/usr/bin/env bash
set -euo pipefail

# One-command launcher for near-real-time DNS tunnel detection stack:
# Combines: pcap capture, ALFlowLyzer chunk processing, and realtime_dns_detector.py
# Outputs JSON alerts to stdout (via detector)

IFACE="eth0"
CHUNK_SECONDS=5
WORK_DIR="/tmp/alflow_rt"
POLL_INTERVAL=0.2
LOG_BATCH_SIZE=200
CLIENT_IP="127.0.0.1"
VERBOSE=0
LATENCY_REPORT_INTERVAL=10.0
PROTECTED_LIST=""
PROTECTED_TOP_N=50
LOG_FILE="/var/log/unbound/unbound.log"

# Resolve script directory so defaults work regardless of CWD
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Defaults (resolved relative to this script)
BASE_CONFIG="$SCRIPT_DIR/../tunnel/alflowlyzer_config.json"
ALFLOW_CMD="alflowlyzer"
BPF_FILTER='(udp port 53 or tcp port 53)'

DGA_MODEL="$SCRIPT_DIR/../models/dga_xgboost_model.pkl"
TYPO_MODEL="$SCRIPT_DIR/../models/typosquatting_multiclass_model_brf.pkl"
TUNNEL_MODEL="$SCRIPT_DIR/../models/dns_tunnel_random_forest_model.pkl"
TUNNEL_THRESHOLD=0.5
DGA_THRESHOLD=0.95
TYPO_THRESHOLD=0.98

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Capture / ALFlowLyzer options:
  --iface <name>              Capture interface (default: ${IFACE})
  --chunk-seconds <n>         Pcap chunk duration (default: ${CHUNK_SECONDS})
  --work-dir <path>           Work directory (default: ${WORK_DIR})
  --base-config <path>        ALFlowLyzer base config (default: ${BASE_CONFIG})
  --alflow-cmd <cmd>          ALFlowLyzer executable (default: ${ALFLOW_CMD})
  --bpf <expr>                tcpdump BPF filter (default: ${BPF_FILTER})

Detector options:
  --poll-interval <sec>       CSV polling interval (default: ${POLL_INTERVAL})
  --dga-model <path>          DGA model bundle
  --typo-model <path>         Typosquatting model bundle
  --tunnel-model <path>       Tunnel model bundle
  --tunnel-threshold <float>  Tunnel malicious threshold (default: ${TUNNEL_THRESHOLD})
  --dga-threshold <float>     DGA malicious threshold (default: ${DGA_THRESHOLD})
  --typo-threshold <float>    Typosquatting malicious threshold (default: ${TYPO_THRESHOLD})
  --log-file <path>           Unbound log for DGA/typo streaming (default: ${LOG_FILE})
  --log-batch-size <n>        Max log lines per iteration (default: ${LOG_BATCH_SIZE})
  --client-ip <ip>            Fallback client IP (default: ${CLIENT_IP})
  --verbose                   Enable verbose output
  --latency-report-interval <sec> Latency report interval (default: ${LATENCY_REPORT_INTERVAL})
  --protected-list <path>     Path to protected domains list
  --protected-top-n <n>       Top-N fuzzy matches (default: ${PROTECTED_TOP_N})
  --no-dga                    Disable DGA detection
  --no-typo                   Disable typosquatting detection
  --no-tunnel                 Disable DNS tunneling detection

Other:
  -h, --help                  Show help

Examples:
  # Run full stack with protected domains list
  sudo $(basename "$0") --iface eth0 --work-dir /tmp/alflow_rt --protected-list protected_domains.txt

  # Run but disable typosquatting detection (no protected list needed)
  sudo $(basename "$0") --iface eth0 --work-dir /tmp/alflow_rt --no-typo

  # Disable multiple detectors (no protected list needed)
  sudo $(basename "$0") --iface eth0 --work-dir /tmp/alflow_rt --no-dga --no-typo
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface) IFACE="$2"; shift 2 ;;
    --chunk-seconds) CHUNK_SECONDS="$2"; shift 2 ;;
    --work-dir) WORK_DIR="$2"; shift 2 ;;
    --base-config) BASE_CONFIG="$2"; shift 2 ;;
    --alflow-cmd) ALFLOW_CMD="$2"; shift 2 ;;
    --bpf) BPF_FILTER="$2"; shift 2 ;;

    --poll-interval) POLL_INTERVAL="$2"; shift 2 ;;
    --dga-model) DGA_MODEL="$2"; shift 2 ;;
    --typo-model) TYPO_MODEL="$2"; shift 2 ;;
    --tunnel-model) TUNNEL_MODEL="$2"; shift 2 ;;
    --tunnel-threshold) TUNNEL_THRESHOLD="$2"; shift 2 ;;
    --dga-threshold) DGA_THRESHOLD="$2"; shift 2 ;;
    --typo-threshold) TYPO_THRESHOLD="$2"; shift 2 ;;
    --log-file) LOG_FILE="$2"; shift 2 ;;
    --log-batch-size) LOG_BATCH_SIZE="$2"; shift 2 ;;
    --client-ip) CLIENT_IP="$2"; shift 2 ;;
    --verbose) VERBOSE=1; shift 1 ;;
    --latency-report-interval) LATENCY_REPORT_INTERVAL="$2"; shift 2 ;;
    --protected-list) PROTECTED_LIST="$2"; shift 2 ;;
    --protected-top-n) PROTECTED_TOP_N="$2"; shift 2 ;;
    --no-dga) DISABLE_DGA=1; shift 1 ;;
    --no-typo) DISABLE_TYPO=1; shift 1 ;;
    --no-tunnel) DISABLE_TUNNEL=1; shift 1 ;;

    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1 ;;
  esac
done

# Validate required arguments
if [[ -z "$PROTECTED_LIST" ]] && [[ "${DISABLE_TYPO:-0}" -ne 1 ]]; then
  echo "Error: --protected-list is required for typosquatting detection (or use --no-typo to disable)" >&2
  usage
  exit 1
fi

# Default python executable (venv) resolved relative to the script directory
PYTHON_EXEC="$SCRIPT_DIR/../.venv/bin/python"

# Allow overriding python executable via CLI
# (added --python option handled below)

if [[ ! -x "$PYTHON_EXEC" ]]; then
  echo "Missing Python executable: $PYTHON_EXEC" >&2
  echo "Create a venv at $(dirname "$PYTHON_EXEC") or provide --python /path/to/python" >&2
  exit 1
fi

LIVE_CSV="${WORK_DIR}/alflow_live.csv"

# Initialize live CSV if it doesn't exist
if [[ ! -f "$LIVE_CSV" ]]; then
  : > "$LIVE_CSV"
fi

CAPTURE_PID=""

cleanup() {
  if [[ -n "$CAPTURE_PID" ]] && kill -0 "$CAPTURE_PID" 2>/dev/null; then
    kill "$CAPTURE_PID" 2>/dev/null || true
    wait "$CAPTURE_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

echo "Starting ALFlowLyzer realtime pipeline (merged) and detector..." >&2

# Create necessary directories with write permissions for tcpdump
mkdir -p "$WORK_DIR/pcap" "$WORK_DIR/chunks" "$WORK_DIR/tmp"
chmod 777 "$WORK_DIR" "$WORK_DIR/pcap" "$WORK_DIR/chunks" "$WORK_DIR/tmp"

# --- Start tcpdump capture (rotating pcap chunks) ---
TCPDUMP_CMD="tcpdump"
if ! command -v "$TCPDUMP_CMD" >/dev/null 2>&1; then
  echo "tcpdump not found: $TCPDUMP_CMD" >&2
  exit 1
fi

"$TCPDUMP_CMD" -i "$IFACE" -nn -s0 -G "$CHUNK_SECONDS" -w "$WORK_DIR/pcap/dns_%Y%m%d_%H%M%S.pcap" "$BPF_FILTER" &
CAPTURE_PID="$!"

sleep 1
if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
  echo "tcpdump exited immediately. Check interface name, privileges, and BPF filter." >&2
  wait "$CAPTURE_PID" 2>/dev/null || true
  exit 1
fi

echo "Waiting for pcap chunks and starting chunk processor loop..." >&2

# process_chunk function inlined from run_alflow_realtime.sh
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

# Start detector after capture is running
echo "Starting realtime detector..." >&2
DETECTOR_CMD=(
  "$PYTHON_EXEC"
  "$SCRIPT_DIR/realtime_dns_detector.py"
  --flow-csv "$LIVE_CSV"
  --dga-model "$DGA_MODEL"
  --typo-model "$TYPO_MODEL"
  --tunnel-model "$TUNNEL_MODEL"
  --tunnel-threshold "$TUNNEL_THRESHOLD"
  --poll-interval "$POLL_INTERVAL"
)
DETECTOR_CMD+=(--dga-threshold "$DGA_THRESHOLD")
DETECTOR_CMD+=(--typo-threshold "$TYPO_THRESHOLD")
DETECTOR_CMD+=(--log-batch-size "$LOG_BATCH_SIZE")
DETECTOR_CMD+=(--client-ip "$CLIENT_IP")
DETECTOR_CMD+=(--latency-report-interval "$LATENCY_REPORT_INTERVAL")
DETECTOR_CMD+=(--protected-top-n "$PROTECTED_TOP_N")

if [[ -n "$LOG_FILE" ]]; then
  DETECTOR_CMD+=(--log-file "$LOG_FILE")
fi

# Protected list is optional if typo is disabled
if [[ -n "$PROTECTED_LIST" ]]; then
  DETECTOR_CMD+=(--protected-list "$PROTECTED_LIST")
fi

if [[ "$VERBOSE" -eq 1 ]]; then
  DETECTOR_CMD+=(--verbose)
fi

# Pass detector disable flags (CLI only)
if [[ "${DISABLE_DGA:-0}" -eq 1 ]]; then
  DETECTOR_CMD+=(--no-dga)
fi
if [[ "${DISABLE_TYPO:-0}" -eq 1 ]]; then
  DETECTOR_CMD+=(--no-typo)
fi
if [[ "${DISABLE_TUNNEL:-0}" -eq 1 ]]; then
  DETECTOR_CMD+=(--no-tunnel)
fi

# Background loop to process completed pcap chunks while detector runs in foreground
(
  # chunk processing loop runs in subshell so we can wait on detector later
  declare -A SEEN
  while true; do
    mapfile -t pcaps < <(ls -1 "$WORK_DIR/pcap"/dns_*.pcap 2>/dev/null | sort || true)
    count="${#pcaps[@]}"

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
)&

# Run detector in foreground (so script exits when detector stops)
"${DETECTOR_CMD[@]}"
