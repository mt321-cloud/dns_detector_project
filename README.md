# Realtime Detector — Run Guide

This repository contains tools and detectors for DNS-based detection: DGA, typosquatting, and DNS tunneling. The detectors live under `run_scripts/` and supporting code is in `dga/`, `tunnel/`, `typo/`, and other folders.

This README gives step-by-step instructions to set up a Python virtual environment, install dependencies, run preprocessing scripts, run detectors in realtime, and produce evaluation plots.

## Files excluded from GitHub

Due to GitHub storage limitations, some large files, like training datasets, are intentionally excluded from this GitHub repository through `.gitignore`. This includes:

- Packet captures (`*.pcap`)
- Generated datasets and CSV files (`*.csv`), including files under `dga/output_dataset/`, `tunnel/dns-exfiltration-dataset/`, `tunnel/my-dataset/`, and `typo/`
- JSON data files (`*.json`)
- Build artifacts and package metadata (`build/`, `*.egg-info/`)
- Python cache files (`__pycache__/`, `*.pyc`)
- Local environment and system files (`venv/`, `.env`, `.DS_Store`)

These files are not required for production use of the detectors and may need to be obtained separately. Models and sample data referenced by the run instructions should be placed in the paths shown in those instructions before running the detectors.

Full project with all datasets is available here: https://aghedupl-my.sharepoint.com/:u:/g/personal/mtomczyk_student_agh_edu_pl/IQD4ES0ESDhpS5Kk62scHMHcAeeEwESf082rWsRb-se-WiQ?e=3iIdie

Prerequisites
- Python 3.8+ (3.10/3.11 recommended)
- `tcpdump` (if using ALFlowLyzer realtime capture)
- ALFlowLyzer binary (for tunnel detection supervisor) if you plan to capture live flows

1) Create a virtual environment and install dependencies

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Note: there is also a `requirements.txt` inside `ALFlowLyzer-main/` for that subproject; install it only if you work with ALFlowLyzer directly.

2) Verify detectors (quick checks)

Before running detectors in realtime, perform quick verification steps from the repository root:

- Print usage/help for each detector to confirm the scripts load:

```bash
./.venv/bin/python run_scripts/dga_detector.py --help
./.venv/bin/python run_scripts/typo_detector.py --help
./.venv/bin/python run_scripts/tunnel_detector.py --help
```

- Confirm model artifacts are present (example):

```bash
ls -l models/*.pkl || echo "No models found in ./models; place trained joblib bundles there"
```

- Optional: perform a dry run by pointing a detector at a small sample file or by piping a few sample log lines; use `--alerts-file` to capture output. If you don't have sample inputs, running `--help` above is sufficient to verify the environment.

If any script errors with missing packages, activate the venv and install the missing package (e.g. `pip install pandas`).

3) Running realtime detectors

Set reusable variables (example):

```bash
PYTHON="./.venv/bin/python"
UNBOUND_LOG="/var/log/unbound/unbound.log"       # path to Unbound query log
ALFLOW_CSV="/tmp/alflow_rt/alflow_live.csv"     # ALFlowLyzer live CSV (supervisor creates)
PROTECTED_LIST="/path/to/protected.txt"         # typosquatting protected domains
ALERTS_FILE="/tmp/dns_alerts.jsonl"             # append-only alerts output
```

DGA detector (tail Unbound log):

```bash
$PYTHON run_scripts/dga_detector.py \
  --log-file "$UNBOUND_LOG" \
  --dga-model ./models/dga_xgboost_model.pkl \
  --dga-threshold 0.95 \
  --poll-interval 1.0 \
  --log-batch-size 200 \
  --client-ip 127.0.0.1 \
  --alerts-file "$ALERTS_FILE" \
  --verbose
```

Typosquatting detector (tail Unbound log):

```bash
$PYTHON run_scripts/typo_detector.py \
  --log-file "$UNBOUND_LOG" \
  --typo-model ./models/typosquatting_multiclass_model_brf.pkl \
  --protected-list "$PROTECTED_LIST" \
  --typo-threshold 0.98 \
  --protected-top-n 50 \
  --poll-interval 1.0 \
  --log-batch-size 200 \
  --client-ip 127.0.0.1 \
  --alerts-file "$ALERTS_FILE" \
  --verbose
```

Tunnel detector (poll ALFlowLyzer live CSV):

```bash
$PYTHON run_scripts/tunnel_detector.py \
  --flow-csv "$ALFLOW_CSV" \
  --tunnel-model ./models/dns_tunnel_random_forest_model.pkl \
  --tunnel-threshold 0.5 \
  --poll-interval 1.0 \
  --alerts-file "$ALERTS_FILE" \
  --verbose
```

4) ALFlowLyzer realtime supervisor (builds live CSV consumed by the tunnel detector)

Example (requires sudo for `tcpdump`):

```bash
sudo ./run_scripts/run_alflow_stack.py \
  --iface eth0 \
  --chunk-seconds 5 \
  --work-dir /tmp/alflow_rt \
  --base-config ./tunnel/alflowlyzer_config.json \
  --alflow-cmd ./.venv/bin/alflowlyzer \
  --bpf '(udp port 53 or tcp port 53)'
```

Then run the tunnel detector and point it to the generated CSV.

5) Common troubleshooting

- Missing Python packages: activate the venv and `pip install -r requirements.txt` or install the package shown by the error.
- File-not-found errors: ensure you run commands from the repository root; many scripts use repository-relative paths.
- Model/CSV column mismatch: model joblib bundles save `feature_columns` — confirm the CSV header contains the same columns in the same order.
