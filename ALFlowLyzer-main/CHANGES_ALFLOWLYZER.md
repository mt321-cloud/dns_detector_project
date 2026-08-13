# ALFlowLyzer Change Documentation (Session)

Date range: 2026-04-18 to 2026-04-20

## 1) DNS parsing and domain extraction fixes

### File: ALFlowLyzer-main/ALFlowLyzer/application_flow_capturer/packet.py
- Added `__decode_dns_name(raw_name)`.
  - Decodes bytes safely.
  - Normalizes to canonical FQDN by ensuring a trailing dot (`.`).
- Added `__get_scapy_record(section, count, index)` helper.
  - Handles Scapy DNS section objects consistently for single and multi-record sections.
- Reworked Scapy DNS extraction logic.
  - Iterates `qd`, `an`, `ar` robustly.
  - Collects names and DNS record metadata without strict object-shape assumptions.
- Reworked dpkt DNS extraction path.
  - Parses dpkt first.
  - Uses normalized name decoding for query and answer names.
- Changed error fallback behavior.
  - On dpkt parse exception, attempts Scapy extraction instead of failing immediately.

Result:
- `dns_domain_name` values now preserve canonical trailing dot.
- DNS name parsing is more robust for malformed/truncated packets.

## 2) TLD/SLD feature correctness fixes

### File: ALFlowLyzer-main/ALFlowLyzer/features/dns_related.py
- Updated `TopLevelDomain.extract`.
  - Replaced fixed negative-index split logic with label filtering and `labels[-1]`.
- Updated `SecondLevelDomain.extract`.
  - Replaced fixed negative-index split logic with label filtering and `labels[-2] + "." + labels[-1]`.

Result:
- Correct behavior for both dotted and non-dotted FQDN forms.
- `dns_top_level_domain` and `dns_second_level_domain` now match expected values.

## 3) Config schema extension

### File: ALFlowLyzer-main/ALFlowLyzer/config_loader.py
- Added new config defaults:
  - `features_allow_list` (list)
  - `output_columns_reference_file` (string or null)

Result:
- Configuration now supports allow-list feature selection and optional external header template.

## 4) Allow-list based feature selection

### File: ALFlowLyzer-main/ALFlowLyzer/feature_extractor.py
- Extended `execute(...)` signature with `features_allow_list`.
- Added allow-list gate for base fields:
  - `flow_id`, `timestamp`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `label`.
- Added allow-list gate for computed features.
- Preserved `features_ignore_list` behavior for backward compatibility.

Result:
- Output schema can be constrained explicitly via allow-list.

### File: ALFlowLyzer-main/ALFlowLyzer/application_flow_analyzer.py
- Passed `features_allow_list` into async `FeatureExtractor.execute(...)` calls.

Result:
- Allow-list is applied consistently in runtime pipeline.

## 5) Header stability and optional reference-header mode

### File: ALFlowLyzer-main/ALFlowLyzer/writers/writer.py
- Extended `Writer.write(...)` to accept optional `headers` argument.

### File: ALFlowLyzer-main/ALFlowLyzer/writers/csv_writer.py
- Added `__derive_headers(data)`.
  - Builds deterministic union of keys in first-seen order across rows.
- Extended `write(...)` to accept optional `headers`.
- Uses provided headers when passed.
- Uses `data_row.get(header, "")` to avoid KeyError and keep column count stable.

### File: ALFlowLyzer-main/ALFlowLyzer/application_flow_analyzer.py
- Added optional reference-header loader:
  - `__load_reference_headers()` reads first row from `output_columns_reference_file`.
- Writer path now supports forced headers when configured.
- Added `_open_pcap_reader(...)` helper to support both pcap and pcapng input formats.

Result:
- Headers are stable even when some rows miss feature keys.
- Optional reference-header mode is available.
- Reader supports pcapng fallback.

## 6) Runtime config migration in tunnel profile

### File: tunnel/alflowlyzer_config.json
- Migrated from ignore-list strategy to allow-list strategy.
- Current profile uses:
  - benign top-1m pcap input
  - `features_allow_list` with 45 features matching desired schema
- `features_ignore_list` removed from this profile.
- `output_columns_reference_file` removed from this profile.

Result:
- Header schema is now controlled directly by config allow-list.

## 7) Generated artifact changes

### Files regenerated during validation
- tunnel/my-dataset/output-of-my_pcap_file_cobalt_merged.csv
- tunnel/my-dataset/output-of-my_pcap_file_top_1m.csv

Notes:
- Several long ALFlowLyzer runs were interrupted manually with Ctrl+C during iterative validation.
- Validation checks confirmed DNS field matching for initial sampled rows after fixes.
