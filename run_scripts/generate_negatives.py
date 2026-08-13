import random
from itertools import combinations
from pathlib import Path

# Read domains from file (one domain per line)
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

input_file = PROJECT_ROOT / "typo" / "top_domains_PL.txt"
output_file = PROJECT_ROOT / "typo" / "domain_negatives.txt"

with open(input_file, "r", encoding="utf-8") as f:
    domains = [line.strip() for line in f if line.strip()]

# Remove duplicates while preserving order
domains = list(dict.fromkeys(domains))

# Check if there are enough unique pairs
all_pairs = list(combinations(domains, 2))

if len(all_pairs) < 1000:
    raise ValueError(
        f"Only {len(all_pairs)} unique pairs can be created from {len(domains)} domains."
    )

# Shuffle and select 1000 random pairs
random.shuffle(all_pairs)
selected_pairs = all_pairs[:1000]

# Save to output file
with open(output_file, "w", encoding="utf-8") as f:
    for d1, d2 in selected_pairs:
        f.write(f"{d1},{d2},none\n")

print(f"Generated {len(selected_pairs)} pairs in {output_file}")