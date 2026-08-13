import pandas as pd
from pathlib import Path

from dga_features import extract_features, FEATURE_NAMES

# -----------------------------
# 1. Load input CSV (use repository-relative paths)
# -----------------------------
ROOT = Path(__file__).resolve().parent.parent
input_file = ROOT / "western_oc" / "1_Raw_Domain_Dataset_labeled.csv"
output_file = ROOT / "output_dataset" / "Raw_Domain_Dataset_labeled.csv"

data = pd.read_csv(input_file)

# Expecting columns: Domain, class


# -----------------------------
# 2. Feature extraction
# -----------------------------
features = data["Domain"].apply(extract_features)

features_df = pd.DataFrame(features.tolist(), columns=FEATURE_NAMES)


# -----------------------------
# 3. Add label (if exists)
# -----------------------------
if "class" in data.columns:
    features_df["domain_class"] = data["class"]


# -----------------------------
# 4. Save to CSV
# -----------------------------
features_df.to_csv(output_file, index=False)

print(f"Features saved to: {output_file}")