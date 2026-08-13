import pandas as pd

# Configuration
INPUT_CSV = "typo/typos_multiclass_dataset_2.csv"
OUTPUT_CSV = "typo/typos_multiclass_dataset_2_reduced_homoglyph_4.csv"

TARGET_HOMOGLYPH = 40_000  # Number of homoglyph samples to keep
RANDOM_STATE = 42

# Load dataset
df = pd.read_csv(INPUT_CSV)

# Split classes
homoglyph = df[df["classification"] == "homoglyph"].copy()
others = df[df["classification"] != "homoglyph"].copy()

print("Original distribution:")
print(df["classification"].value_counts())

# KEEP ONLY homoglyph rows that contain Punycode (xn--)
# homoglyph = homoglyph[
#     homoglyph["target_domain"].str.contains("xn--", na=False) |
#     homoglyph["query_domain"].str.contains("xn--", na=False)
# ]

print(f"\nHomoglyph after filtering (punycode only): {len(homoglyph):,}")

# Downsample homoglyph if needed
if len(homoglyph) > TARGET_HOMOGLYPH:
    homoglyph = homoglyph.sample(
        n=TARGET_HOMOGLYPH,
        random_state=RANDOM_STATE
    )

# Merge back
result = pd.concat([homoglyph, others], ignore_index=True)

# Shuffle dataset
result = result.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)

print("\nNew distribution:")
print(result["classification"].value_counts())

# Save
result.to_csv(OUTPUT_CSV, index=False)

print(f"\nSaved to {OUTPUT_CSV}")