import pandas as pd

df = pd.read_csv("./typo/typos_multiclass_dataset.csv")

# compute distribution and percentage per class
class_counts = df["classification"].value_counts()
class_percentage = df["classification"].value_counts(normalize=True) * 100

# map them back to the dataframe as new columns
df["distribution"] = df["classification"].map(class_counts)
df["percentage"] = df["classification"].map(class_percentage)

# show one row per class with the extra columns
result = df[["classification", "distribution", "percentage"]].drop_duplicates() \
                                                            .sort_values("distribution", ascending=False)

print(result.to_string(index=False))