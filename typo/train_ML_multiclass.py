import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

from imblearn.ensemble import BalancedRandomForestClassifier
from typo_features import ALLOWED_CLASSES, FEATURE_NAMES, extract_features


# LOAD DATASET
df = pd.read_csv("./typo/typos_multiclass_dataset_balanced.csv")

# normalize
df["target_domain"] = df["target_domain"].str.lower()
df["query_domain"] = df["query_domain"].str.lower()

# FILTER CLASSES (important!)
df = df[df["classification"].isin(ALLOWED_CLASSES)]

print("Class distribution:")
print(df["classification"].value_counts())


# FEATURE EXTRACTION
features = []

for _, row in df.iterrows():
    features.append(
        extract_features(row["target_domain"], row["query_domain"])
    )

X = np.array(features)
y = df["classification"]


# TRAIN / TEST SPLIT
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


# TRAIN MODEL
model = BalancedRandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

# model = BalancedRandomForestClassifier(
#     n_estimators=400,          # more trees because each tree sees under-sampled data
#     sampling_strategy="all",   # balance all classes per tree
#     replacement=True,          # recommended for BRF
#     bootstrap=False,           # recommended for BRF (internal sampler already bootstraps)
#     max_features="sqrt",
#     n_jobs=-1,
#     random_state=42
# )

model.fit(X_train, y_train)


# EVALUATION
y_pred = model.predict(X_test)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))


# SAVE MODEL / ARTIFACTS
joblib.dump({
    "model": model,
    "feature_names": FEATURE_NAMES,
    "classes": ALLOWED_CLASSES
}, "models/typosquatting_multiclass_model_brf_reduced_homo_5.pkl")

print("Saved: models/typosquatting_multiclass_model_brf_reduced_homo_5.pkl")

