import pandas as pd
import numpy as np
import joblib
import tldextract

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

from sklearn.ensemble import RandomForestClassifier

from typo_binary_features import extract_features, FEATURE_NAMES_BINARY


# -----------------------------
# Load dataset
# -----------------------------
df = pd.read_csv("./typo/typos_binary_dataset.csv", nrows=100000)

# -----------------------------
# Extract features
# -----------------------------
features = []

for _, row in df.iterrows():

    target = row["target_domain"]
    query = row["query_domain"]

    features.append(extract_features(target, query))

X = np.array(features)
y = df["classification"]

# -----------------------------
# Train/test split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# -----------------------------
# Train Balanced Random Forest
# -----------------------------
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)


model.fit(X_train, y_train)

joblib.dump({
    "model": model,
    "features": FEATURE_NAMES_BINARY
}, "typosquat_binary_model.pkl")

# -----------------------------
# Evaluate model
# -----------------------------
y_pred = model.predict(X_test)

print("Classification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))
