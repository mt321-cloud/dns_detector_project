import pandas as pd
import numpy as np
import glob
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

pd.set_option('display.max_columns', None)


def print_full_precision_classification_report(model_name, y_true, y_pred):
    report_dict = classification_report(
        y_true,
        y_pred,
        output_dict=True,
        zero_division=0,
    )
    report_df = pd.DataFrame(report_dict).transpose()
    print(f"\n=== {model_name} ===")
    print(report_df.to_string(float_format=lambda x: f"{x:.15f}"))

# # -----------------------------
# # 1. LOAD DATA
# # -----------------------------
# df = pd.read_csv("dns-exfiltration-dataset/02_generated_dataset/benign/benign.csv", nrows=100)

# print("Initial shape:", df.shape)

# -----------------------------
# 1. LOAD ALL FILES
# -----------------------------

# Paths (adjust to your folders)
benign_path = "tunnel/dns-exfiltration-dataset/02_generated_dataset/benign/benign.csv"
malicious_path = "tunnel/dns-exfiltration-dataset/02_generated_dataset/malicious/*/*.csv"

# Load benign files
benign_files = glob.glob(benign_path)
print("Benign files found:", benign_files)
benign_df = pd.concat([pd.read_csv(f) for f in benign_files], ignore_index=True)
# benign_df["label"] = "Benign"

# Load malicious files
malicious_files = glob.glob(malicious_path)
print("Malicious files found:", malicious_files)

malicious_dfs = []
for f in malicious_files:
    df = pd.read_csv(f)  # Adjust nrows as needed
    
    # OPTIONAL: keep attack type (very useful later)
    # attack_type = f.split("/")[-1].replace(".csv", "")
    # df["attack_type"] = attack_type
    
    # df["label"] = "Malicious"
    malicious_dfs.append(df)

malicious_df = pd.concat(malicious_dfs, ignore_index=True)

# Combine all
df = pd.concat([benign_df, malicious_df], ignore_index=True)

print("Final dataset shape:", df.shape)
# print("Final dataset:", df.head())
print(df["label"].value_counts())

# -----------------------------
# 2. CLEANING
# -----------------------------
# df = df.drop_duplicates()
# df = df.dropna()

# groups = df["flow_id"]
# groups = df["src_ip"]
# groups = df["dns_second_level_domain"]

# -----------------------------
# 3. DROP NON-USEFUL COLUMNS
# -----------------------------
drop_cols = [
    "flow_id",
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port", #for testing purposes
    "dst_port", #for testing purposes
    "dns_domain_name",
    "dns_top_level_domain",
    "dns_second_level_domain",
    "uni_gram_domain_name",
    "bi_gram_domain_name",
    "tri_gram_domain_name",
    "character_distribution",
    "ans_resource_record_type",   # string/list-like
    "ans_resource_record_class"
    # "ttl_values_mean",
    # "ttl_values_mode",
    # "ttl_values_max",
    # "ttl_values_min",
    # "ttl_values_median",
    # "distinct_ttl_values",
    # "distinct_A_records"
]

df = df.drop(columns=[col for col in drop_cols if col in df.columns])

# -----------------------------
# 4. LABEL ENCODING
# -----------------------------
# Target
le = LabelEncoder()
df["label"] = le.fit_transform(df["label"])  # Benign=0, Attack=1

# -----------------------------
# 5. HANDLE REMAINING NON-NUMERIC
# -----------------------------
# Convert any remaining object columns
# print(df.dtypes)
for col in df.select_dtypes(include=["object"]).columns:
    # print(f"Encoding column: {col}")
    df[col] = LabelEncoder().fit_transform(df[col])
    # print(f"Encoded column: {col}")

# -----------------------------
# 6. SPLIT FEATURES / LABEL
# -----------------------------
X = df.drop(columns=["label"])
y = df["label"]
# print("labels:", y.unique())
print("Final feature count:", X.shape[1])
print("feature names:", X.columns.tolist())
# print("Class distribution:\n", y.value_counts())

# -----------------------------
# 7. TRAIN / TEST SPLIT
# -----------------------------

# groups = df["dns_second_level_domain"]

## OPTION 1: split with grouping

# from sklearn.model_selection import GroupShuffleSplit

# gss = GroupShuffleSplit(test_size=0.2, random_state=42)

# train_idx, test_idx = next(gss.split(X, y, groups))

# X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
# y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

## OPTION 2: regular split

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    stratify=y,
    random_state=42
)

## OPTION 3: Stratified Group K-Fold (for more robust evaluation)   

# from sklearn.model_selection import StratifiedGroupKFold

# sgkf = StratifiedGroupKFold(n_splits=5)

# for train_idx, test_idx in sgkf.split(X, y, groups):
#     X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
#     y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
    
#     break  # use first split

# -----------------------------
# 8. SCALING (for LR)
# -----------------------------
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# -----------------------------
# 9. LOGISTIC REGRESSION
# -----------------------------
lr = LogisticRegression(max_iter=1000, class_weight="balanced")

lr.fit(X_train_scaled, y_train)

y_pred_lr = lr.predict(X_test_scaled)
y_prob_lr = lr.predict_proba(X_test_scaled)[:, 1]

print_full_precision_classification_report("Logistic Regression", y_test, y_pred_lr)
print("ROC-AUC:", f"{roc_auc_score(y_test, y_prob_lr):.15f}")

# -----------------------------
# 10. RANDOM FOREST
# -----------------------------
rf = RandomForestClassifier(
    n_estimators=200,
    n_jobs=-1,
    random_state=42,
    class_weight="balanced"
)
# y_shuffled = np.random.permutation(y_train)
# rf.fit(X_train, y_shuffled)

rf.fit(X_train, y_train)

y_pred_rf = rf.predict(X_test)
y_prob_rf = rf.predict_proba(X_test)[:, 1]

print_full_precision_classification_report("Random Forest", y_test, y_pred_rf)
print("ROC-AUC:", f"{roc_auc_score(y_test, y_prob_rf):.15f}")

# -----------------------------
# 11. XGBOOST
# -----------------------------
xgb = XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    n_jobs=-1,
    eval_metric="logloss"
)

xgb.fit(X_train, y_train)

y_pred_xgb = xgb.predict(X_test)
y_prob_xgb = xgb.predict_proba(X_test)[:, 1]

print_full_precision_classification_report("XGBoost", y_test, y_pred_xgb)
print("ROC-AUC:", f"{roc_auc_score(y_test, y_prob_xgb):.15f}")

# -----------------------------
# 12. CONFUSION MATRIX
# -----------------------------
print("\nConfusion Matrix (RF):")
print(confusion_matrix(y_test, y_pred_rf))

# -----------------------------
# 13. FEATURE IMPORTANCE
# -----------------------------
importances = rf.feature_importances_
feature_names = X.columns

feat_imp = pd.DataFrame({
    "feature": feature_names,
    "importance": importances
}).sort_values(by="importance", ascending=False)

print("\nTop 15 Features:")
print(feat_imp.head(15))

# -----------------------------
# 13. SAVE TRAINED MODELS / ARTIFACTS
# -----------------------------
joblib.dump({
    "model": lr,
    "scaler": scaler,
    "label_encoder": le,
    "feature_columns": X.columns.tolist()
}, "dns_tunnel_logistic_model_test.pkl")

joblib.dump({
    "model": rf,
    "label_encoder": le,
    "feature_columns": X.columns.tolist()
}, "dns_tunnel_random_forest_model_test.pkl")

joblib.dump({
    "model": xgb,
    "label_encoder": le,
    "feature_columns": X.columns.tolist()
}, "dns_tunnel_xgboost_model_test.pkl")

print("Saved: dns_tunnel_logistic_model_test.pkl, dns_tunnel_random_forest_model_test.pkl, dns_tunnel_xgboost_model_test.pkl")

