import pandas as pd
import joblib
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.base import clone
from sklearn.pipeline import make_pipeline

from dga_features import FEATURE_NAMES


# 1. Load dataset (path relative to repository root)
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
data = pd.read_csv(ROOT / "output_dataset" / "Raw_Domain_Dataset_labeled.csv")

# Features
X = data.drop("domain_class", axis=1)

# Labels
y = data["domain_class"]


def compute_metrics(y_true, y_pred):
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
    }


def print_train_test_metrics(model_name, y_train_true, y_train_pred, y_test_true, y_test_pred):
    train_metrics = compute_metrics(y_train_true, y_train_pred)
    test_metrics = compute_metrics(y_test_true, y_test_pred)

    print(f"===== {model_name} =====")
    print(
        "Train metrics: "
        f"acc={train_metrics['accuracy']:.4f}, "
        f"prec={train_metrics['precision']:.4f}, "
        f"rec={train_metrics['recall']:.4f}, "
        f"f1={train_metrics['f1']:.4f}"
    )
    print(
        "Test metrics:  "
        f"acc={test_metrics['accuracy']:.4f}, "
        f"prec={test_metrics['precision']:.4f}, "
        f"rec={test_metrics['recall']:.4f}, "
        f"f1={test_metrics['f1']:.4f}"
    )
    print(classification_report(y_test_true, y_test_pred))

    return train_metrics, test_metrics


# 2. Encode labels
encoder = LabelEncoder()
y = encoder.fit_transform(y)  # legit=0, dga=1


# 3. Train/Test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    stratify=y,
    random_state=42
)


# 4. Logistic Regression

# Logistic regression requires feature scaling
scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

log_model = LogisticRegression(max_iter=1000)

log_model.fit(X_train_scaled, y_train)

y_pred_log_train = log_model.predict(X_train_scaled)
y_pred_log = log_model.predict(X_test_scaled)

log_train_metrics, log_test_metrics = print_train_test_metrics(
    "Logistic Regression", y_train, y_pred_log_train, y_test, y_pred_log
)


# 5. Random Forest

rf_model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

rf_model.fit(X_train, y_train)

y_pred_rf_train = rf_model.predict(X_train)
y_pred_rf = rf_model.predict(X_test)

rf_train_metrics, rf_test_metrics = print_train_test_metrics(
    "Random Forest", y_train, y_pred_rf_train, y_test, y_pred_rf
)

# 6. XGBoost

xgb_model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    eval_metric='logloss',
    use_label_encoder=False
)

xgb_model.fit(X_train, y_train)

y_pred_xgb_train = xgb_model.predict(X_train)
y_pred_xgb = xgb_model.predict(X_test)

xgb_train_metrics, xgb_test_metrics = print_train_test_metrics(
    "XGBoost", y_train, y_pred_xgb_train, y_test, y_pred_xgb
)


# 7. Stratified 5-fold CV + compact overfitting report

scoring = {
    "accuracy": "accuracy",
    "precision": "precision",
    "recall": "recall",
    "f1": "f1",
}

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

model_specs = [
    {
        "name": "Logistic Regression",
        "estimator": LogisticRegression(max_iter=1000),
        "use_scaling": True,
        "train_metrics": log_train_metrics,
        "test_metrics": log_test_metrics,
    },
    {
        "name": "Random Forest",
        "estimator": RandomForestClassifier(n_estimators=100, random_state=42),
        "use_scaling": False,
        "train_metrics": rf_train_metrics,
        "test_metrics": rf_test_metrics,
    },
    {
        "name": "XGBoost",
        "estimator": XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            eval_metric='logloss',
            use_label_encoder=False,
        ),
        "use_scaling": False,
        "train_metrics": xgb_train_metrics,
        "test_metrics": xgb_test_metrics,
    },
]

report_rows = []

for spec in model_specs:
    base_estimator = clone(spec["estimator"])
    if spec["use_scaling"]:
        cv_estimator = make_pipeline(StandardScaler(), base_estimator)
    else:
        cv_estimator = base_estimator

    cv_scores = cross_validate(
        cv_estimator,
        X,
        y,
        cv=cv,
        scoring=scoring,
        n_jobs=1,
    )

    row = {
        "model": spec["name"],
        "train_acc": spec["train_metrics"]["accuracy"],
        "test_acc": spec["test_metrics"]["accuracy"],
        "train_precision": spec["train_metrics"]["precision"],
        "test_precision": spec["test_metrics"]["precision"],
        "train_recall": spec["train_metrics"]["recall"],
        "test_recall": spec["test_metrics"]["recall"],
        "train_f1": spec["train_metrics"]["f1"],
        "test_f1": spec["test_metrics"]["f1"],
        "f1_gap_train_minus_test": spec["train_metrics"]["f1"] - spec["test_metrics"]["f1"],
        "cv_acc_mean": cv_scores["test_accuracy"].mean(),
        "cv_acc_std": cv_scores["test_accuracy"].std(),
        "cv_precision_mean": cv_scores["test_precision"].mean(),
        "cv_precision_std": cv_scores["test_precision"].std(),
        "cv_recall_mean": cv_scores["test_recall"].mean(),
        "cv_recall_std": cv_scores["test_recall"].std(),
        "cv_f1_mean": cv_scores["test_f1"].mean(),
        "cv_f1_std": cv_scores["test_f1"].std(),
    }
    report_rows.append(row)

overfitting_report = pd.DataFrame(report_rows).sort_values(by="test_f1", ascending=False)

print("===== Overfitting Report (compact) =====")
print(overfitting_report.to_string(index=False, float_format=lambda x: f"{x:.4f}"))

overfitting_report_path = "dga_overfitting_report.csv"
overfitting_report.to_csv(overfitting_report_path, index=False)
print(f"Saved overfitting report to: {overfitting_report_path}")

# 10. Feature importance (Random Forest)

importances = pd.Series(
    rf_model.feature_importances_,
    index=X.columns
)

print("===== Feature Importance =====")
print(importances.sort_values(ascending=False))

# 11. Save trained models/artifacts

joblib.dump({
    "model": log_model,
    "scaler": scaler,
    "label_encoder": encoder,
    "feature_columns": X.columns.tolist()
}, "dga_logistic_model_2.pkl")

joblib.dump({
    "model": rf_model,
    "label_encoder": encoder,
    "feature_columns": X.columns.tolist()
}, "dga_random_forest_model_2.pkl")

joblib.dump({
    "model": xgb_model,
    "label_encoder": encoder,
    "feature_columns": X.columns.tolist()
}, "dga_xgboost_model_2.pkl")

# joblib.dump({
#     "model": svm_model,
#     "scaler": scaler,
#     "label_encoder": encoder,
#     "feature_columns": X.columns.tolist()
# }, "dga_svm_model_2.pkl")

# joblib.dump({
#     "model": mlp_model,
#     "scaler": scaler,
#     "label_encoder": encoder,
#     "feature_columns": X.columns.tolist()
# }, "dga_mlp_model_2.pkl")

print("Saved: dga_logistic_model_2.pkl, dga_random_forest_model_2.pkl, dga_xgboost_model_2.pkl, dga_svm_model_2.pkl, dga_mlp_model_2.pkl")