import argparse
import json
import sys

import joblib
import numpy as np
import pandas as pd


def resolve_class_names(model, label_encoder):
    classes = getattr(model, "classes_", None)
    if classes is None:
        return None
    if label_encoder is None:
        return [str(c) for c in classes]
    try:
        decoded = label_encoder.inverse_transform(classes)
        return [str(c) for c in decoded]
    except Exception:
        return [str(c) for c in classes]


def resolve_predicted_labels(predictions, label_encoder):
    if label_encoder is None:
        return [str(p) for p in predictions]
    try:
        decoded = label_encoder.inverse_transform(predictions)
        return [str(p) for p in decoded]
    except Exception:
        return [str(p) for p in predictions]


def build_feature_matrix(df, feature_columns):
    prepared = df.copy()

    missing_columns = [c for c in feature_columns if c not in prepared.columns]
    for col in missing_columns:
        prepared[col] = 0.0

    prepared = prepared[feature_columns]

    for col in prepared.columns:
        prepared[col] = pd.to_numeric(prepared[col], errors="coerce")

    prepared = prepared.fillna(-1.0)
    return prepared, missing_columns


def main():
    parser = argparse.ArgumentParser(
        description="Predict DNS tunneling labels from ALFlowLyzer CSV features"
    )
    parser.add_argument(
        "input_csv",
        help="Path to ALFlowLyzer CSV with extracted features",
    )
    parser.add_argument(
        "--model",
        default="models/dns_tunnel_random_forest_model.pkl",
        help="Path to saved tunnel model bundle",
    )
    parser.add_argument(
        "--output-csv",
        default=None,
        help="Optional path to save CSV with predictions",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Threshold for malicious alert score",
    )
    args = parser.parse_args()

    bundle = joblib.load(args.model)
    model = bundle["model"]
    label_encoder = bundle.get("label_encoder")
    scaler = bundle.get("scaler")
    feature_columns = bundle.get("feature_columns")

    if not feature_columns:
        print("Model bundle does not contain feature_columns.", file=sys.stderr)
        sys.exit(1)

    df = pd.read_csv(args.input_csv)
    X_df, missing_columns = build_feature_matrix(df, feature_columns)
    X = X_df

    if scaler is not None:
        scaled = scaler.transform(X_df.values)
        X = pd.DataFrame(scaled, columns=feature_columns)

    raw_predictions = model.predict(X)
    predicted_labels = resolve_predicted_labels(raw_predictions, label_encoder)

    malicious_scores = np.zeros(len(df), dtype=float)
    class_names = resolve_class_names(model, label_encoder)

    if hasattr(model, "predict_proba") and class_names is not None:
        probs = model.predict_proba(X)
        class_to_idx = {name.lower(): idx for idx, name in enumerate(class_names)}

        malicious_idx = None
        for candidate in ["malicious", "attack", "tunnel", "dns_tunneling"]:
            if candidate in class_to_idx:
                malicious_idx = class_to_idx[candidate]
                break

        if malicious_idx is None and probs.shape[1] == 2:
            malicious_idx = 1

        if malicious_idx is not None:
            malicious_scores = probs[:, malicious_idx]

    result_df = df.copy()
    result_df["predicted_label"] = predicted_labels
    result_df["malicious_score"] = malicious_scores

    alerts = []
    for idx, row in result_df.iterrows():
        if float(row["malicious_score"]) >= args.threshold:
            alerts.append(
                {
                    "row_index": int(idx),
                    "predicted_label": str(row["predicted_label"]),
                    "malicious_score": round(float(row["malicious_score"]), 6),
                    "dns_domain_name": str(row.get("dns_domain_name", "")),
                    "src_ip": str(row.get("src_ip", "")),
                    "dst_ip": str(row.get("dst_ip", "")),
                }
            )

    print(
        json.dumps(
            {
                "rows_total": int(len(result_df)),
                "alerts": int(len(alerts)),
                "threshold": float(args.threshold),
                "missing_feature_columns": missing_columns,
            }
        )
    )

    for alert in alerts:
        print(json.dumps(alert))

    if args.output_csv:
        result_df.to_csv(args.output_csv, index=False)
        print(json.dumps({"saved_predictions_csv": args.output_csv}))


if __name__ == "__main__":
    main()
