import argparse
import joblib
import numpy as np

from dga_features import extract_features


def main():
    parser = argparse.ArgumentParser(description="Predict if domain is DGA or legit")
    parser.add_argument("domain", help="Domain to classify, e.g. google.com")
    parser.add_argument(
        "--model",
        default="models/dga_xgboost_model.pkl",
        help="Path to saved model bundle (.pkl)",
    )
    args = parser.parse_args()

    bundle = joblib.load(args.model)

    model = bundle["model"]
    label_encoder = bundle.get("label_encoder")
    scaler = bundle.get("scaler")

    domain = args.domain.strip().lower()

    features = np.array([extract_features(domain)], dtype=float)

    if scaler is not None:
        features = scaler.transform(features)

    pred_idx = model.predict(features)[0]

    if label_encoder is not None:
        pred_label = label_encoder.inverse_transform([pred_idx])[0]
    else:
        pred_label = str(pred_idx)

    print(f"Domain: {domain}")
    print(f"Prediction: {pred_label}")

    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(features)[0]

        if label_encoder is not None:
            class_names = [str(c) for c in label_encoder.inverse_transform(model.classes_)]
        else:
            class_names = [str(c) for c in model.classes_]

        probabilities = dict(zip(class_names, proba))

        print("Probabilities:")
        for class_name, probability in sorted(probabilities.items(), key=lambda item: item[1], reverse=True):
            print(f"  {class_name}: {probability:.4f}")

        dga_key = None
        for class_name in probabilities:
            if class_name.lower() == "dga":
                dga_key = class_name
                break

        if dga_key is not None:
            print(f"DGA score: {probabilities[dga_key]:.4f}")


if __name__ == "__main__":
    main()