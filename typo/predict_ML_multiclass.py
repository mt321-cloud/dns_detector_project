import argparse
import joblib
import numpy as np

from typo_features import extract_features


def main():
    parser = argparse.ArgumentParser(description="Predict typo class from two domains")
    parser.add_argument("target_domain", help="Reference domain, e.g. google.com")
    parser.add_argument("query_domain", help="Queried domain, e.g. goggle.com")
    parser.add_argument(
        "--model",
        default="models/typosquatting_multiclass_model_brf_reduced_homo_5.pkl",
        help="Path to saved model bundle",
    )
    parser.add_argument(
        "--class-name",
        default=None,
        help="Optional class name to print probability for, e.g. replacement",
    )
    args = parser.parse_args()

    bundle = joblib.load(args.model)
    model = bundle["model"]

    target = args.target_domain.lower()
    query = args.query_domain.lower()

    x = np.array([extract_features(target, query)], dtype=float)

    predicted_class = model.predict(x)[0]
    probabilities = dict(zip(model.classes_, model.predict_proba(x)[0]))
    print("probabilities:", probabilities)

    print(f"Predicted class: {predicted_class}")
    print("Probabilities:")
    for class_name, probability in sorted(probabilities.items(), key=lambda item: item[1], reverse=True):
        print(f"  {class_name}: {probability:.4f}")

    if args.class_name is not None:
        print(f"\nP({args.class_name}) = {probabilities.get(args.class_name, 0.0):.4f}")


if __name__ == "__main__":
    main()