import json
import time
from pathlib import Path

import joblib
from sklearn.metrics import (
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)

from rules.sqli import scan_request as sqli_scan
from rules.xss import scan_request as xss_scan
from ml.predict import predict, is_available


def decision(value):
    """Convert common detector outputs into a binary decision."""
    if isinstance(value, dict):
        if "matched" in value and "category" in value:
            return 1
        for key in (
            "is_attack", "is_malicious", "malicious",
            "detected", "blocked", "prediction", "label"
        ):
            if key in value:
                return decision(value[key])
        raise ValueError(f"Unknown detector result: {value!r}")

    if isinstance(value, (tuple, list)):
        if not value:
            return 0
        return decision(value[0])

    if isinstance(value, str):
        value = value.strip().lower()

        if value in (
            "0", "benign", "normal", "safe",
            "allow", "allowed", "clean", "false", "none"
        ):
            return 0

        if value in (
            "1", "malicious", "attack", "sqli",
            "xss", "block", "blocked", "true"
        ):
            return 1

        raise ValueError(f"Unknown detector result: {value!r}")

    return int(bool(value))


def regex_detect(text):
    return int(
        decision(sqli_scan(text, "")) or
        decision(xss_scan(text, ""))
    )


def hybrid_detect(text):
    if regex_detect(text):
        return 1

    return decision(predict(text))


def evaluate(name, detector, texts, labels):
    predictions = []
    durations = []

    for text in texts:
        start = time.perf_counter()
        result = detector(str(text))
        elapsed = time.perf_counter() - start

        predictions.append(result)
        durations.append(elapsed * 1000)

    tn, fp, fn, tp = confusion_matrix(
        labels, predictions, labels=[0, 1]
    ).ravel()

    return {
        "mode": name,
        "samples": len(labels),
        "TP": int(tp),
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(
            precision_score(labels, predictions, zero_division=0)
        ),
        "recall": float(
            recall_score(labels, predictions, zero_division=0)
        ),
        "f1": float(
            f1_score(labels, predictions, zero_division=0)
        ),
        "false_positive_rate": (
            float(fp / (fp + tn)) if fp + tn else 0.0
        ),
        "mean_detection_ms": float(
            sum(durations) / len(durations)
        ),
    }


def main():
    texts = joblib.load("ml/prepared/X_test_text.pkl")
    labels = joblib.load("ml/prepared/y_test.pkl")

    labels = [int(x) for x in labels]

    if set(labels) - {0, 1}:
        raise ValueError("Test labels must be 0 or 1")

    if not is_available():
        raise RuntimeError("Trained ML model is unavailable")

    print("SECURESHIELD DETECTION COMPARISON")
    print("=" * 45)
    print("Test samples:", len(texts))
    print("Regex benign test:", regex_detect("hello world"))
    print("Regex SQLi test:", regex_detect("' OR 1=1 --"))
    print(
        "Regex XSS test:",
        regex_detect("<script>alert(1)</script>")
    )
    print("ML benign output:", repr(predict("hello world")))

    results = [
        evaluate("Regex-only", regex_detect, texts, labels),
        evaluate("Regex + ML", hybrid_detect, texts, labels),
    ]

    for result in results:
        print("\nMode:", result["mode"])
        print("-" * 35)

        for key, value in result.items():
            if key == "mode":
                continue

            if key in (
                "accuracy", "precision", "recall",
                "f1", "false_positive_rate"
            ):
                print(f"{key}: {value:.2%}")
            elif key == "mean_detection_ms":
                print(f"{key}: {value:.4f} ms")
            else:
                print(f"{key}: {value}")

    Path("reports").mkdir(exist_ok=True)

    with open("reports/detection_comparison.json", "w") as file:
        json.dump(results, file, indent=2)

    print("\nResults saved to reports/detection_comparison.json")


if __name__ == "__main__":
    main()