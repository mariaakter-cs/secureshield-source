"""
train.py - Train the Logistic Regression classifier.

Takes the prepared data from prepare_data.py (TF-IDF features + labels)
and trains a binary classifier: malicious (1) vs benign (0).

Outputs:
- ml/model/classifier.pkl — the trained model
- ml/model/vectorizer.pkl — the TF-IDF vectoriser (copied from prepared/)
- ml/model/metrics.json — accuracy, precision, recall, F1
- Classification report printed to console

Run prepare_data.py first if ml/prepared/ doesn't exist.
"""

import os
import sys
import json
import numpy as np
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

PREPARED_DIR = os.path.join(os.path.dirname(__file__), "prepared")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "model")


def main():
    # check that prepare_data.py has been run
    if not os.path.exists(os.path.join(PREPARED_DIR, "X_train.pkl")):
        print("Error: prepared data not found. Run prepare_data.py first.")
        sys.exit(1)

    # load prepared data
    print("Loading prepared data...")
    X_train = joblib.load(os.path.join(PREPARED_DIR, "X_train.pkl"))
    X_test = joblib.load(os.path.join(PREPARED_DIR, "X_test.pkl"))
    y_train = joblib.load(os.path.join(PREPARED_DIR, "y_train.pkl"))
    y_test = joblib.load(os.path.join(PREPARED_DIR, "y_test.pkl"))

    print(f"  Train: {X_train.shape[0]} samples, {X_train.shape[1]} features")
    print(f"  Test: {X_test.shape[0]} samples")

    # train the model
    print("\nTraining Logistic Regression...")
    model = LogisticRegression(
        max_iter=1000,      # enough iterations to converge
        C=1.0,              # regularisation strength (default)
        solver="lbfgs",     # good general-purpose solver
        random_state=42,    # reproducible
    )
    model.fit(X_train, y_train)
    print("  Training complete.")

    # evaluate on test set
    print("\nEvaluating on test set...")
    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    print(f"\n  Accuracy:  {accuracy:.4f} ({accuracy*100:.1f}%)")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1 Score:  {f1:.4f}")
    print(f"\n  Confusion Matrix:")
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")

    print("\n  Full Classification Report:")
    print(classification_report(y_test, y_pred,
                                target_names=["benign", "malicious"]))

    # save model
    os.makedirs(MODEL_DIR, exist_ok=True)
    model_path = os.path.join(MODEL_DIR, "classifier.pkl")
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")

    # copy vectorizer to model dir too (needed at prediction time)
    vectorizer_src = os.path.join(PREPARED_DIR, "vectorizer.pkl")
    vectorizer_dst = os.path.join(MODEL_DIR, "vectorizer.pkl")
    vectorizer = joblib.load(vectorizer_src)
    joblib.dump(vectorizer, vectorizer_dst)
    print(f"Vectorizer saved to {vectorizer_dst}")

    # save metrics
    metrics = {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": {
            "true_negatives": int(cm[0][0]),
            "false_positives": int(cm[0][1]),
            "false_negatives": int(cm[1][0]),
            "true_positives": int(cm[1][1]),
        },
        "train_samples": X_train.shape[0],
        "test_samples": X_test.shape[0],
    }
    metrics_path = os.path.join(MODEL_DIR, "metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"Metrics saved to {metrics_path}")

    # final verdict
    if accuracy >= 0.90:
        print(f"\n✓ Target met: {accuracy*100:.1f}% accuracy (target: ≥90%)")
    else:
        print(f"\n✗ Target NOT met: {accuracy*100:.1f}% accuracy (target: ≥90%)")
        print("  Consider: more training data, feature tuning, or hyperparameter search.")


if __name__ == "__main__":
    main()
