"""
prepare_data.py - Builds the labelled dataset for the ML classifier.

This script:
1. Loads payload samples from the text files in ml/data/
2. Labels them (sqli, xss, or benign)
3. Combines into a single dataset
4. Applies TF-IDF vectorisation
5. Splits into train (80%) and test (20%)
6. Saves everything to disk for the training script to use

I'm keeping the data preparation separate from training so I can
inspect the dataset independently and make sure it looks right before
fitting a model to it.
"""

import os
import sys
import json
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
import joblib

# paths
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "prepared")


def load_samples(filename):
    """Load lines from a text file, strip whitespace, skip blanks."""
    filepath = os.path.join(DATA_DIR, filename)
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def build_dataset():
    """
    Combine all sample files into a single labelled dataset.
    Labels:
        0 = benign
        1 = malicious (sqli or xss)

    I'm using binary classification (malicious vs benign) rather than
    multi-class (sqli vs xss vs benign) because:
    - The ML model is a backup — specific attack type is already identified by rules
    - Binary classification is simpler and more robust with limited data
    - The model just needs to flag "this looks suspicious" for anything the rules missed
    """
    print("Loading samples...")

    sqli = load_samples("sqli_samples.txt")
    xss = load_samples("xss_samples.txt")
    benign = load_samples("benign_samples.txt")

    print(f"  SQLi samples: {len(sqli)}")
    print(f"  XSS samples: {len(xss)}")
    print(f"  Benign samples: {len(benign)}")

    # combine malicious together
    malicious = sqli + xss
    print(f"  Total malicious: {len(malicious)}")
    print(f"  Total benign: {len(benign)}")

    # create labels: 0 = benign, 1 = malicious
    texts = benign + malicious
    labels = [0] * len(benign) + [1] * len(malicious)

    print(f"  Total dataset: {len(texts)} samples")
    print(f"  Class balance: {labels.count(0)} benign, {labels.count(1)} malicious")

    return texts, labels


def create_tfidf_pipeline(texts):
    """
    Fit a TF-IDF vectoriser on the training data.

    Settings I chose:
    - analyzer='char_wb': use character n-grams within word boundaries.
      This works better than word-level for attack payloads because SQLi/XSS
      payloads aren't real words. Character patterns like "OR 1=" or "<scr"
      are more distinctive.
    - ngram_range=(2,5): character sequences of length 2 to 5.
      Short enough to catch patterns like "1=1" or "alert" but not so long
      that we overfit to specific payloads.
    - max_features=3000: cap the vocabulary. Keeps the model small and fast.
    - sublinear_tf=True: applies log scaling to term frequencies.
      Helps when some characters appear much more often than others.
    """
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(2, 5),
        max_features=3000,
        sublinear_tf=True,
        strip_accents="unicode",
    )
    return vectorizer


def main():
    """Run the full data preparation pipeline."""
    # create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 1. build dataset
    texts, labels = build_dataset()

    # 2. split into train/test (80/20)
    print("\nSplitting dataset (80% train, 20% test)...")
    X_train_text, X_test_text, y_train, y_test = train_test_split(
        texts, labels,
        test_size=0.2,
        random_state=42,  # fixed seed for reproducibility
        stratify=labels,  # maintain class balance in both sets
    )
    print(f"  Train set: {len(X_train_text)} samples")
    print(f"  Test set: {len(X_test_text)} samples")

    # 3. fit TF-IDF on training data only (no data leakage)
    print("\nFitting TF-IDF vectoriser on training data...")
    vectorizer = create_tfidf_pipeline(X_train_text)
    X_train = vectorizer.fit_transform(X_train_text)
    X_test = vectorizer.transform(X_test_text)
    print(f"  Feature matrix shape: {X_train.shape}")
    print(f"  Vocabulary size: {len(vectorizer.vocabulary_)}")

    # 4. save everything
    print("\nSaving prepared data...")
    joblib.dump(vectorizer, os.path.join(OUTPUT_DIR, "vectorizer.pkl"))
    joblib.dump(X_train, os.path.join(OUTPUT_DIR, "X_train.pkl"))
    joblib.dump(X_test, os.path.join(OUTPUT_DIR, "X_test.pkl"))
    joblib.dump(np.array(y_train), os.path.join(OUTPUT_DIR, "y_train.pkl"))
    joblib.dump(np.array(y_test), os.path.join(OUTPUT_DIR, "y_test.pkl"))

    # also save the raw text for inspection
    joblib.dump(X_train_text, os.path.join(OUTPUT_DIR, "X_train_text.pkl"))
    joblib.dump(X_test_text, os.path.join(OUTPUT_DIR, "X_test_text.pkl"))

    # save a summary
    summary = {
        "total_samples": len(texts),
        "train_samples": len(X_train_text),
        "test_samples": len(X_test_text),
        "benign_count": labels.count(0),
        "malicious_count": labels.count(1),
        "feature_count": X_train.shape[1],
        "vectorizer_params": {
            "analyzer": "char_wb",
            "ngram_range": [2, 5],
            "max_features": 3000,
        }
    }
    with open(os.path.join(OUTPUT_DIR, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\nDone! Files saved to {OUTPUT_DIR}/")
    print(f"Summary: {json.dumps(summary, indent=2)}")


if __name__ == "__main__":
    main()
