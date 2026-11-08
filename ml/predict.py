"""
predict.py - ML prediction interface for the proxy.

Loads the trained model and vectoriser, provides a simple function
that takes a request string and returns whether it's malicious.

This gets called from the proxy as the third detection layer —
only for requests that passed both the SQLi and XSS regex rules.
"""

import os
import joblib
from config import ML_MODEL_PATH, ML_VECTORIZER_PATH, ML_CONFIDENCE_THRESHOLD

# lazy-load: model gets loaded on first prediction, not at import time
_model = None
_vectorizer = None
_available = None


def _load_model():
    """Load model and vectorizer from disk. Called once on first use."""
    global _model, _vectorizer, _available

    if not os.path.exists(ML_MODEL_PATH) or not os.path.exists(ML_VECTORIZER_PATH):
        _available = False
        return

    try:
        _model = joblib.load(ML_MODEL_PATH)
        _vectorizer = joblib.load(ML_VECTORIZER_PATH)
        _available = True
    except Exception as e:
        print(f"[SecureShield] Warning: Could not load ML model: {e}")
        _available = False


def is_available():
    """Check if the ML model is loaded and ready."""
    if _available is None:
        _load_model()
    return _available


def predict(text):
    """
    Classify a request string as malicious or benign.

    Args:
        text: the request content to classify (query string + body combined)

    Returns:
        None if model unavailable or prediction is benign.
        Dict with details if classified as malicious:
        {"confidence": float, "label": str}
    """
    if not is_available():
        return None

    if not text or not text.strip():
        return None

    # vectorise the input using the same TF-IDF transformer
    features = _vectorizer.transform([text])

    # get prediction and probability
    prediction = _model.predict(features)[0]
    probabilities = _model.predict_proba(features)[0]

    # probabilities[1] = probability of class 1 (malicious)
    confidence = probabilities[1]

    # only flag as malicious if confidence exceeds threshold
    if prediction == 1 and confidence >= ML_CONFIDENCE_THRESHOLD:
        return {
            "confidence": round(float(confidence), 4),
            "label": "malicious",
        }

    return None


def reload_model():
    """Force reload of model (useful after retraining)."""
    global _model, _vectorizer, _available
    _model = None
    _vectorizer = None
    _available = None
    _load_model()
