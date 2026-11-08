# Sprint 9 Report — ML Model Training and Integration

**Sprint dates:** 21 September – 27 September 2026  
**Objective:** Train a Logistic Regression classifier and integrate into the proxy as the third detection layer.

---

## What I built

Two things this sprint:
1. A training script (`ml/train.py`) that fits a Logistic Regression model on the prepared TF-IDF features.
2. A prediction interface (`ml/predict.py`) that the proxy calls to classify requests that got past the regex rules.

---

## Model performance

| Metric | Result |
| --- | --- |
| **Accuracy** | 97.2% (35/36 correct) |
| **Precision** | 95.2% |
| **Recall** | 100% (no malicious requests missed) |
| **F1 Score** | 97.6% |

Confusion matrix (36 test samples):

|  | Predicted Benign | Predicted Malicious |
| --- | --- | --- |
| Actually Benign | 15 (TN) | 1 (FP) |
| Actually Malicious | 0 (FN) | 20 (TP) |

One false positive out of 36 test samples. Zero false negatives — the model caught every malicious payload in the test set.

---

## How it fits in the detection pipeline

The full pipeline is now:

```
Request → SQLi rules → XSS rules → Brute-force check → ML classifier → Forward to target
```

The ML model only runs if all three rule-based checks pass. This means:
- Rules handle the obvious, well-known patterns (fast, transparent)
- ML catches anything unusual that slipped past the rules (more flexible but less explainable)

The model has a configurable confidence threshold (default 0.7). If it classifies something as malicious but with low confidence, it lets it through. This reduces false positives at the cost of potentially missing some edge-case attacks — which is the right trade-off for a backup layer.

---

## Model details

| Setting | Value | Why |
| --- | --- | --- |
| Algorithm | Logistic Regression | Simple, fast, interpretable. Works well for text classification with TF-IDF features. |
| Solver | lbfgs | Good general-purpose solver for L2-regularised logistic regression. |
| Regularisation (C) | 1.0 (default) | No reason to tune this with the current data size. |
| max_iter | 1000 | More than enough for convergence. |
| Confidence threshold | 0.7 | Only block if model is 70%+ confident it's malicious. |

I considered using SVM or Random Forest but Logistic Regression is simpler, faster at prediction time, and gives probability estimates out of the box (which I need for the confidence threshold). With 97.2% accuracy there's no reason to add complexity.

---

## Prediction interface design

The `ml/predict.py` module uses lazy loading — the model doesn't get loaded into memory until the first prediction is requested. This means:
- If the model files don't exist (haven't trained yet), the proxy still works — it just skips the ML step
- No startup slowdown if the model isn't needed
- The `is_available()` check lets the proxy know whether to bother calling the ML layer

---

## Testing the threshold

I tested a few payloads to understand how the confidence threshold works:

| Input | Confidence | Blocked? |
| --- | --- | --- |
| `' OR 1=1 --` | 0.848 | Yes (above 0.7) |
| `<script>alert(1)</script>` | 0.898 | Yes |
| `1 UNION SELECT username FROM users` | 0.604 | No (below threshold — but rules catch this anyway) |
| `normal search query` | 0.404 | No |
| `My order number is 12345` | Low | No |

The model's lower confidence on some SQLi payloads doesn't matter because the regex rules in Sprint 5 already catch those with 96.7% accuracy. The ML model is there for the unusual patterns that don't match any rule.

---

## How to retrain

If I add more training data later:
```bash
# add samples to ml/data/*.txt files, then:
python ml/prepare_data.py   # re-process the data
python ml/train.py          # re-train the model
```

The proxy picks up the new model on restart (or call `ml.predict.reload_model()` to hot-reload).

---

## Files changed/created

| File | Change |
| --- | --- |
| `ml/train.py` | Rewritten — full training pipeline with evaluation and metrics saving |
| `ml/predict.py` | Rewritten — lazy-loading prediction interface with confidence threshold |
| `app/proxy.py` | Modified — ML classifier integrated as fourth detection layer |

---

## Sprint 9 milestone status

**M9: ML classifier trained and integrated into the detection pipeline.** ✓ Complete (97.2% accuracy, target was ≥90%).
