# Sprint 8 Report — ML Data Preparation

**Sprint dates:** 14 September – 20 September 2026  
**Objective:** Collect and label a dataset of HTTP request payloads, implement TF-IDF vectorisation pipeline, and split into train/test sets.

---

## What I built

A data preparation pipeline (`ml/prepare_data.py`) that loads attack payloads and benign inputs from text files, labels them, applies TF-IDF feature extraction, and saves train/test splits ready for model training in Sprint 9.

---

## Dataset composition

| Category | Samples | Source |
| --- | --- | --- |
| SQL Injection | 50 | OWASP payload lists, SQLi cheat sheets, manual variations |
| Cross-Site Scripting | 50 | XSS payload lists, PortSwigger cheat sheet, manual variations |
| Benign (legitimate) | 79 | Made up — normal search queries, form inputs, URLs, account activity messages |
| **Total** | **179** | |

The malicious set is intentionally diverse — I included payloads from different SQLi categories (UNION, error-based, time-based, boolean-blind, stacked queries) and different XSS vectors (script tags, event handlers, javascript: protocol, DOM manipulation, encoded payloads).

The benign set includes tricky inputs that contain words like "select", "union", "or", "drop", "script", "alert" in normal English context. These are the ones that would trip up a naive keyword-based detector but should be handled correctly by a model that looks at character patterns rather than individual words.

---

## Why binary classification (not multi-class)

I'm training the model to classify as **malicious vs benign** (binary), not **SQLi vs XSS vs benign** (multi-class). Reasoning:

1. The ML model is a backup — the regex rules already identify the specific attack type. The model just needs to catch things the rules missed.
2. Binary classification is more robust with limited data (179 samples is small).
3. Simpler model = less chance of overfitting.

---

## TF-IDF configuration

| Parameter | Value | Why |
| --- | --- | --- |
| `analyzer` | `char_wb` | Character n-grams work better than words for attack payloads (they're not real English words) |
| `ngram_range` | (2, 5) | Short enough for patterns like `1=1`, `<sc`, `ert(` but not so long we overfit |
| `max_features` | 3000 | Keeps the model manageable; 3000 character patterns is plenty |
| `sublinear_tf` | True | Log-scales term frequencies to reduce the impact of very common characters |

I chose character-level n-grams over word-level because SQL injection and XSS payloads aren't structured as normal words. A word-level tokeniser would see `' UNION SELECT null --` as individual tokens, but a character n-gram approach picks up on patterns like `' U`, `UNI`, `ION`, `SEL` which are more robust to variations.

---

## Train/test split

- **80% train** (143 samples) — used to fit the model
- **20% test** (36 samples) — held out for evaluation
- **Stratified** — class balance maintained in both sets
- **Random seed fixed** (42) — reproducible results

I fit the TF-IDF vectoriser on training data only. The test data is transformed using the already-fitted vectoriser. This prevents data leakage — the model never sees test patterns during training.

---

## Output files

Everything saves to `ml/prepared/` (gitignored since it's regenerated):

| File | Contents |
| --- | --- |
| `vectorizer.pkl` | Fitted TF-IDF vectoriser (needed at prediction time too) |
| `X_train.pkl` | TF-IDF feature matrix for training (143 × 3000 sparse matrix) |
| `X_test.pkl` | TF-IDF feature matrix for testing (36 × 3000 sparse matrix) |
| `y_train.pkl` | Training labels (0=benign, 1=malicious) |
| `y_test.pkl` | Test labels |
| `X_train_text.pkl` | Raw text of training samples (for inspection) |
| `X_test_text.pkl` | Raw text of test samples (for inspection) |
| `summary.json` | Dataset statistics in a readable format |

---

## How to run

```bash
cd secureshield
source venv/bin/activate
python ml/prepare_data.py
```

Output shows sample counts, split sizes, and feature matrix dimensions.

---

## What I'd improve with more data

- 179 samples is small. A production system would want thousands. But for proving the concept works, it's enough.
- I could augment the dataset with encoded variants of existing payloads (URL encoding, double encoding, case mixing).
- Could add more categories of benign input (JSON bodies, XML, multipart form data).
- A real system would retrain periodically as new attack patterns emerge.

---

## Files created

| File | Purpose |
| --- | --- |
| `ml/data/sqli_samples.txt` | 50 SQLi payloads for training |
| `ml/data/xss_samples.txt` | 50 XSS payloads for training |
| `ml/data/benign_samples.txt` | 79 legitimate inputs for training |
| `ml/prepare_data.py` | Data loading, labelling, TF-IDF fitting, train/test split |
| `.gitignore` | Updated to exclude `ml/prepared/` (generated output) |

---

## Sprint 8 milestone status

**M8: Labelled dataset prepared; TF-IDF pipeline implemented.** ✓ Complete.
