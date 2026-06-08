# Phishing URL Detector

Lightweight ML classifier that flags phishing URLs from the URL string alone — no DOM scraping, no WHOIS lookups, no external API calls. Built around 35 URL-string features (lexical, structural, entropy-based) and benchmarked across three classical models.

## Results

Trained on the PhiUSIIL Phishing URL Dataset (235,795 URLs; 134,850 legitimate, 100,945 phishing). Stratified 80/20 train/test split.

| Model | Phishing F1 | ROC-AUC | Precision | Recall |
|---|---|---|---|---|
| **Random Forest** | **0.9946** | **0.9977** | 0.9975 | 0.9917 |
| Logistic Regression | 0.9932 | 0.9967 | 0.9995 | 0.9870 |
| Linear SVM | 0.9928 | 0.9969 | 0.9998 | 0.9858 |

Random Forest is saved as `model.pkl` and used at inference time.

**A note on these numbers:** PhiUSIIL's phishing and legitimate classes separate cleanly on URL-string signals, so ~0.99 F1 reflects in-dataset performance, not real-world robustness. Adversarially obfuscated URLs (homoglyphs, punycode tricks, brand-impersonating IDNs) would degrade these numbers. Production phishing detection typically layers DOM signals, WHOIS age, certificate transparency logs, and brand-impersonation checks on top of URL-only models.

## Features (35)

All features are extracted from the URL string by `features.py::extract_features`:

- **Lengths & structure (9):** url, hostname, path, query, TLD, subdomain count, path depth, longest path token, path token count
- **Special characters (13):** counts of `. - _ / ? = @ & % # ~ + *`
- **Character composition (6):** digit count, letter count, digit ratio, hostname digit ratio, hostname entropy, path entropy
- **Security signals (7):** HTTPS, IP-as-host, custom port, `@` symbol, `//` in path, suspicious TLD, suspicious-word count

## Dataset

Prasad, A.; Chandra, S. (2024). *PhiUSIIL Phishing URL Dataset.* UCI Machine Learning Repository. <https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset>

PhiUSIIL labels legitimate as 1 and phishing as 0; `train.py` flips this so the rest of the codebase uses the more intuitive `1 = phishing, 0 = safe` convention.

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate         # Windows
pip install -r requirements.txt
```

## Train

Download the dataset to `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv`, then:

```bash
python train.py
```

Trains all three models, prints classification reports, saves the best (by F1) as `model.pkl`.

## Predict (Flask)

```bash
python app.py
```

Then open `http://localhost:5000` and submit a URL.

## Files

- `features.py` — 35-feature extractor
- `train.py` — trains RF / LR / SVM, saves best model
- `app.py` — Flask inference server
- `model.pkl` — trained Random Forest
- `data/` — dataset (gitignored)