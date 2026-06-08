import time
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score, roc_auc_score

from features import extract_features, FEATURE_NAMES


DATA_PATH = "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"
RANDOM_STATE = 42


def load_and_featurize():
    print(f"Loading {DATA_PATH}...")
    df = pd.read_csv(DATA_PATH)
    print(f"  rows: {len(df):,}")

    # PhiUSIIL: 1 = legitimate, 0 = phishing.
    # Flip to our convention: 1 = phishing, 0 = safe.
    y = (1 - df["label"]).to_numpy()

    print("Extracting features...")
    t0 = time.time()
    urls = df["URL"].tolist()
    X = np.empty((len(urls), len(FEATURE_NAMES)), dtype=np.float64)
    for i, u in enumerate(urls):
        X[i] = extract_features(u)
        if (i + 1) % 25000 == 0:
            print(f"  {i + 1:,}/{len(urls):,}")
    print(f"  done in {time.time() - t0:.1f}s")
    print(f"  X shape: {X.shape}  |  phishing: {int(y.sum()):,}  safe: {int((y == 0).sum()):,}")
    return X, y


def evaluate(name, model, X_test, y_test):
    y_pred = model.predict(X_test)
    f1_phish = f1_score(y_test, y_pred, pos_label=1)
    try:
        scores = model.predict_proba(X_test)[:, 1]
    except AttributeError:
        scores = model.decision_function(X_test)
    auc = roc_auc_score(y_test, scores)
    print(f"\n=== {name} ===")
    print(classification_report(y_test, y_pred, target_names=["safe", "phishing"], digits=4))
    print(f"  ROC-AUC: {auc:.4f}   phishing F1: {f1_phish:.4f}")
    return {"name": name, "f1_phish": f1_phish, "auc": auc, "model": model}


def main():
    X, y = load_and_featurize()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )
    print(f"\nTrain: {X_train.shape}   Test: {X_test.shape}")

    models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=200, n_jobs=-1, random_state=RANDOM_STATE
        ),
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=1000, n_jobs=-1, random_state=RANDOM_STATE)),
        ]),
        "Linear SVM": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LinearSVC(random_state=RANDOM_STATE, dual="auto")),
        ]),
    }

    results = []
    for name, model in models.items():
        print(f"\nTraining {name}...")
        t0 = time.time()
        model.fit(X_train, y_train)
        print(f"  trained in {time.time() - t0:.1f}s")
        results.append(evaluate(name, model, X_test, y_test))

    best = max(results, key=lambda r: r["f1_phish"])
    print(f"\n>>> Best model: {best['name']}   F1={best['f1_phish']:.4f}   AUC={best['auc']:.4f}")

    with open("model.pkl", "wb") as f:
        pickle.dump(best["model"], f)
    print("Saved best model -> model.pkl")


if __name__ == "__main__":
    main()