import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import pickle
from features import extract_features

# Sample dataset (url, label) - 0 = safe, 1 = phishing
data = [
    ("https://www.google.com", 0),
    ("https://www.facebook.com", 0),
    ("https://www.github.com", 0),
    ("https://www.amazon.com", 0),
    ("https://www.microsoft.com", 0),
    ("https://www.youtube.com", 0),
    ("https://www.linkedin.com", 0),
    ("https://www.twitter.com", 0),
    ("http://free-login-verify.com/bank/account", 1),
    ("http://192.168.1.1/update/verify", 1),
    ("http://secure-account-login.tk/free", 1),
    ("http://verify-bank-update.ml/lucky", 1),
    ("http://login-free-account.ga/secure", 1),
    ("http://update-verify-login.cf/bank", 1),
    ("http://192.168.0.1/account/login", 1),
    ("http://lucky-free-verify.gq/update", 1),
]

# Extract features
X = [extract_features(url) for url, label in data]
y = [label for url, label in data]

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Accuracy
y_pred = model.predict(X_test)
print(f"✅ Model Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")

# Save model
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ Model saved as model.pkl")