from flask import Flask, request, render_template_string
import pickle
from features import extract_features

app = Flask(__name__)

# Load trained model
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Phishing URL Detector</title>
    <style>
        body { font-family: Arial; max-width: 600px; margin: 80px auto; text-align: center; background: #f0f0f0; }
        h1 { color: #333; }
        input { width: 80%; padding: 10px; font-size: 16px; margin: 10px; border-radius: 8px; border: 1px solid #ccc; }
        button { padding: 10px 30px; font-size: 16px; background: #4CAF50; color: white; border: none; border-radius: 8px; cursor: pointer; }
        .safe { color: green; font-size: 24px; font-weight: bold; }
        .phishing { color: red; font-size: 24px; font-weight: bold; }
    </style>
</head>
<body>
    <h1>🔐 Phishing URL Detector</h1>
    <p>Enter a URL to check if it is safe or phishing</p>
    <input type="text" id="url" placeholder="https://example.com" />
    <br>
    <button onclick="checkURL()">Check URL</button>
    <br><br>
    <div id="result"></div>
    <script>
        async function checkURL() {
            const url = document.getElementById('url').value;
            const res = await fetch('/predict?url=' + encodeURIComponent(url));
            const data = await res.json();
            const div = document.getElementById('result');
            if (data.result === 'Phishing') {
                div.innerHTML = '<p class="phishing">⚠️ PHISHING DETECTED!</p>';
            } else {
                div.innerHTML = '<p class="safe">✅ This URL looks Safe!</p>';
            }
        }
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML)

@app.route('/predict')
def predict():
    url = request.args.get('url', '')
    features = extract_features(url)
    prediction = model.predict([features])[0]
    result = 'Phishing' if prediction == 1 else 'Safe'
    return {'result': result}

if __name__ == '__main__':
    app.run(debug=True)