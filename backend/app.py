from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import os
import re

app = Flask(__name__)
# Enable CORS for all routes, allowing frontend and extension to connect
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, 'models')

# Load models and vectorizer globally
url_model = None
text_model = None
vectorizer = None

def load_models():
    global url_model, text_model, vectorizer
    
    url_model_path = os.path.join(MODEL_DIR, 'url_model.pkl')
    text_model_path = os.path.join(MODEL_DIR, 'text_model.pkl')
    vectorizer_path = os.path.join(MODEL_DIR, 'vectorizer.pkl')
    
    if os.path.exists(url_model_path):
        with open(url_model_path, 'rb') as f:
            url_model = pickle.load(f)
            
    if os.path.exists(text_model_path) and os.path.exists(vectorizer_path):
        with open(text_model_path, 'rb') as f:
            text_model = pickle.load(f)
        with open(vectorizer_path, 'rb') as f:
            vectorizer = pickle.load(f)

# Helper function to extract URL features (Must match the one in train_models.py)
def extract_url_features(url):
    url_len = len(url)
    num_dots = url.count('.')
    has_at_symbol = 1 if '@' in url else 0
    has_https = 1 if 'https://' in url else 0
    num_hyphens = url.count('-')
    
    domain_part = url.split('://')[-1].split('/')[0] if '://' in url else url.split('/')[0]
    num_digits = sum(c.isdigit() for c in domain_part)
    
    return [url_len, num_dots, has_at_symbol, has_https, num_hyphens, num_digits]

@app.route('/', methods=['GET'])
def home():
    return "Phishing Detection API Running!"

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({"status": "API is running", "models_loaded": url_model is not None and text_model is not None})

@app.route('/check-url', methods=['POST'])
def check_url():
    if not url_model:
        return jsonify({"error": "URL model not found. Train models first."}), 500
        
    data = request.json
    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400
        
    url = data['url']
    features = extract_url_features(url)
    
    # Predict (Random Forest)
    prediction = url_model.predict([features])[0]
    probabilities = url_model.predict_proba([features])[0]
    
    # 1 is phishing, 0 is safe
    result = "Safety Alert: Suspicious URL Detected" if prediction == 1 else "Safe URL"
    confidence = round(max(probabilities) * 100, 2)
    
    # Generate simple explanation
    reasons = []
    if features[2] == 1: reasons.append("URL contains '@' symbol.")
    if features[3] == 0: reasons.append("Does not use secure HTTPS protocol.")
    if features[4] > 2: reasons.append("Too many hyphens, indicating likely spoofing.")
    if features[1] > 3: reasons.append("Too many subdomains (dots).")
    if features[5] > 0: reasons.append("Contains numbers in the domain, a common typosquatting tactic.")
    
    explanation = " ".join(reasons) if reasons else "No obvious anomalies detected based on rules."
    if prediction == 0:
        explanation = "The URL syntax looks normal and matches standard safe patterns."

    return jsonify({
        "url": url,
        "is_phishing": bool(prediction == 1),
        "result": result,
        "confidence": f"{confidence}%",
        "explanation": explanation
    })

@app.route('/check-text', methods=['POST'])
def check_text():
    if not text_model or not vectorizer:
        return jsonify({"error": "Text model not found. Train models first."}), 500
        
    data = request.json
    if not data or 'text' not in data:
        return jsonify({"error": "No text provided"}), 400
        
    text = data['text']
    
    # Transform and predict
    features = vectorizer.transform([text])
    prediction = text_model.predict(features)[0]
    probabilities = text_model.predict_proba(features)[0]
    
    result = "Phishing/Spam Message Detected" if prediction == 1 else "Safe Message"
    confidence = round(max(probabilities) * 100, 2)
    
    # Generate basic explanation
    suspicious_keywords = ['urgent', 'verify', 'account', 'suspended', 'password', 'click', 'claim', 'prize', 'gift']
    found_keywords = [word for word in suspicious_keywords if word in text.lower()]
    
    explanation = ""
    if prediction == 1:
        if found_keywords:
            explanation = f"We detected suspicious keywords often used in phishing: {', '.join(found_keywords)}."
        else:
            explanation = "The writing style and terminology matches common phishing or spam patterns."
    else:
        explanation = "The text appears organic and free of common manipulative phrasing."

    return jsonify({
        "text": text,
        "is_phishing": bool(prediction == 1),
        "result": result,
        "confidence": f"{confidence}%",
        "explanation": explanation,
        "found_keywords": found_keywords
    })

if __name__ == '__main__':
    # Load Models before starting
    print("Loading models...")
    load_models()
    print("Models loaded successfully.")
    # Run the server on port 5000
    app.run(debug=True, port=5000)
