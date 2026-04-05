from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import os
import re
import email
import base64
from email import policy

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

# -------- Helper Functions for Email Forensics --------

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2): return levenshtein_distance(s2, s1)
    if len(s2) == 0: return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def detect_domain_similarity(domain):
    known_brands = ['paypal', 'google', 'amazon', 'microsoft', 'apple', 'netflix', 'facebook', 'bankofamerica', 'chase', 'wellsfargo', 'linkedin']
    if not domain: return {"similar_to_brand": None, "distance": -1}
    base_domain = domain.split('.')[0].lower()
    
    best_match = None
    min_dist = float('inf')
    for brand in known_brands:
        if base_domain == brand:
            return {"similar_to_brand": brand, "distance": 0}
        dist = levenshtein_distance(base_domain, brand)
        if dist <= 2 and len(brand) >= 4:
            if dist < min_dist:
                min_dist = dist
                best_match = brand
                
    if best_match: return {"similar_to_brand": best_match, "distance": min_dist}
    return {"similar_to_brand": None, "distance": -1}

def check_auth_headers(msg, auth_header):
    results = {"spf": "unknown", "dkim": "missing", "dmarc": "unknown"}
    auth_lower = auth_header.lower()
    
    if 'spf=pass' in auth_lower: results['spf'] = 'pass'
    elif 'spf=fail' in auth_lower or 'spf=softfail' in auth_lower: results['spf'] = 'fail'
    elif msg.get('Received-SPF'):
        spf_hdr = str(msg.get('Received-SPF')).lower()
        if 'pass' in spf_hdr: results['spf'] = 'pass'
        elif 'fail' in spf_hdr: results['spf'] = 'fail'
        
    if 'dkim=pass' in auth_lower: results['dkim'] = 'present'
    elif msg.get('DKIM-Signature'): results['dkim'] = 'present'
    
    if 'dmarc=pass' in auth_lower: results['dmarc'] = 'aligned'
    elif 'dmarc=fail' in auth_lower: results['dmarc'] = 'misaligned'
    return results

def analyze_attachments(msg):
    flags = []
    suspicious_exts = ['.exe', '.js', '.scr', '.vbs', '.bat', '.cmd', '.jar', '.sh']
    safe_mimes = {'.pdf': 'application/pdf', '.docx': 'application/vnd.openxmlformats', '.xlsx': 'application/vnd.openxmlformats', '.jpg': 'image/jpeg', '.png': 'image/png'}
    
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart': continue
        filename = part.get_filename()
        if not filename: continue
            
        filename_lower = filename.lower()
        content_type = part.get_content_type().lower()
        
        if any(filename_lower.endswith(ext) for ext in suspicious_exts):
            flags.append(f"Suspicious attachment type: {filename}")
            
        ext = os.path.splitext(filename_lower)[1]
        if ext in safe_mimes and safe_mimes[ext] not in content_type and content_type != 'application/octet-stream':
            flags.append(f"MIME type mismatch for {filename} (Ext: {ext}, MIME: {content_type})")
                
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            if payload.startswith(b'MZ'): flags.append(f"Hidden executable detected in {filename}")

    return flags

def analyze_html(html_content):
    flags = []
    html_lower = html_content.lower()
    if 'window.location' in html_lower or 'meta http-equiv="refresh"' in html_lower:
        flags.append("JavaScript redirect detected in body")
    if '<iframe' in html_lower:
        flags.append("Hidden <iframe> detected in body")
    if re.search(r'<a href="[^"]+">[^<]+\.pdf<\/a>', html_lower):
        flags.append("Fake PDF link masquerading as document")
    return flags

# ------------------------------------------------------

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

@app.route('/analyze-email', methods=['POST'])
def analyze_email():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
        
    if not file.filename.endswith('.eml'):
        return jsonify({"error": "Invalid file type. Please upload a .eml file"}), 400
        
    try:
        # Parse the email
        msg = email.message_from_bytes(file.read(), policy=policy.default)
        
        headers = {
            "from": msg.get('From', 'Unknown'),
            "to": msg.get('To', 'Unknown'),
            "subject": msg.get('Subject', 'No Subject'),
            "return_path": msg.get('Return-Path', 'Unknown')
        }
        
        reasons = []
        risk_score = 0
        
        # Helper inner function to extract domain
        def get_domain(email_str):
            if not email_str or email_str == 'unknown': return ''
            return email_str.split('@')[-1] if '@' in email_str else ''

        from_header = str(headers['from']).lower()
        return_path = str(headers['return_path']).lower()
        subject_lower = str(headers['subject']).lower()
        
        from_emails = re.findall(r'<([^>]+)>', from_header) or re.findall(r'[\w\.-]+@[\w\.-]+', from_header)
        return_emails = re.findall(r'<([^>]+)>', return_path) or re.findall(r'[\w\.-]+@[\w\.-]+', return_path)
        
        from_email = from_emails[0] if from_emails else from_header
        return_email = return_emails[0] if return_emails else return_path
        
        from_domain = get_domain(from_email)
        return_domain = get_domain(return_email)
        reply_to_header = str(msg.get('Reply-To', '')).lower()
        reply_emails = re.findall(r'<([^>]+)>', reply_to_header) or re.findall(r'[\w\.-]+@[\w\.-]+', reply_to_header)
        reply_email = reply_emails[0] if reply_emails else reply_to_header
        
        flags = []
        positive_signals = 0
        negative_signals = 0
        
        # 1. Authentication Checks
        auth_header = str(msg.get('Authentication-Results', '')).lower()
        security_checks = check_auth_headers(msg, auth_header)
        
        if security_checks['spf'] == 'pass':
            risk_score -= 30
            positive_signals += 1
        else:
            flags.append(f"SPF check {security_checks['spf']}")
            
        if security_checks['dkim'] == 'present':
            risk_score -= 30
            positive_signals += 1
        else:
            flags.append("DKIM signature missing")
            
        if security_checks['dmarc'] == 'aligned':
            risk_score -= 30
            positive_signals += 1
        else:
            flags.append(f"DMARC {security_checks['dmarc']}")

        # 2. Known Email Service Provider
        known_providers = ['sendgrid.net', 'mailgun.org', 'amazonses.com', 'google.com', 'outlook.com', 'zohomail.com', 'mandrillapp.com', 'hubspot.com', 'microsoft']
        received_str = str(msg.get_all('Received', [])).lower()
        if any(p in return_path or p in received_str for p in known_providers):
            risk_score -= 20
            positive_signals += 1
            
        # 3. Header & Domain Mismatch
        domain_match = False
        if from_domain and return_domain:
            if from_domain.endswith(return_domain) or return_domain.endswith(from_domain):
                domain_match = True
        
        if not domain_match and from_email != return_email and from_email != 'unknown' and return_email != 'unknown':
            if from_domain != return_domain and from_domain and return_domain:
                risk_score += 20
                negative_signals += 1
                flags.append("Domain mismatch between From and Return-Path.")
            else:
                risk_score += 10
                negative_signals += 1
                flags.append("Header mismatch between From and Return-Path addresses.")
                
        # 3.1. Reply-To vs From Check
        if reply_email and reply_email != 'unknown' and str(headers['from']).lower() != 'unknown':
            if reply_email != from_email:
                risk_score += 20
                negative_signals += 1
                flags.append("Reply-To mismatch (directed to different address).")
            
        # 3.2. Domain Similarity Detection
        domain_analysis = detect_domain_similarity(from_domain)
        if domain_analysis['similar_to_brand']:
            risk_score += 40
            negative_signals += 1
            flags.append(f"Domain visually similar to known brand ({domain_analysis['similar_to_brand']}).")
                
        # 4. Suspicious links, attachments, & HTML body
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() in ['text/plain', 'text/html']:
                    try: 
                        p = part.get_payload(decode=True)
                        if isinstance(p, bytes): body += p.decode(errors='ignore')
                        elif isinstance(p, str): body += p
                    except: pass
        else:
            try: 
                p = msg.get_payload(decode=True)
                if isinstance(p, bytes): body = p.decode(errors='ignore')
                elif isinstance(p, str): body = p
            except: pass
            
        body_lower = body.lower()
        suspicious_links = [r'http\:\/\/\d+\.\d+\.\d+\.\d+', r'bit\.ly', r'tinyurl\.com', r'ngrok\.io']
        if any(re.search(p, body_lower) for p in suspicious_links):
            risk_score += 40
            negative_signals += 1
            flags.append("Email body contains suspicious or unknown links.")
            
        attachment_flags = analyze_attachments(msg)
        if attachment_flags:
            risk_score += sum([20 for _ in attachment_flags]) # penalty per attachment issue
            negative_signals += 1
            flags.extend(attachment_flags)
            
        html_flags = analyze_html(body)
        if html_flags:
            risk_score += sum([30 for _ in html_flags])
            negative_signals += 1
            flags.extend(html_flags)
            
        # 5. Urgency / phishing language
        suspicious_keywords = ['urgent', 'verify now', 'verify', 'account', 'suspended', 'password', 'click', 'claim', 'prize', 'gift', 'invoice', 'action required']
        if any(kw in subject_lower for kw in suspicious_keywords) or any(kw in body_lower for kw in suspicious_keywords):
            risk_score += 30
            negative_signals += 1
            flags.append("Contains phishing keywords (urgent, verify now, etc.).")

        # 6. Final Classification Mapping
        if risk_score <= 0:
            result = "SAFE"
            risk_level = "LOW"
        elif risk_score <= 40:
            result = "LOW RISK"
            risk_level = "MEDIUM"
        elif risk_score <= 70:
            result = "SUSPICIOUS"
            risk_level = "HIGH"
        else:
            result = "MALICIOUS"
            risk_level = "HIGH"
            
        # 7. Confidence Score
        if positive_signals > 0 and negative_signals > 0:
            base_conf = 55.0
            confidence = base_conf + min(15.0, abs(risk_score) * 0.2)
        else:
            base_conf = 85.0
            confidence = base_conf + min(14.9, abs(risk_score) * 0.2)
            
        confidence = round(confidence, 2)
        if not flags: flags.append("No specific high or low risk indicators found.")
        
        return jsonify({
            "result": result,
            "risk_level": risk_level,
            "confidence": confidence,
            "headers": headers,
            "security_checks": security_checks,
            "domain_analysis": domain_analysis,
            "flags": flags,
            "reasons": flags # Keep legacy field strictly so JS keeps working before the patch
        })
        
    except Exception as e:
        return jsonify({"error": f"Failed to parse email: {str(e)}"}), 500

if __name__ == '__main__':
    # Load Models before starting
    print("Loading models...")
    load_models()
    print("Models loaded successfully.")
    # Run the server on port 5000
    app.run(debug=True, port=5000)
