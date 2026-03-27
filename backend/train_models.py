import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
import pickle
import os
import re

# Set up paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'dataset')
MODEL_DIR = os.path.join(BASE_DIR, 'models')

# Ensure models directory exists
os.makedirs(MODEL_DIR, exist_ok=True)

def extract_url_features(url):
    """
    Extracts features from a URL for phishing detection.
    Features: length, num_dots, has_at_symbol, has_https, num_hyphens, num_digits
    """
    url_len = len(url)
    num_dots = url.count('.')
    has_at_symbol = 1 if '@' in url else 0
    has_https = 1 if 'https://' in url else 0
    num_hyphens = url.count('-')
    
    domain_part = url.split('://')[-1].split('/')[0] if '://' in url else url.split('/')[0]
    num_digits = sum(c.isdigit() for c in domain_part)
    
    return [url_len, num_dots, has_at_symbol, has_https, num_hyphens, num_digits]

def train_url_model():
    print("Training URL Model...")
    df = pd.read_csv(os.path.join(DATA_DIR, 'urls.csv'))
    
    # Feature Extraction
    features = []
    for url in df['url']:
        features.append(extract_url_features(url))
        
    X = np.array(features)
    y = df['label'].values  # 1 for phishing, 0 for safe
    
    # Train Model (Random Forest for better performance on structured features)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    
    # Save Model
    with open(os.path.join(MODEL_DIR, 'url_model.pkl'), 'wb') as f:
        pickle.dump(model, f)
    print("URL Model saved.")

def train_text_model():
    print("Training Text Model...")
    df = pd.read_csv(os.path.join(DATA_DIR, 'texts.csv'))
    
    X_raw = df['text'].values
    y = df['label'].values # 1 for phishing, 0 for safe
    
    # Vectorization
    vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
    X = vectorizer.fit_transform(X_raw)
    
    # Train Model (Logistic Regression works well for text classification)
    model = LogisticRegression(random_state=42)
    model.fit(X, y)
    
    # Save Vectorizer & Model
    with open(os.path.join(MODEL_DIR, 'vectorizer.pkl'), 'wb') as f:
        pickle.dump(vectorizer, f)
    with open(os.path.join(MODEL_DIR, 'text_model.pkl'), 'wb') as f:
        pickle.dump(model, f)
    print("Text Model saved.")

if __name__ == "__main__":
    print("Starting Training Process...")
    train_url_model()
    train_text_model()
    print("Training Complete! Models are ready to use.")
