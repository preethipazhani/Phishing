# 🛡️ PhishGuard locally deployable Web Application

Welcome to PhishGuard! This is a complete, beginner-friendly yet advanced-looking phishing detection application. It uses Machine Learning (Scikit-Learn/Random Forest/Logistic Regression) to classify malicious URLs and deceitful messages (emails, SMS) in real-time.

## 📁 Project Structure

```
phishing_detector/
├── backend/                  # Flask backend and Machine Learning
│   ├── app.py                # Main API Server
│   ├── train_models.py       # ML Model generator
│   ├── requirements.txt      # Python dependencies
│   ├── dataset/              # Dummy datasets for URLs and Texts
│   └── models/               # Auto-generated .pkl model files
├── frontend/                 # Beautiful UI Interface
│   ├── index.html            # Main webpage
│   ├── style.css             # Modern dark-theme styling
│   └── script.js             # API connection logic
├── extension/                # Chrome Extension MVP
│   ├── manifest.json         # Extension config
│   ├── popup.html            # Extension ui
│   ├── popup.js              # Reads active tab and sends to API
│   └── background.js         # Service worker
└── README.md                 # Project Setup Instructions
```

---

## 🚀 Setup & Installation Guide

Follow these steps carefully to run the deep ML protection system locally.

### Step 1: Install Python Dependencies
Open your terminal (Command Prompt / PowerShell) and navigate to the `backend` folder:
```bash
cd backend
pip install -r requirements.txt
```

### Step 2: Train Machine Learning Models
Generate the `.pkl` files by running the trainer script. It will read the dummy datasets and output lightweight Random Forest / Logistic Regression models.
```bash
python train_models.py
```
*You should see "Training Complete! Models are ready to use."*

### Step 3: Start the Backend API Server
Keep this terminal open, and run the backend Flask server.
```bash
python app.py
```
*The server will start running on `http://127.0.0.1:5000`.*

---

## 🌐 Running the Web Interface

1. Open the `frontend` directory in your file explorer.
2. Simply **Double-click `index.html`** to open it in any web browser.
3. Test it out!
   * Enter a fake url like: `http://verify-your-bank-account.xyz`
   * Enter fake text like: `Urgent: Your bank account has been compromised. Verify your details here immediately.`

---

## 🧩 Installing the Chrome Extension

1. Open Google Chrome.
2. In the URL bar, go to: `chrome://extensions/`
3. Toggle the **Developer mode** switch in the top right corner.
4. Click **Load unpacked** in the top left.
5. Select the `extension` folder located inside `phishing_detector`.
6. Use it! Browse to any potentially harmful site and click the extension icon to run a scan.

---

## 🧪 Sample Test Inputs

### Phishing Examples:
- **URL**: `http://netflix-billing-issue-resolve.com`
- **Text**: `URGENT: Verify your Apple ID within 24 hours or it will be permanently locked.`

### Safe Examples:
- **URL**: `https://www.google.com`
- **Text**: `Hey, are we still meeting for lunch tomorrow?`

---

## 📈 How to Improve Accuracy (For your College Project)

1. **Better Datasets**: Replace the dummy CSV files inside `backend/dataset/` with larger public datasets. You can find excellent real-world data at:
   * [Kaggle - Malicious URLs Dataset](https://www.kaggle.com/datasets/pavanraj159/malicious-url-dataset)
   * [Kaggle - SMS Spam Collection](https://www.kaggle.com/datasets/uciml/sms-spam-collection-dataset)
2. **Deep Learning**: For a more advanced version, replace `scikit-learn` in `train_models.py` with `tensorflow` to use LSTM/RNN models for the text detection.
3. **Third-Party APIs**: Check real-time blacklists by integrating the [Google Safe Browsing API](https://developers.google.com/safe-browsing) or [VirusTotal API](https://www.virustotal.com/gui/home/upload) into `app.py`.

Good luck with your project! 🚀
