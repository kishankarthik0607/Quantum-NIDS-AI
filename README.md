# Quantum-NIDS-AI ◈

**Quantum NIDS AI** is an intelligent Network Intrusion Detection System (NIDS) and Browser Guard for e-commerce security, combining high-performance machine learning (Random Forest trained on CIC-IDS2017) with explainable AI (SHAP), a modern Streamlit operations dashboard, and a Manifest V3 browser security extension.

---

## 🌟 Key Architecture & Components

1. **Quantum Operations Dashboard (Web UI)**
   - Built with Streamlit, Plotly, and custom Quantum Dark Theme.
   - **6 Interactive Modules**:
     - **Overview**: System telemetry, live detection counts, and model metrics.
     - **Performance**: Confusion matrices, ROC-AUC curves, and algorithm comparisons (Random Forest, XGBoost, SVM, Logistic Regression).
     - **Live Traffic**: Real-time packet capture (Scapy) and live classification.
     - **Explainability (XAI)**: SHAP waterfall and global feature importance attribution.
     - **Analytics**: Historical traffic inspection and threat distribution.
     - **Settings**: Dynamic alert thresholds and capture parameters.
   - **Authentication**: Salted PBKDF2-SHA256 user authentication (`auth.py`).

2. **Quantum NIDS Browser Guard (Chrome MV3 Extension)**
   - Client-side security monitor for 110+ major retail and e-commerce websites.
   - **Attribution Defense**: Detects unauthorized affiliate/referral cookie manipulation during checkout and browsing.
   - **Magecart / Formjacking Detection**: Real-time inspection of unauthorized external form actions.
   - **Privacy-Preserving Telemetry**: Sensitive session credentials and tokens are strictly hashed/redacted.
   - **Detailed Security Scanner**: 19-dimensional browser security audit engine with actionable remediation workflows.

3. **Inference API Service (`api_server.py`)**
   - High-throughput FastAPI wrapper serving the pre-trained `best_model.pkl` Random Forest model (99.92% accuracy, 0.9999 ROC-AUC).

---

## 🚀 Quick Start Guide

### 1. Environment Setup
Clone the repository and activate your Python virtual environment:
```bash
git clone https://github.com/kishankarthik0607/Quantum-NIDS-AI.git
cd Quantum-NIDS-AI

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\activate   # Windows
# source .venv/bin/activate # Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

### 2. Launching the Web UI Dashboard
Start the full-featured dashboard:
```bash
python app.py
```
*Alternatively: `streamlit run dashboard.py`*
Open **http://localhost:8501**, click **Create account** to set up your administrator credentials, and log in.

### 3. Starting the ML Inference Backend (for Browser Guard)
In a separate terminal window:
```bash
python api_server.py
```
The API server starts on **http://127.0.0.1:8000** with endpoints for live feature classification.

### 4. Installing the Browser Extension in Chrome
1. Open Google Chrome and go to `chrome://extensions/`.
2. Toggle on **Developer mode** in the top right.
3. Click **Load unpacked** and select the `browser-extension` folder inside this repository.
4. Navigate to any supported retail website (e.g. `https://www.amazon.com`, `https://www.ebay.com`) and click the Quantum NIDS icon to run detailed scans.

---

## 🧪 Testing

### Automated Browser Extension Test Suite
Run the 18 automated unit and integration tests (Node.js test runner):
```bash
node --test browser-extension/tests/*.test.js
```

### Automated ML Backend Test Suite
Run the Pytest suite for the FastAPI model inference engine:
```bash
pytest browser-extension/tests/test_api_server.py -v
```

---

## 📂 Repository Structure

```
Quantum-NIDS-AI/
├── app.py                      # Root launcher for the Web UI Dashboard
├── dashboard.py                # Streamlit operations dashboard (6 pages)
├── auth.py                     # User authentication & PBKDF2 hashing
├── data_access.py              # Data and artifact retrieval gateway
├── quantum_theme.py            # Dark aesthetic UI tokens & layout
├── api_server.py               # FastAPI inference service (best_model.pkl)
├── requirements.txt            # Python dependencies
├── browser-extension/          # Quantum NIDS Browser Guard Chrome MV3 extension
│   ├── manifest.json
│   ├── background/             # Background service worker
│   ├── content/                # Content scripts (DOM & storage auditing)
│   ├── popup/                  # Popup scanner UI
│   ├── options/                # Extension settings UI
│   ├── scan/                   # 19-dimensional security audit engine
│   ├── cookies/                # Cookie & affiliate attribution monitor
│   ├── sites/                  # 110+ validated retail domain configs
│   ├── config/                 # False-positive allowlists
│   └── tests/                  # Automated & manual test suites
├── models/                     # Trained ML models (best_model.pkl, shap_explainer.pkl)
├── results/                    # Confusion matrices, ROC curves, and SHAP plots
└── src/                        # Model training, feature selection & Scapy capture
```

---

## 🔒 Security & Privacy Notice
- Quantum NIDS operates on a **Local-First** privacy architecture.
- No user credentials, session tokens, passwords, or credit card numbers are ever stored in plaintext or transmitted externally.
