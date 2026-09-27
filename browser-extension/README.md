# Quantum NIDS Browser Guard

A Chrome Manifest V3 extension that monitors browser-visible security indicators for e-commerce and retail websites, backed by the Quantum NIDS AI model.

## 1. Project Architecture

The system consists of two parts:
1. **The Extension**: A local-first, privacy-focused Chrome Extension that monitors cookies, requests, and page structure.
2. **The Inference API**: A lightweight FastAPI wrapper (`api_server.py`) around your existing `best_model.pkl` Random Forest classifier. The API synthesizes proxy features from the browser events to match the 30-feature vector expected by your model.

### Data Flow:
`Browser Event` -> `Extension (Service Worker)` -> `POST /api/v1/predict` -> `API Server` -> `Random Forest Model` -> `Risk Score` -> `Popup UI`

## 2. Privacy Considerations

- **Local First**: The extension defaults to querying `http://127.0.0.1:8000`. No user data is sent to external servers by default.
- **Minimal Collection**: The extension ONLY extracts hostnames, cookie metadata (Secure/HttpOnly flags, names), and request counts. It **DOES NOT** collect cookie values, passwords, payment info, or private messages.
- **Rule-based & ML Hybrid**: The Risk Engine uses both deterministic browser rules (e.g., hidden iframes) and the Quantum NIDS ML predictions to form a composite Risk Score.

## 3. How to Start the ML Backend

1. Open your terminal in the `QUANTUM_NIDS_AI` root directory.
2. Activate your virtual environment: `.\.venv\Scripts\activate` (Windows)
3. Install dependencies: `pip install fastapi uvicorn pydantic pandas joblib scikit-learn`
4. Run the API: `python api_server.py`
5. The API will be available at `http://127.0.0.1:8000`

## 4. How to Load the Extension in Chrome

1. Open Google Chrome.
2. Navigate to `chrome://extensions/`.
3. Enable **Developer mode** in the top right corner.
4. Click **Load unpacked** in the top left.
5. Select the `browser-extension` folder inside `QUANTUM_NIDS_AI`.

## 5. How to Test It

1. Start the API backend.
2. Open Chrome and go to a supported site like `amazon.com` or `ebay.com`.
3. Click the extension icon. It should display "MONITOR" on the badge and "SAFE" in the popup.
4. **Test Cookie Anomaly**: Open Chrome DevTools (`F12`) -> Application -> Cookies. Create a new cookie named `session` and uncheck the `Secure` flag. 
5. The extension will instantly flag it as an "Insecure session cookie detected" and increase the risk score.
6. **Test ML Inference**: The extension background script continuously monitors network requests and pings the API. If the ML predicts an attack, it will trigger an `ML Engine alert`.

## 6. How to Add New Supported Websites

Edit `browser-extension/sites/supported-sites.js` and add a new domain entry to the `SUPPORTED_SITES` array.

## 7. Known Limitations

- **Browser Context**: The ML model was trained on low-level PCAP networking features (TCP window sizes, PSH flags). The browser extension operates at Layer 7 (HTTP) and cannot observe raw TCP packets. The API backend maps HTTP metrics (like request size) to the closest flow features, and pads unobservable features with `0.0`. For true flow-level inference, `realtime_detection.py` must run as a system daemon alongside the extension.
- **Server-Side Hacks**: This extension detects client-side anomalies (rogue scripts, session hijacking). It cannot guarantee a server is safe.

## 8. Required Chrome Permissions

- `cookies`: To detect session tampering.
- `webRequest`: To detect malicious third-party requests.
- `storage`: For storing configuration.
- `scripting`: To analyze the DOM for phishing indicators.
- `host_permissions: <all_urls>`: Required to intercept requests on supported dynamic retail sites.
