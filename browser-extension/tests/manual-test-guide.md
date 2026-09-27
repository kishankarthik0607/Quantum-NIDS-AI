# Manual & Automated Testing Guide for Quantum NIDS Guard

Because Chrome Manifest V3 extensions rely on browser UI and internal APIs, use these steps to validate the security engine on a live webpage and execute automated test suites.

---

## 1. Automated Test Suite Execution

### Running JavaScript Extension Tests (Node.js Test Runner)
Run all 18 automated unit and integration tests covering domain matching, cookie monitoring, attribution manipulation detection, and security scanning:
```powershell
node --test browser-extension/tests/*.test.js
```

### Running Python Inference API Tests (Pytest)
Run the automated tests for the local ML inference backend:
```powershell
.\.venv\Scripts\python.exe -m pytest browser-extension/tests/test_api_server.py -v
```

---

## 2. Live Extension Manual Testing in Chrome

### Test 1: Detailed Security Scan
1. Navigate to a supported retail site (e.g. `https://www.amazon.com` or `https://www.ebay.com`).
2. Click the **Quantum NIDS Guard** extension icon in your browser toolbar.
3. Verify that the badge shows **MONITOR** and the site name shows the current hostname.
4. Click **Run Detailed Scan**.
5. Observe the animated progress bar tracking domain authenticity, cookie security, DOM scripts, and network telemetry.
6. The scan will produce an audit report with risk score, overall status (e.g. `SAFE`), and expandable technical details.

### Test 2: Insecure Sensitive Cookie Detection
1. On an active HTTPS tab (e.g. `https://www.amazon.com`), open Chrome DevTools (`F12`) -> **Application** -> **Cookies**.
2. Create a new cookie:
   - Name: `session_token`
   - Value: `test_token_value_123`
   - Leave the **Secure** checkbox unticked.
3. **Result:** The extension background worker instantly flags:
   `Insecure Sensitive Cookie Without Secure Flag` (Severity: HIGH).
   Open the popup to verify the finding, risk increase, and the safe redaction of the token value (`[REDACTED_SENSITIVE length=20 hash=...]`).

### Test 3: Affiliate / Referral Attribution Manipulation Detection
1. Open DevTools -> **Application** -> **Cookies**.
2. Simulate arrival through an affiliate partner:
   - Create a cookie named `tag` with value `partner_original-20`.
3. Open the popup to verify the baseline.
4. Simulate third-party script injection or coupon extension rewriting:
   - In DevTools console or cookie editor, change `tag` value to `hijacked_partner-20`.
5. **Result:** The extension records:
   `Potential Affiliate/Referral Attribution Change Detected` (Severity: MEDIUM, or HIGH if on a checkout page).
   The technical evidence displays the previous vs current masked values along with the complete 10-step investigation workflow from Phase 8.

### Test 4: Hidden Iframes and DOM Script Injection
1. On any supported site, open DevTools -> **Console**.
2. Inject a hidden iframe:
   ```javascript
   let iframe = document.createElement('iframe');
   iframe.style.display = 'none';
   iframe.src = 'https://example-tracker.com/frame';
   document.body.appendChild(iframe);
   ```
3. Run the **Detailed Scan** in the popup.
4. **Result:** The scanner flags `1 Hidden Iframe(s) Detected in DOM` (Severity: MEDIUM).

### Test 5: Form Action Hijacking (Magecart Detection)
1. In DevTools -> **Console**, simulate a hijacked payment form:
   ```javascript
   let form = document.createElement('form');
   form.action = 'https://unauthorized-attacker-drop.com/collect';
   let input = document.createElement('input');
   input.name = 'card_number';
   input.type = 'text';
   form.appendChild(input);
   document.body.appendChild(form);
   ```
2. Run **Detailed Scan** in the popup.
3. **Result:** The scanner flags `Suspicious External Form Action (Potential Formjacking / Magecart)` (Severity: CRITICAL, Status: CONFIRMED MALICIOUS).

### Test 6: Brand Lookalike and Phishing Rejection
1. Visit an unsupported domain or simulated lookalike (e.g. `https://not-amazon.com` or local test page).
2. Open the popup.
3. **Result:** The extension status correctly displays `UNSUPPORTED` or `Standard E-Commerce Protection Active` instead of falsely classifying it as an official Amazon site.

### Test 7: Restricted Protocol Graceful Handling
1. Open `chrome://extensions` or `about:blank`.
2. Open the popup.
3. **Result:** Status badge displays `RESTRICTED` with a clear explanation:
   *"Browser security policies restrict extension access on this page."*
   The extension does not crash and handles restricted contexts gracefully.
