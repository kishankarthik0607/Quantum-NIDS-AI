document.addEventListener('DOMContentLoaded', () => {
    const apiUrlInput = document.getElementById('api-url');
    const riskThresholdInput = document.getElementById('risk-threshold');
    const statusEl = document.getElementById('status');
    const saveBtn = document.getElementById('save-btn');
    const testBtn = document.getElementById('test-btn');

    // Load current settings
    chrome.storage.local.get(['apiUrl', 'riskThreshold'], (result) => {
        if (result.apiUrl) {
            apiUrlInput.value = result.apiUrl;
        }
        if (result.riskThreshold !== undefined) {
            riskThresholdInput.value = result.riskThreshold;
        }
    });

    // Save settings
    saveBtn.addEventListener('click', () => {
        let apiUrl = apiUrlInput.value.trim();
        let riskThreshold = parseInt(riskThresholdInput.value, 10);

        if (isNaN(riskThreshold) || riskThreshold < 1 || riskThreshold > 100) {
            riskThreshold = 50;
            riskThresholdInput.value = 50;
        }

        if (!apiUrl.startsWith('http://') && !apiUrl.startsWith('https://')) {
            showStatus('API URL must start with http:// or https://', '#d32f2f');
            return;
        }

        chrome.storage.local.set({ apiUrl, riskThreshold }, () => {
            showStatus('Settings saved successfully!', '#2e7d32');
        });
    });

    // Test connection
    testBtn.addEventListener('click', async () => {
        const apiUrl = apiUrlInput.value.trim();
        showStatus('Testing connection...', '#1976d2');
        testBtn.disabled = true;

        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000);

            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ features: {} }),
                signal: controller.signal
            });
            clearTimeout(timeoutId);

            if (response.ok) {
                showStatus('Connection successful! Backend is online.', '#2e7d32');
            } else {
                showStatus(`Connected with error status: ${response.status}`, '#f57c00');
            }
        } catch (e) {
            showStatus('Connection failed: Backend unreachable or offline.', '#d32f2f');
        } finally {
            testBtn.disabled = false;
        }
    });

    function showStatus(msg, color) {
        statusEl.textContent = msg;
        statusEl.style.color = color;
        setTimeout(() => {
            if (statusEl.textContent === msg) {
                statusEl.textContent = '';
            }
        }, 3500);
    }
});
