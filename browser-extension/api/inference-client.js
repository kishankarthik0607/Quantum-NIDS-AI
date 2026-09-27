/**
 * Quantum NIDS Browser Guard - Inference Client
 * 
 * Communicates with the local or configured FastAPI Quantum NIDS ML server.
 * Reads custom endpoints from chrome.storage.local with graceful offline fallback.
 */

const DEFAULT_API_URL = "http://127.0.0.1:8000/api/v1/predict";

/**
 * Retrieves the currently configured API URL from chrome.storage.local.
 */
async function getApiUrl() {
    try {
        if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
            const data = await chrome.storage.local.get(['apiUrl']);
            if (data.apiUrl && data.apiUrl.trim()) {
                return data.apiUrl.trim();
            }
        }
    } catch {}
    return DEFAULT_API_URL;
}

/**
 * Sends a feature vector to the Quantum NIDS ML inference engine.
 * 
 * @param {object} features - Key-value pair of flow/HTTP proxy features
 * @returns {object|null} Model prediction result or null if offline/error
 */
export async function checkNIDS(features) {
    try {
        const apiUrl = await getApiUrl();
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2500);

        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ features }),
            signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (!response.ok) {
            console.warn("[Quantum NIDS] Backend HTTP error:", response.status, response.statusText);
            return null;
        }

        return await response.json();
    } catch (e) {
        // Backend offline or unreachable - extension fails gracefully
        return null;
    }
}

/**
 * Quick health check for the backend API.
 */
export async function checkBackendHealth() {
    try {
        const apiUrl = await getApiUrl();
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 1500);

        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ features: {} }),
            signal: controller.signal
        });
        clearTimeout(timeoutId);

        return response.ok;
    } catch {
        return false;
    }
}
