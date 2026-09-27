/**
 * Quantum NIDS Browser Guard - Enhanced Content Script
 * 
 * Inspects DOM structure, script elements, iframe insertions, form action targets,
 * storage security indicators, and mixed-content resources. Supports both continuous
 * mutation observation and on-demand deep audits from the popup and background worker.
 */

// Patterns indicating suspicious script hosts
const SUSPICIOUS_SCRIPT_PATTERNS = [
    'bit.ly',
    'ngrok.io',
    'ngrok-free.app',
    'localtunnel.me',
    'pagekite.me',
    'serveo.net',
    'pastebin.com',
    'hastebin.com',
    'raw.githubusercontent.com',
    'anonfiles.com'
];

// Sensitive keywords to check in storage keys
const SENSITIVE_STORAGE_KEYS = ['card', 'cvv', 'creditcard', 'password', 'passwd', 'auth_token', 'session_secret', 'secret'];

/**
 * Performs a comprehensive audit of the active DOM and browser storage.
 */
function auditPageSecurity() {
    const findings = {
        hiddenIframes: [],
        suspiciousScripts: [],
        suspiciousForms: [],
        storageFindings: [],
        mixedContentResources: [],
        hasMetaCsp: false
    };

    try {
        const pageHost = window.location.hostname;
        const isHttps = window.location.protocol === 'https:';

        // 1. Audit Iframes (Hidden, 0-dimension, or suspicious)
        const iframes = document.querySelectorAll('iframe');
        iframes.forEach(f => {
            const style = window.getComputedStyle ? window.getComputedStyle(f) : null;
            const isHidden = (
                f.style.display === 'none' ||
                f.style.visibility === 'hidden' ||
                (style && (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0')) ||
                f.width === '0' ||
                f.height === '0' ||
                f.getAttribute('width') === '0' ||
                f.getAttribute('height') === '0'
            );

            if (isHidden) {
                findings.hiddenIframes.push({
                    src: f.src || f.getAttribute('data-src') || '[inline/blank]',
                    id: f.id || null,
                    name: f.name || null
                });
            }
        });

        // 2. Audit Script Tags
        const scripts = document.querySelectorAll('script[src]');
        scripts.forEach(s => {
            try {
                const scriptUrl = new URL(s.src, window.location.href);
                const isSuspicious = SUSPICIOUS_SCRIPT_PATTERNS.some(pat => scriptUrl.hostname.includes(pat));
                if (isSuspicious) {
                    findings.suspiciousScripts.push({
                        src: s.src,
                        hostname: scriptUrl.hostname
                    });
                }

                // Check for mixed content script
                if (isHttps && scriptUrl.protocol === 'http:') {
                    findings.mixedContentResources.push(s.src);
                }
            } catch {}
        });

        // 3. Formjacking / Magecart Checkout Form Hijack Audit
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            const action = form.action || form.getAttribute('action');
            if (action && action !== '#' && !action.startsWith('javascript:')) {
                try {
                    const actionUrl = new URL(action, window.location.href);
                    // Check if form submits to an external domain that is not a recognized payment processor or sub-domain
                    const actionHost = actionUrl.hostname;
                    const isExternal = actionHost && actionHost !== pageHost && !actionHost.endsWith('.' + pageHost);

                    // If external and this looks like a login or payment form
                    const isSensitiveForm = form.querySelector('input[type="password"], input[name*="card"], input[name*="cvv"], input[name*="payment"], input[name*="account"]');

                    if (isExternal && isSensitiveForm) {
                        findings.suspiciousForms.push({
                            action: actionUrl.href,
                            hostname: actionHost,
                            id: form.id || form.name || 'unnamed-form'
                        });
                    }
                } catch {}
            }
        });

        // 4. LocalStorage & SessionStorage Exposure Audit
        function auditStorage(storage, type) {
            try {
                if (!storage) return;
                for (let i = 0; i < storage.length; i++) {
                    const key = storage.key(i);
                    if (!key) continue;
                    const lowerKey = key.toLowerCase();
                    const matched = SENSITIVE_STORAGE_KEYS.find(k => lowerKey.includes(k));
                    if (matched) {
                        findings.storageFindings.push({
                            storageType: type,
                            key: key,
                            matchedPattern: matched
                        });
                    }
                }
            } catch {}
        }

        auditStorage(window.localStorage, 'localStorage');
        auditStorage(window.sessionStorage, 'sessionStorage');

        // 5. Meta CSP check
        const metaCsp = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
        findings.hasMetaCsp = !!metaCsp;

    } catch (e) {
        console.warn('[Quantum NIDS] Error during DOM audit:', e);
    }

    return findings;
}

// Initial analysis and reporting
function reportLiveFindings() {
    const audit = auditPageSecurity();
    const flags = [];

    if (audit.hiddenIframes.length > 0) {
        flags.push(`Hidden iframe detected: ${audit.hiddenIframes.length}`);
    }
    if (audit.suspiciousScripts.length > 0) {
        flags.push(`Suspicious script source detected: ${audit.suspiciousScripts.map(s => s.hostname).join(', ')}`);
    }
    if (audit.suspiciousForms.length > 0) {
        flags.push(`External form action detected on sensitive form: ${audit.suspiciousForms[0].hostname}`);
    }

    if (flags.length > 0) {
        chrome.runtime.sendMessage({
            type: 'PAGE_SECURITY_ALERT',
            flags,
            audit
        }).catch(() => {});
    }
}

// Observe dynamic DOM injection attacks (e.g. scripts or hidden frames injected post-load)
function setupDynamicObserver() {
    if (!window.MutationObserver) return;

    let debounceTimer = null;
    const observer = new MutationObserver((mutations) => {
        let hasRelevantAdditions = false;
        for (const m of mutations) {
            if (m.addedNodes && m.addedNodes.length > 0) {
                for (const node of m.addedNodes) {
                    if (node.nodeName === 'SCRIPT' || node.nodeName === 'IFRAME' || node.nodeName === 'FORM') {
                        hasRelevantAdditions = true;
                        break;
                    }
                }
            }
            if (hasRelevantAdditions) break;
        }

        if (hasRelevantAdditions) {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(reportLiveFindings, 1000);
        }
    });

    observer.observe(document.documentElement || document.body, {
        childList: true,
        subtree: true
    });
}

// On-demand message listener from background worker or popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'EXECUTE_DEEP_PAGE_AUDIT') {
        const audit = auditPageSecurity();
        sendResponse(audit);
        return false;
    }
});

// Run audit when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        reportLiveFindings();
        setupDynamicObserver();
    });
} else {
    reportLiveFindings();
    setupDynamicObserver();
}
