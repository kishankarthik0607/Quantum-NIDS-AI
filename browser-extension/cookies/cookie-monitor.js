/**
 * Quantum NIDS Browser Guard - Cookie & Affiliate Attribution Monitoring Engine
 * 
 * Provides robust monitoring of cookie creation, mutation, deletion, security flags,
 * and detects suspicious affiliate/referral attribution manipulation without exposing
 * sensitive credentials or session tokens.
 */

import { isSensitiveCookieName, isAttributionCookieName } from '../config/allowlists.js';

/**
 * Creates a safe, non-reversible redacted hash representation of a cookie value.
 * Sensitive tokens, passwords, and credentials are NEVER stored or displayed in plaintext.
 */
export function safeRedactedValue(cookieName, value) {
    if (!value) return '[Empty]';
    
    // Always hash/redact if sensitive
    const isSensitive = isSensitiveCookieName(cookieName);
    
    // Simple deterministic non-cryptographic fast hash for safe comparison and telemetry
    let hash = 0;
    for (let i = 0; i < value.length; i++) {
        const char = value.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash |= 0; // Convert to 32bit integer
    }
    const hashHex = (hash >>> 0).toString(16).padStart(8, '0');

    if (isSensitive) {
        return `[REDACTED_SENSITIVE length=${value.length} hash=${hashHex}]`;
    }

    // For non-sensitive tracking/attribution values, show a safe sanitized preview
    if (value.length <= 16 && /^[a-zA-Z0-9_\-.:=]+$/.test(value)) {
        return value;
    }

    const prefix = value.slice(0, 4).replace(/[^a-zA-Z0-9]/g, '*');
    return `${prefix}... [length=${value.length} hash=${hashHex}]`;
}

/**
 * Cookie Monitoring State Manager
 */
export class CookieMonitor {
    constructor() {
        // Tab-specific attribution and cookie state: tabId -> { domain, cookies: Map, attributionHistory: [] }
        this.tabStates = new Map();
        // Global domain attribution state to track cross-tab session attribution
        this.domainAttribution = new Map();
    }

    /**
     * Initializes or updates tracking for a tab.
     */
    initTab(tabId, domain, url) {
        if (!this.tabStates.has(tabId)) {
            this.tabStates.set(tabId, {
                domain,
                currentUrl: url,
                cookies: new Map(),
                events: [],
                recentMutations: [],
                attributionHistory: []
            });
        } else {
            const state = this.tabStates.get(tabId);
            state.domain = domain;
            state.currentUrl = url;
        }
    }

    /**
     * Cleans up state when a tab is closed.
     */
    removeTab(tabId) {
        this.tabStates.delete(tabId);
    }

    /**
     * Analyzes a cookie event from chrome.cookies.onChanged.
     * Returns an array of detected security findings/anomalies (if any).
     */
    analyzeCookieChange(changeInfo, tabId, tabUrl) {
        const findings = [];
        const { removed, cause, cookie } = changeInfo;
        const cookieName = cookie.name;
        const now = new Date();
        const timestamp = now.toLocaleTimeString();
        const isoTimestamp = now.toISOString();

        const isSensitive = isSensitiveCookieName(cookieName);
        const isAttribution = isAttributionCookieName(cookieName);
        const safeVal = safeRedactedValue(cookieName, cookie.value);

        const tabState = tabId ? this.tabStates.get(tabId) : null;
        const currentUrl = tabUrl || (tabState ? tabState.currentUrl : `https://${cookie.domain.replace(/^\./, '')}`);
        const isCheckout = /checkout|cart|payment|order|billing|buy|purchase|spc/i.test(currentUrl);

        // 1. Rate-limiting & thrashing check (DoS / cookie-stuffing loop detection)
        if (tabState) {
            const tenSecondsAgo = Date.now() - 10000;
            tabState.recentMutations = tabState.recentMutations.filter(t => t > tenSecondsAgo);
            tabState.recentMutations.push(Date.now());
            
            if (tabState.recentMutations.length > 25) {
                findings.push({
                    id: `cookie-thrash-${Date.now()}`,
                    severity: 'MEDIUM',
                    title: 'Excessive Cookie Mutation Burst Detected',
                    status: 'SUSPICIOUS',
                    confidence: 'HIGH',
                    detectedAt: timestamp,
                    timestamp: isoTimestamp,
                    affectedWebsite: cookie.domain,
                    affectedResource: `Cookie: ${cookieName}`,
                    technicalEvidence: `Observed ${tabState.recentMutations.length} cookie changes within a 10-second window (cause: ${cause}).`,
                    whyItMatters: 'Rapid cookie thrashing can indicate client-side loop errors, aggressive tracking beacons, or brute-force session manipulation.',
                    recommendedActions: [
                        'Inspect active background scripts and network tabs in DevTools.',
                        'Verify if third-party extensions are rapidly rewriting storage.',
                        'Reload the page in an incognito window to verify if the thrashing ceases.'
                    ],
                    investigationSteps: [
                        'Review Network and Application > Cookies tabs in DevTools.',
                        'Identify which script initiated the cookie writes via the Stack Trace.',
                        'Check for conflicting tracking scripts attempting to synchronize state.'
                    ]
                });
            }
        }

        // 2. Insecure Session / Auth Cookie on HTTPS
        if (!removed && isSensitive && !cookie.secure && currentUrl.startsWith('https:')) {
            findings.push({
                id: `insecure-session-${cookieName}-${Date.now()}`,
                severity: 'HIGH',
                title: 'Insecure Sensitive Cookie Without Secure Flag',
                status: 'HIGH-RISK',
                confidence: 'HIGH',
                detectedAt: timestamp,
                timestamp: isoTimestamp,
                affectedWebsite: cookie.domain,
                affectedResource: `Cookie: ${cookieName}`,
                technicalEvidence: `Sensitive cookie "${cookieName}" was set without the "Secure" attribute on an HTTPS domain (${cookie.domain}). Value: ${safeVal}.`,
                whyItMatters: 'Cookies lacking the Secure flag can be transmitted in plaintext if any unencrypted HTTP requests are made, exposing session credentials to network eavesdropping.',
                recommendedActions: [
                    'Ensure all connections to this domain use HTTPS exclusively.',
                    'Clear browser cookies for this domain to force secure reissue.',
                    'Avoid entering authentication or payment information until verified.'
                ],
                investigationSteps: [
                    'Open Chrome DevTools > Application > Cookies.',
                    'Inspect the flags for the flagged cookie and confirm the Secure checkbox is missing.',
                    'Check whether an unencrypted HTTP asset or redirect initiated the cookie write.'
                ]
            });
        }

        // 3. Sensitive Cookie missing HttpOnly where accessible
        if (!removed && isSensitive && !cookie.httpOnly && /session|auth|token|jwt|sid/i.test(cookieName)) {
            findings.push({
                id: `httponly-missing-${cookieName}-${Date.now()}`,
                severity: 'MEDIUM',
                title: 'Sensitive Session Identifier Lacking HttpOnly Protection',
                status: 'SUSPICIOUS',
                confidence: 'MEDIUM',
                detectedAt: timestamp,
                timestamp: isoTimestamp,
                affectedWebsite: cookie.domain,
                affectedResource: `Cookie: ${cookieName}`,
                technicalEvidence: `Authentication/Session identifier "${cookieName}" is accessible to client-side JavaScript (HttpOnly=false). Value: ${safeVal}.`,
                whyItMatters: 'Without the HttpOnly attribute, any Cross-Site Scripting (XSS) vulnerability on the website can directly exfiltrate this session token.',
                recommendedActions: [
                    'Ensure trusted extensions only are active in this browsing profile.',
                    'Do not click untrusted links leading into this authenticated session.'
                ],
                investigationSteps: [
                    'Verify if the cookie is legitimately accessed by client-side SPAs or should be protected.',
                    'Inspect if any third-party scripts have DOM read access to document.cookie.'
                ]
            });
        }

        // 4. Affiliate / Referral Attribution Manipulation Detection
        if (isAttribution) {
            const domainKey = cookie.domain.replace(/^\./, '').toLowerCase();
            const existingAttr = this.domainAttribution.get(`${domainKey}:${cookieName}`);

            if (removed) {
                // Attribution deleted
                if (existingAttr && isCheckout) {
                    findings.push({
                        id: `attr-removed-${cookieName}-${Date.now()}`,
                        severity: 'HIGH',
                        title: 'Attribution Identifier Removed During Checkout',
                        status: 'HIGH-RISK',
                        confidence: 'HIGH',
                        detectedAt: timestamp,
                        timestamp: isoTimestamp,
                        affectedWebsite: cookie.domain,
                        affectedResource: `Attribution Cookie: ${cookieName}`,
                        technicalEvidence: `Established attribution cookie "${cookieName}" was deleted while browsing checkout page: ${currentUrl}.`,
                        whyItMatters: 'Deleting referral cookies during checkout can strip legitimate affiliate attribution or signal unauthorized coupon extension interference.',
                        recommendedActions: [
                            'Temporarily disable third-party coupon or shopping assistant extensions.',
                            'Verify the order summary before submitting payment.',
                            'Re-open the affiliate link if you intended to support a specific creator or partner.'
                        ],
                        investigationSteps: [
                            '1. Review the cookie name and domain.',
                            '2. Compare the previous and current attribution state.',
                            '3. Identify the page where the change occurred.',
                            '4. Review third-party scripts active at that time.',
                            '5. Review related network requests.',
                            '6. Determine whether the change was caused by a legitimate user action.',
                            '7. Check whether the same behavior repeats on subsequent visits.',
                            '8. Temporarily disable suspicious third-party extensions and test again.',
                            '9. Re-run the scan.',
                            '10. If reproducible, preserve the event evidence and report it to the relevant website/affiliate platform.'
                        ]
                    });
                }
            } else {
                // Attribution created or updated
                if (existingAttr && existingAttr.valueHash !== safeVal) {
                    // Attribution was overwritten
                    const severity = isCheckout ? 'HIGH' : 'MEDIUM';
                    const status = isCheckout ? 'HIGH-RISK' : 'SUSPICIOUS';

                    findings.push({
                        id: `attr-overwrite-${cookieName}-${Date.now()}`,
                        severity: severity,
                        title: 'Potential Affiliate/Referral Attribution Change Detected',
                        status: status,
                        confidence: 'HIGH',
                        detectedAt: timestamp,
                        timestamp: isoTimestamp,
                        affectedWebsite: cookie.domain,
                        affectedResource: `Attribution Cookie: ${cookieName}`,
                        technicalEvidence: `Attribution cookie "${cookieName}" was modified from previous value ${existingAttr.valueHash} to ${safeVal} (cause: ${cause}, checkout flow: ${isCheckout ? 'YES' : 'NO'}).`,
                        whyItMatters: 'A previously established affiliate or referral tracking cookie was overwritten during your browsing session. This may indicate unauthorized attribution hijacking (cookie stuffing), shopping extension injection, or normal campaign retargeting.',
                        recommendedActions: [
                            'Review active shopping, cash-back, or coupon extensions.',
                            'If this change occurred without clicking a new referral link, an extension or script may have altered attribution.',
                            'Re-open the legitimate affiliate link in a clean profile if you wish to preserve the original attribution.'
                        ],
                        investigationSteps: [
                            '1. Review the cookie name and domain.',
                            '2. Compare the previous and current attribution state.',
                            '3. Identify the page where the change occurred.',
                            '4. Review third-party scripts active at that time.',
                            '5. Review related network requests.',
                            '6. Determine whether the change was caused by a legitimate user action.',
                            '7. Check whether the same behavior repeats on subsequent visits.',
                            '8. Temporarily disable suspicious third-party extensions and test again.',
                            '9. Re-run the scan.',
                            '10. If reproducible, preserve the event evidence and report it to the relevant website/affiliate platform.'
                        ]
                    });
                }

                // Update attribution memory
                this.domainAttribution.set(`${domainKey}:${cookieName}`, {
                    cookieName,
                    domain: cookie.domain,
                    valueHash: safeVal,
                    lastUpdated: isoTimestamp,
                    path: cookie.path,
                    secure: cookie.secure,
                    httpOnly: cookie.httpOnly,
                    sameSite: cookie.sameSite
                });
            }
        }

        return findings;
    }
}

export const globalCookieMonitor = new CookieMonitor();
