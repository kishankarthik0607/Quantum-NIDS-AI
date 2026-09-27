/**
 * Quantum NIDS Browser Guard - Background Service Worker
 * 
 * Orchestrates real-time network request auditing, cookie lifecycle and attribution monitoring,
 * content script communication, ML engine inference, and on-demand security scans.
 */

import { getSiteConfig, extractDomainParts } from '../sites/supported-sites.js';
import { checkNIDS } from '../api/inference-client.js';
import { isAllowlistedDomain } from '../config/allowlists.js';
import { globalCookieMonitor } from '../cookies/cookie-monitor.js';
import { globalSecurityScanner } from '../scan/security-scanner.js';

// In-memory state tracking active monitored tabs
const activeTabs = {};

// Throttle ML calls per tab to prevent saturating the inference backend
const lastMlCheckPerTab = {};

/**
 * Handle tab navigation and page load completion.
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        try {
            const parsedUrl = new URL(tab.url);
            if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
                delete activeTabs[tabId];
                chrome.action.setBadgeText({ text: "", tabId }).catch(() => {});
                return;
            }

            const config = getSiteConfig(tab.url);
            const domainInfo = extractDomainParts(parsedUrl.hostname);
            const rootDomain = domainInfo ? domainInfo.rootDomain : parsedUrl.hostname;

            if (config) {
                activeTabs[tabId] = {
                    config,
                    url: tab.url,
                    hostname: parsedUrl.hostname,
                    rootDomain,
                    isSupported: true,
                    riskScore: 0,
                    alerts: [],
                    findings: [],
                    recentRequests: [],
                    flaggedThirdParties: new Set()
                };

                globalCookieMonitor.initTab(tabId, config.domain, tab.url);
                chrome.action.setBadgeText({ text: "MONITOR", tabId }).catch(() => {});
                chrome.action.setBadgeBackgroundColor({ color: "#2E7D32", tabId }).catch(() => {});
            } else {
                // Unsupported website: maintain generic baseline tracking without claiming supported
                activeTabs[tabId] = {
                    config: null,
                    url: tab.url,
                    hostname: parsedUrl.hostname,
                    rootDomain,
                    isSupported: false,
                    riskScore: 0,
                    alerts: [],
                    findings: [],
                    recentRequests: [],
                    flaggedThirdParties: new Set()
                };

                globalCookieMonitor.initTab(tabId, rootDomain, tab.url);
                chrome.action.setBadgeText({ text: "", tabId }).catch(() => {});
            }
        } catch {
            delete activeTabs[tabId];
        }
    }
});

/**
 * Clean up tab state when tab is closed.
 */
chrome.tabs.onRemoved.addListener((tabId) => {
    delete activeTabs[tabId];
    delete lastMlCheckPerTab[tabId];
    globalCookieMonitor.removeTab(tabId);
});

/**
 * Monitor cookie creation, updates, and deletions.
 */
chrome.cookies.onChanged.addListener((changeInfo) => {
    const cookie = changeInfo.cookie;
    const cleanCookieDomain = cookie.domain.replace(/^\./, '').toLowerCase();

    // Check all active tabs that match this cookie's domain
    for (const [tabIdStr, tabData] of Object.entries(activeTabs)) {
        const tabId = parseInt(tabIdStr, 10);
        if (!tabData || !tabData.url) continue;

        try {
            const tabHost = new URL(tabData.url).hostname.toLowerCase();
            if (tabHost === cleanCookieDomain || tabHost.endsWith('.' + cleanCookieDomain) || cleanCookieDomain.endsWith('.' + tabData.rootDomain)) {
                const cookieFindings = globalCookieMonitor.analyzeCookieChange(changeInfo, tabId, tabData.url);
                
                if (cookieFindings && cookieFindings.length > 0) {
                    for (const finding of cookieFindings) {
                        tabData.findings.push(finding);
                        tabData.alerts.push(`${finding.title} (${finding.affectedResource})`);
                        
                        let scoreIncrement = 15;
                        if (finding.severity === 'HIGH' || finding.severity === 'CRITICAL') scoreIncrement = 30;
                        else if (finding.severity === 'LOW') scoreIncrement = 5;

                        updateTabRisk(tabId, finding.title, scoreIncrement);
                    }
                }
            }
        } catch {}
    }
});

/**
 * Monitor network requests made by active tabs.
 */
chrome.webRequest.onCompleted.addListener(
    (details) => {
        const tabData = activeTabs[details.tabId];
        if (!tabData || !details.url) return;

        // Buffer recent requests (keep latest 60)
        tabData.recentRequests.push({
            url: details.url,
            statusCode: details.statusCode,
            method: details.method,
            timeStamp: details.timeStamp
        });
        if (tabData.recentRequests.length > 60) {
            tabData.recentRequests.shift();
        }

        analyzeNetworkRequest(details.tabId, details);
    },
    { urls: ["<all_urls>"] }
);

/**
 * Evaluates individual network requests for suspicious external domains and triggers ML inference.
 */
async function analyzeNetworkRequest(tabId, details) {
    const tabData = activeTabs[tabId];
    if (!tabData) return;

    try {
        const reqUrl = new URL(details.url);
        const reqHost = reqUrl.hostname;
        const siteSpecificAllowed = tabData.config ? tabData.config.allowedThirdPartyDomains : [];

        // Check if request is third-party
        const isThirdParty = reqHost && reqHost !== tabData.hostname && !reqHost.endsWith('.' + tabData.rootDomain);

        if (isThirdParty) {
            const isWhitelisted = isAllowlistedDomain(reqHost, siteSpecificAllowed);

            if (!isWhitelisted && !tabData.flaggedThirdParties.has(reqHost)) {
                tabData.flaggedThirdParties.add(reqHost);
                const isCheckout = /checkout|cart|payment|order|billing/i.test(tabData.url);
                const alertMsg = `Non-whitelisted third-party request to ${reqHost}`;
                
                tabData.findings.push({
                    id: `net-third-party-${reqHost}-${Date.now()}`,
                    severity: isCheckout ? 'HIGH' : 'LOW',
                    title: `External Connection to ${reqHost}`,
                    status: isCheckout ? 'HIGH-RISK' : 'SUSPICIOUS',
                    confidence: 'MEDIUM',
                    detectedAt: new Date().toLocaleTimeString(),
                    affectedWebsite: tabData.hostname,
                    affectedResource: reqHost,
                    technicalEvidence: `Network request to unverified third-party host ${reqHost} during ${isCheckout ? 'checkout session' : 'browsing session'}.`,
                    whyItMatters: 'Unverified external requests may indicate tracking pixels, unauthorized affiliate beacons, or potential data exfiltration.',
                    recommendedActions: [
                        'Verify third-party script origins in Network tab.',
                        'Avoid completing payment if unfamiliar external domains intercept checkout.'
                    ],
                    investigationSteps: [
                        'Review DevTools Network tab filter by domain.',
                        'Inspect initiator stack trace for the requesting script.'
                    ]
                });

                updateTabRisk(tabId, alertMsg, isCheckout ? 15 : 4);
            }
        }

        // Rate-limited ML inference check (at most once every 4 seconds per tab)
        const now = Date.now();
        const lastCheck = lastMlCheckPerTab[tabId] || 0;
        if (now - lastCheck > 4000) {
            lastMlCheckPerTab[tabId] = now;

            const features = {
                "Destination_Port": reqUrl.port ? parseInt(reqUrl.port, 10) : (reqUrl.protocol === 'https:' ? 443 : 80),
                "Total_Length_of_Fwd_Packets": 500,
                "Total_Length_of_Bwd_Packets": 2000,
                "Fwd_Packets/s": 10
            };

            const mlResponse = await checkNIDS(features);
            if (mlResponse && mlResponse.prediction === "ATTACK") {
                const riskInc = mlResponse.risk_score_contribution || 40;
                updateTabRisk(tabId, "ML Engine alert: Anomaly pattern detected in traffic flow.", riskInc);
            }
        }
    } catch {}
}

/**
 * Updates the risk score and badge for a tab.
 */
function updateTabRisk(tabId, reason, riskIncrease) {
    const tabData = activeTabs[tabId];
    if (!tabData) return;

    tabData.riskScore = Math.min(100, Math.round(tabData.riskScore + riskIncrease));
    if (reason && !tabData.alerts.includes(reason)) {
        tabData.alerts.push(reason);
    }

    if (tabData.riskScore >= 50) {
        chrome.action.setBadgeText({ text: "HIGH", tabId }).catch(() => {});
        chrome.action.setBadgeBackgroundColor({ color: "#D32F2F", tabId }).catch(() => {});
    } else if (tabData.riskScore >= 20) {
        chrome.action.setBadgeText({ text: "WARN", tabId }).catch(() => {});
        chrome.action.setBadgeBackgroundColor({ color: "#F57C00", tabId }).catch(() => {});
    }

    // Notify open popup if listening
    chrome.runtime.sendMessage({
        type: "RISK_UPDATE",
        tabId,
        data: tabData
    }).catch(() => {});
}

/**
 * Message handler for popup and content script requests.
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // Validate sender: only allow internal extension messages
    if (sender.id !== chrome.runtime.id) {
        console.warn("[Quantum NIDS] Rejected message from untrusted sender:", sender);
        return false;
    }

    // 1. Return current tab summary data
    if (request.type === "GET_TAB_DATA") {
        const tabId = request.tabId;
        if (activeTabs[tabId]) {
            sendResponse(activeTabs[tabId]);
            return false;
        }

        // Tab not cached yet, initialize dynamically
        chrome.tabs.get(tabId, (tab) => {
            if (chrome.runtime.lastError || !tab || !tab.url) {
                sendResponse(null);
                return;
            }

            try {
                const parsedUrl = new URL(tab.url);
                const config = getSiteConfig(tab.url);
                const domainInfo = extractDomainParts(parsedUrl.hostname);
                const rootDomain = domainInfo ? domainInfo.rootDomain : parsedUrl.hostname;

                activeTabs[tabId] = {
                    config,
                    url: tab.url,
                    hostname: parsedUrl.hostname,
                    rootDomain,
                    isSupported: !!config,
                    riskScore: 0,
                    alerts: [],
                    findings: [],
                    recentRequests: [],
                    flaggedThirdParties: new Set()
                };

                if (config) {
                    chrome.action.setBadgeText({ text: "MONITOR", tabId }).catch(() => {});
                    chrome.action.setBadgeBackgroundColor({ color: "#2E7D32", tabId }).catch(() => {});
                }

                sendResponse(activeTabs[tabId]);
            } catch {
                sendResponse(null);
            }
        });
        return true; // Keep channel open for async response
    }

    // 2. Execute on-demand Detailed Security Scan
    if (request.type === "RUN_DETAILED_SCAN") {
        const tabId = request.tabId;
        chrome.tabs.get(tabId, async (tab) => {
            if (chrome.runtime.lastError || !tab || !tab.url) {
                sendResponse(globalSecurityScanner.buildIncompleteReport('Could not access active tab.', '', new Date().toLocaleTimeString()));
                return;
            }

            const tabData = activeTabs[tabId] || {
                config: getSiteConfig(tab.url),
                url: tab.url,
                alerts: [],
                recentRequests: []
            };

            // Retrieve cookies for this tab URL
            let cookies = [];
            try {
                cookies = await chrome.cookies.getAll({ url: tab.url });
            } catch (e) {
                console.warn('[Quantum NIDS] Cookie access restricted for scan:', e);
            }

            // Retrieve DOM audit from content script
            let domAudit = null;
            try {
                domAudit = await new Promise((resolve) => {
                    chrome.tabs.sendMessage(tabId, { type: "EXECUTE_DEEP_PAGE_AUDIT" }, (response) => {
                        if (chrome.runtime.lastError || !response) {
                            resolve(null);
                        } else {
                            resolve(response);
                        }
                    });
                });
            } catch (e) {
                console.warn('[Quantum NIDS] Content script communication restricted:', e);
            }

            // Run scanner engine
            const scanReport = globalSecurityScanner.runDetailedScan({
                tabId,
                url: tab.url,
                cookies,
                domAudit,
                recentRequests: tabData.recentRequests || [],
                priorAlerts: tabData.alerts || []
            });

            // Update tab risk with scan findings
            if (activeTabs[tabId]) {
                activeTabs[tabId].riskScore = scanReport.riskScore;
                activeTabs[tabId].findings = scanReport.findings;
                if (scanReport.riskScore >= 50) {
                    chrome.action.setBadgeText({ text: "HIGH", tabId }).catch(() => {});
                    chrome.action.setBadgeBackgroundColor({ color: "#D32F2F", tabId }).catch(() => {});
                } else if (scanReport.riskScore >= 20) {
                    chrome.action.setBadgeText({ text: "WARN", tabId }).catch(() => {});
                    chrome.action.setBadgeBackgroundColor({ color: "#F57C00", tabId }).catch(() => {});
                } else if (tabData.isSupported) {
                    chrome.action.setBadgeText({ text: "MONITOR", tabId }).catch(() => {});
                    chrome.action.setBadgeBackgroundColor({ color: "#2E7D32", tabId }).catch(() => {});
                }
            }

            sendResponse(scanReport);
        });
        return true; // Asynchronous response
    }

    // 3. Dynamic alert from content script observer
    if (request.type === "PAGE_SECURITY_ALERT") {
        if (sender.tab && sender.tab.id && activeTabs[sender.tab.id]) {
            const tabId = sender.tab.id;
            if (request.flags && request.flags.length > 0) {
                for (const flag of request.flags) {
                    updateTabRisk(tabId, flag, 15);
                }
            }
        }
        sendResponse({ received: true });
        return false;
    }
});
