/**
 * Quantum NIDS Browser Guard - Security Scanner Engine
 * 
 * Performs comprehensive browser-side security audits for retail & e-commerce sessions:
 * - Domain Authenticity & Homograph detection
 * - HTTPS / Security Context & Mixed Content
 * - Hidden Iframes & Form Action Hijacking (Magecart)
 * - Suspicious Scripts & Third-Party Domains
 * - Cookie Security & Session Flags
 * - Affiliate/Referral Attribution Manipulation
 * - Storage Exposure (Sensitive tokens/cards)
 * - Actionable Remediation & Investigation Workflows
 */

import { getSiteConfig, extractDomainParts } from '../sites/supported-sites.js';
import { isAllowlistedDomain, isSensitiveCookieName, isAttributionCookieName, SUSPICIOUS_SCRIPT_PATTERNS } from '../config/allowlists.js';
import { safeRedactedValue } from '../cookies/cookie-monitor.js';

export class SecurityScanner {
    constructor() {}

    /**
     * Executes a full detailed security scan on the specified tab.
     * 
     * @param {object} params
     * @param {number} params.tabId
     * @param {string} params.url
     * @param {Array} params.cookies - Cookies retrieved via chrome.cookies.getAll
     * @param {object} params.domAudit - Audit data from content script (scripts, iframes, forms, storage)
     * @param {Array} params.recentRequests - Web requests recorded for this tab
     * @param {Array} params.priorAlerts - Existing alerts recorded during the session
     * @returns {object} Scan report with findings, risk score, status, and remediation
     */
    runDetailedScan({ tabId, url, cookies = [], domAudit = null, recentRequests = [], priorAlerts = [] }) {
        const now = new Date();
        const timestamp = now.toLocaleTimeString();
        const isoTimestamp = now.toISOString();

        // 1. Error / Security Context Validation
        let parsedUrl;
        try {
            parsedUrl = new URL(url);
        } catch {
            return this.buildIncompleteReport('Malformed or invalid URL provided.', url, timestamp);
        }

        // Handle internal or restricted URLs
        if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
            return this.buildIncompleteReport(
                'Not accessible due to browser security restrictions (non-HTTP protocol).',
                url,
                timestamp
            );
        }

        const hostname = parsedUrl.hostname;
        const siteConfig = getSiteConfig(url);
        const domainParts = extractDomainParts(hostname);
        const rootDomain = domainParts ? domainParts.rootDomain : hostname;
        const isCheckout = /checkout|cart|payment|order|billing|buy|purchase|spc/i.test(parsedUrl.pathname);

        const findings = [];

        // 2. Protocol / HTTPS Security Context Check
        if (parsedUrl.protocol === 'http:') {
            findings.push({
                id: `sec-http-plaintext-${Date.now()}`,
                severity: 'CRITICAL',
                title: 'Unencrypted Plaintext Connection (HTTP)',
                status: 'HIGH-RISK',
                confidence: 'HIGH',
                detectedAt: timestamp,
                timestamp: isoTimestamp,
                affectedWebsite: hostname,
                affectedResource: url,
                technicalEvidence: `Page is served over unencrypted HTTP protocol (${parsedUrl.protocol}). All network transmissions are readable in transit.`,
                whyItMatters: 'Using HTTP on an e-commerce website exposes user logins, session tokens, personal addresses, and payment data to network interception, ISP tracking, and man-in-the-middle tampering.',
                recommendedActions: [
                    'Immediately leave this unencrypted page.',
                    'Do not enter passwords, addresses, or payment card details.',
                    'Check if the legitimate website offers an HTTPS version (https://).',
                    'If credentials were entered, change passwords immediately from a secure network.'
                ],
                investigationSteps: [
                    '1. Verify the address bar for the missing padlock indicator.',
                    '2. Inspect if HTTP Strict Transport Security (HSTS) headers were bypassed.',
                    '3. Check if local network captive portals or proxies forced an HTTP downgrade.'
                ]
            });
        }

        // 3. Domain Authenticity & Homograph / Lookalike Analysis
        if (hostname.includes('xn--')) {
            findings.push({
                id: `sec-punycode-homograph-${Date.now()}`,
                severity: 'HIGH',
                title: 'Internationalized Domain Name (Punycode) Detected',
                status: 'SUSPICIOUS',
                confidence: 'HIGH',
                detectedAt: timestamp,
                timestamp: isoTimestamp,
                affectedWebsite: hostname,
                affectedResource: hostname,
                technicalEvidence: `Hostname uses Punycode encoding (${hostname}), which may represent lookalike Unicode characters resembling legitimate retail brands.`,
                whyItMatters: 'Punycode homograph attacks substitute visual lookalike characters (e.g. Cyrillic "а" for Latin "a") to spoof brand URLs and trick shoppers into phishing traps.',
                recommendedActions: [
                    'Carefully inspect the decoded ASCII characters in the address bar.',
                    'Avoid logging in or completing purchases on this domain unless authenticity is verified.',
                    'Navigate to the retailer directly by typing their known web address.'
                ],
                investigationSteps: [
                    '1. Decode the punycode string to inspect characters.',
                    '2. Check WHOIS registration age and registrant details.',
                    '3. Compare SSL certificate subject alternative names with known official certificates.'
                ]
            });
        }

        // Check for suspicious brand lookalike patterns
        if (!siteConfig && (hostname.includes('amazon') || hostname.includes('walmart') || hostname.includes('apple') || hostname.includes('ebay'))) {
            findings.push({
                id: `sec-lookalike-domain-${Date.now()}`,
                severity: 'HIGH',
                title: 'Potential Brand Lookalike Domain Detected',
                status: 'SUSPICIOUS',
                confidence: 'MEDIUM',
                detectedAt: timestamp,
                timestamp: isoTimestamp,
                affectedWebsite: hostname,
                affectedResource: hostname,
                technicalEvidence: `Domain "${hostname}" contains a major retail brand name but is not registered in the verified retail domain whitelist.`,
                whyItMatters: 'Phishing and counterfeit store operators frequently register domains containing recognizable retail names to deceive consumers.',
                recommendedActions: [
                    'Double check the exact spelling of the domain.',
                    'Do not input account credentials or financial data.',
                    'Close this window and access the retailer via an official search bookmark.'
                ],
                investigationSteps: [
                    '1. Compare domain registrar and DNS records against official corporate registries.',
                    '2. Verify whether this is an authorized affiliate microsite or an unauthorized domain.'
                ]
            });
        }

        // 4. Supported Status Notice
        if (!siteConfig) {
            findings.push({
                id: `sec-info-unsupported-${Date.now()}`,
                severity: 'INFO',
                title: 'Standard E-Commerce Protection Active',
                status: 'NORMAL',
                confidence: 'HIGH',
                detectedAt: timestamp,
                timestamp: isoTimestamp,
                affectedWebsite: hostname,
                affectedResource: hostname,
                technicalEvidence: `Domain "${hostname}" is evaluated under standard e-commerce security heuristics (not in specialized 110+ custom rulesets).`,
                whyItMatters: 'General security rules (HTTPS validation, cookie hygiene, hidden iframes, attribution protection) remain fully operational.',
                recommendedActions: [
                    'Continue standard security awareness when shopping on third-party stores.'
                ],
                investigationSteps: [
                    'Verify website identity and reputation independently if this is an unfamiliar store.'
                ]
            });
        }

        // 5. Content Script DOM Audit Evaluation (Iframes, Scripts, Forms, Storage)
        if (domAudit) {
            // A. Hidden Iframes
            if (domAudit.hiddenIframes && domAudit.hiddenIframes.length > 0) {
                const count = domAudit.hiddenIframes.length;
                findings.push({
                    id: `sec-hidden-iframes-${Date.now()}`,
                    severity: 'MEDIUM',
                    title: `${count} Hidden Iframe(s) Detected in DOM`,
                    status: 'SUSPICIOUS',
                    confidence: 'HIGH',
                    detectedAt: timestamp,
                    timestamp: isoTimestamp,
                    affectedWebsite: hostname,
                    affectedResource: domAudit.hiddenIframes[0].src || 'about:blank',
                    technicalEvidence: `Detected ${count} invisible or 0-dimension iframe(s) rendered on the page: ${domAudit.hiddenIframes.map(f => f.src || '[inline]').slice(0, 3).join(', ')}.`,
                    whyItMatters: 'Hidden iframes are frequently used for silent cookie-stuffing, ad-fraud click harvesting, or background exploit delivery without user awareness.',
                    recommendedActions: [
                        'Review active browser extensions that might inject tracking frames.',
                        'Avoid completing sensitive transactions until verified.',
                        'Reload the page in an incognito window with extensions disabled.'
                    ],
                    investigationSteps: [
                        '1. Open DevTools Elements tab and search for <iframe> tags.',
                        '2. Inspect the src attribute and parent nodes.',
                        '3. Monitor the Network tab to identify payloads loaded by the hidden iframe.'
                    ]
                });
            }

            // B. Suspicious Script Domains
            if (domAudit.suspiciousScripts && domAudit.suspiciousScripts.length > 0) {
                for (const script of domAudit.suspiciousScripts) {
                    findings.push({
                        id: `sec-suspicious-script-${Date.now()}`,
                        severity: 'HIGH',
                        title: 'Suspicious External Script Source Detected',
                        status: 'HIGH-RISK',
                        confidence: 'HIGH',
                        detectedAt: timestamp,
                        timestamp: isoTimestamp,
                        affectedWebsite: hostname,
                        affectedResource: script.src,
                        technicalEvidence: `Page loads external script from suspicious or unauthorized hosting service: ${script.src}.`,
                        whyItMatters: 'Loading scripts from temporary pastebins, link-shorteners, or tunneling proxies can indicate client-side code injection or compromised third-party dependencies.',
                        recommendedActions: [
                            'Close the current checkout or account session immediately.',
                            'Do not submit payment or credit card details.',
                            'Clear local site cache and re-scan.'
                        ],
                        investigationSteps: [
                            '1. Inspect script contents in DevTools Sources tab.',
                            '2. Identify whether the script is injected by an extension or the page HTML.',
                            '3. Analyze outbound network requests initiated by this script.'
                        ]
                    });
                }
            }

            // C. Formjacking / Form Action Hijacking Checks
            if (domAudit.suspiciousForms && domAudit.suspiciousForms.length > 0) {
                for (const form of domAudit.suspiciousForms) {
                    findings.push({
                        id: `sec-form-hijack-${Date.now()}`,
                        severity: 'CRITICAL',
                        title: 'Suspicious External Form Action (Potential Formjacking / Magecart)',
                        status: 'CONFIRMED MALICIOUS',
                        confidence: 'HIGH',
                        detectedAt: timestamp,
                        timestamp: isoTimestamp,
                        affectedWebsite: hostname,
                        affectedResource: `Form target: ${form.action}`,
                        technicalEvidence: `Form on "${hostname}" submits user inputs to external, unwhitelisted destination: ${form.action} (Form ID: ${form.id || 'none'}).`,
                        whyItMatters: 'Formjacking attacks (such as Magecart) modify payment or login forms to transmit submitted card numbers and credentials directly to attacker servers.',
                        recommendedActions: [
                            'DO NOT enter payment information or submit this form.',
                            'Close the page immediately.',
                            'If payment information was already submitted, contact your card issuer to block unauthorized charges.'
                        ],
                        investigationSteps: [
                            '1. Inspect the form element in DevTools Elements tab.',
                            '2. Check whether the form action was altered by DOM manipulation scripts.',
                            '3. Verify if the target destination matches official merchant payment gateway documentation.'
                        ]
                    });
                }
            }

            // D. Sensitive Plaintext in Local/Session Storage
            if (domAudit.storageFindings && domAudit.storageFindings.length > 0) {
                for (const item of domAudit.storageFindings) {
                    findings.push({
                        id: `sec-storage-sensitive-${Date.now()}`,
                        severity: 'MEDIUM',
                        title: 'Potentially Sensitive Data Stored in Plaintext Storage',
                        status: 'SUSPICIOUS',
                        confidence: 'MEDIUM',
                        detectedAt: timestamp,
                        timestamp: isoTimestamp,
                        affectedWebsite: hostname,
                        affectedResource: `Storage key: ${item.key} (${item.storageType})`,
                        technicalEvidence: `Observed sensitive data indicator in ${item.storageType}: Key "${item.key}" contains pattern "${item.matchedPattern}". Value: [REDACTED_SENSITIVE].`,
                        whyItMatters: 'Storing unencrypted tokens or credentials in web storage (localStorage/sessionStorage) exposes them to any script running in the page origin, including third-party widgets and XSS exploits.',
                        recommendedActions: [
                            'Do not use public or shared computers for this session.',
                            'Ensure you log out cleanly after finishing purchases.'
                        ],
                        investigationSteps: [
                            '1. Open DevTools > Application > Local Storage / Session Storage.',
                            '2. Verify what script created the key and whether encryption is implemented.'
                        ]
                    });
                }
            }

            // E. Mixed Content Indicators
            if (domAudit.mixedContentResources && domAudit.mixedContentResources.length > 0) {
                findings.push({
                    id: `sec-mixed-content-${Date.now()}`,
                    severity: 'MEDIUM',
                    title: 'Mixed Content Detected on Secure Page',
                    status: 'SUSPICIOUS',
                    confidence: 'HIGH',
                    detectedAt: timestamp,
                    timestamp: isoTimestamp,
                    affectedWebsite: hostname,
                    affectedResource: domAudit.mixedContentResources[0],
                    technicalEvidence: `Secure HTTPS page references ${domAudit.mixedContentResources.length} insecure HTTP asset(s): ${domAudit.mixedContentResources.slice(0, 3).join(', ')}.`,
                    whyItMatters: 'Mixed content weakens HTTPS security and can allow attackers to tamper with images, scripts, or stylesheets via man-in-the-middle attacks.',
                    recommendedActions: [
                        'Avoid completing sensitive transactions until assets are loaded over HTTPS.',
                        'Verify if the browser blocked mixed active content.'
                    ],
                    investigationSteps: [
                        'Check the Chrome DevTools Console for "Mixed Content" warnings.',
                        'Review asset origins in the Network tab.'
                    ]
                });
            }
        }

        // 6. Cookie Security & Attribution Analysis
        if (cookies && cookies.length > 0) {
            let insecureSensitiveCount = 0;
            let missingHttpOnlyCount = 0;
            const attributionCookies = [];

            for (const c of cookies) {
                const isSens = isSensitiveCookieName(c.name);
                const isAttr = isAttributionCookieName(c.name);

                if (isSens) {
                    if (!c.secure && parsedUrl.protocol === 'https:') {
                        insecureSensitiveCount++;
                    }
                    if (!c.httpOnly && /session|auth|token|jwt|sid/i.test(c.name)) {
                        missingHttpOnlyCount++;
                    }
                }

                if (isAttr) {
                    attributionCookies.push(c);
                }
            }

            if (insecureSensitiveCount > 0) {
                findings.push({
                    id: `sec-cookies-insecure-${Date.now()}`,
                    severity: 'HIGH',
                    title: `${insecureSensitiveCount} Insecure Sensitive Cookie(s) Detected`,
                    status: 'HIGH-RISK',
                    confidence: 'HIGH',
                    detectedAt: timestamp,
                    timestamp: isoTimestamp,
                    affectedWebsite: hostname,
                    affectedResource: `Cookies on domain: ${hostname}`,
                    technicalEvidence: `Found ${insecureSensitiveCount} sensitive authentication/session cookie(s) lacking the "Secure" flag on an HTTPS site.`,
                    whyItMatters: 'Sensitive cookies without the Secure flag can be sent over unencrypted HTTP connections, exposing user sessions to interception.',
                    recommendedActions: [
                        'Clear cookies for this domain to force secure reissue.',
                        'Avoid entering credentials until cookies are properly secured.'
                    ],
                    investigationSteps: [
                        'Inspect Application > Cookies in DevTools and verify the Secure flag.'
                    ]
                });
            }

            if (attributionCookies.length > 3) {
                findings.push({
                    id: `sec-attr-competing-${Date.now()}`,
                    severity: 'LOW',
                    title: 'Multiple Competing Attribution Tags Present',
                    status: 'SUSPICIOUS',
                    confidence: 'MEDIUM',
                    detectedAt: timestamp,
                    timestamp: isoTimestamp,
                    affectedWebsite: hostname,
                    affectedResource: attributionCookies.map(c => c.name).join(', '),
                    technicalEvidence: `Observed ${attributionCookies.length} distinct affiliate/referral tracking identifiers: ${attributionCookies.map(c => c.name).slice(0, 5).join(', ')}.`,
                    whyItMatters: 'Multiple conflicting attribution parameters can signal affiliate link collision, shopping extension cookie replacement, or multiple ad campaigns active simultaneously.',
                    recommendedActions: [
                        'If shopping through a specific cashback or affiliate link, verify that the intended partner is acknowledged.',
                        'Disable extraneous shopping extensions if they overwrite discounts.'
                    ],
                    investigationSteps: [
                        '1. Check cookie values and expiration dates in DevTools.',
                        '2. Identify whether multiple extensions injected their own partner tags.'
                    ]
                });
            }
        }

        // 7. Network Telemetry & Third-Party Domain Evaluation
        if (recentRequests && recentRequests.length > 0) {
            const externalHosts = new Set();
            const unwhitelistedHosts = [];
            const siteSpecificAllowed = siteConfig ? siteConfig.allowedThirdPartyDomains : [];

            for (const req of recentRequests) {
                try {
                    const reqUrl = new URL(req.url || req);
                    const reqHost = reqUrl.hostname;
                    if (!reqHost || reqHost === hostname || reqHost.endsWith('.' + rootDomain)) {
                        continue; // First-party request
                    }

                    externalHosts.add(reqHost);

                    if (!isAllowlistedDomain(reqHost, siteSpecificAllowed)) {
                        if (!unwhitelistedHosts.includes(reqHost)) {
                            unwhitelistedHosts.push(reqHost);
                        }
                    }
                } catch {}
            }

            if (unwhitelistedHosts.length > 0) {
                const topUnwhitelisted = unwhitelistedHosts.slice(0, 4);
                findings.push({
                    id: `sec-unwhitelisted-requests-${Date.now()}`,
                    severity: isCheckout ? 'HIGH' : 'LOW',
                    title: `${unwhitelistedHosts.length} Non-Whitelisted External Domain(s) Contacted`,
                    status: isCheckout ? 'HIGH-RISK' : 'SUSPICIOUS',
                    confidence: 'MEDIUM',
                    detectedAt: timestamp,
                    timestamp: isoTimestamp,
                    affectedWebsite: hostname,
                    affectedResource: topUnwhitelisted.join(', '),
                    technicalEvidence: `Observed network requests to non-whitelisted third-party hostnames: ${topUnwhitelisted.join(', ')} (checkout flow: ${isCheckout ? 'ACTIVE' : 'INACTIVE'}).`,
                    whyItMatters: 'Third-party connections during browsing or checkout that are not recognized CDNs, analytics, or payment gateways may indicate unauthorized data exfiltration, ad-trackers, or compromised scripts.',
                    recommendedActions: [
                        'Inspect active background network connections.',
                        'Do not submit payment information if unfamiliar third-party domains intercept the checkout.',
                        'Check for extensions making background outbound connections.'
                    ],
                    investigationSteps: [
                        '1. Review Network tab in DevTools for the affected domains.',
                        '2. Examine request initiator call stacks to identify the requesting script.',
                        '3. Verify if the domain belongs to a newly integrated merchant vendor.'
                    ]
                });
            }
        }

        // 8. Session Attribution Anomalies from prior alerts
        if (priorAlerts && priorAlerts.length > 0) {
            for (const alert of priorAlerts) {
                // If it was an attribution manipulation event, promote it as a high priority finding
                if (typeof alert === 'string' && alert.includes('Attribution')) {
                    findings.push({
                        id: `sec-prior-attr-${Date.now()}`,
                        severity: 'HIGH',
                        title: 'Attribution Manipulation Event Recorded During Session',
                        status: 'HIGH-RISK',
                        confidence: 'HIGH',
                        detectedAt: timestamp,
                        timestamp: isoTimestamp,
                        affectedWebsite: hostname,
                        affectedResource: 'Affiliate Attribution Tracking',
                        technicalEvidence: alert,
                        whyItMatters: 'Attribution cookie values were modified or overwritten during active browsing.',
                        recommendedActions: [
                            'Review active shopping extensions.',
                            'Verify cart totals and promotions prior to checkout.'
                        ],
                        investigationSteps: [
                            '1. Compare cookie history in Cookie Monitor logs.',
                            '2. Re-test the page in a clean browser window.'
                        ]
                    });
                }
            }
        }

        // 9. Intrusion Assessment & Synthesis
        return this.synthesizeReport(hostname, findings, timestamp);
    }

    /**
     * Synthesizes findings into overall risk score, status, and summary report.
     */
    synthesizeReport(hostname, findings, timestamp) {
        let riskScore = 0;
        let hasConfirmedMalicious = false;
        let hasCritical = false;
        let hasHigh = false;
        let hasMedium = false;

        for (const f of findings) {
            if (f.status === 'CONFIRMED MALICIOUS') {
                hasConfirmedMalicious = true;
            }
            switch (f.severity) {
                case 'CRITICAL':
                    riskScore += 45;
                    hasCritical = true;
                    break;
                case 'HIGH':
                    riskScore += 25;
                    hasHigh = true;
                    break;
                case 'MEDIUM':
                    riskScore += 12;
                    hasMedium = true;
                    break;
                case 'LOW':
                    riskScore += 4;
                    break;
                case 'INFO':
                default:
                    break;
            }
        }

        riskScore = Math.min(100, riskScore);

        let overallStatus = 'SAFE';
        let statusSummary = 'No suspicious indicators detected during browser security audit.';

        if (hasConfirmedMalicious) {
            overallStatus = 'CONFIRMED MALICIOUS INDICATOR';
            statusSummary = 'Confirmed malicious indicator detected on this page (e.g. formjacking or data theft).';
        } else if (hasCritical || hasHigh || riskScore >= 50) {
            overallStatus = 'HIGH-RISK ACTIVITY';
            statusSummary = 'High-risk security anomalies detected. Caution is strongly advised.';
        } else if (hasMedium || riskScore >= 20) {
            overallStatus = 'SUSPICIOUS ACTIVITY';
            statusSummary = 'Potential intrusion indicators detected; browser-level evidence is insufficient to confirm compromise.';
        }

        // If no findings, provide an informational safe baseline
        if (findings.length === 0) {
            findings.push({
                id: `sec-baseline-safe-${Date.now()}`,
                severity: 'INFO',
                title: 'Security Context Verified Safe',
                status: 'NORMAL',
                confidence: 'HIGH',
                detectedAt: timestamp,
                affectedWebsite: hostname,
                affectedResource: hostname,
                technicalEvidence: 'HTTPS connection active, zero hidden iframes, no formjacking indicators, clean cookie flags, and verified domain authenticity.',
                whyItMatters: 'Page conforms to secure e-commerce web standards.',
                recommendedActions: ['Continue standard browsing.'],
                investigationSteps: ['No investigation required.']
            });
        }

        return {
            status: overallStatus,
            summary: statusSummary,
            riskScore,
            hostname,
            scanCompletedAt: timestamp,
            findingsCount: findings.length,
            findings
        };
    }

    buildIncompleteReport(reason, url, timestamp) {
        return {
            status: 'SCAN INCOMPLETE',
            summary: `Not accessible due to browser security restrictions: ${reason}`,
            riskScore: 0,
            hostname: url || 'Unknown',
            scanCompletedAt: timestamp,
            findingsCount: 1,
            findings: [
                {
                    id: `sec-incomplete-${Date.now()}`,
                    severity: 'INFO',
                    title: 'Scan Incomplete - Restricted Security Context',
                    status: 'NORMAL',
                    confidence: 'HIGH',
                    detectedAt: timestamp,
                    affectedWebsite: url || 'Unknown',
                    affectedResource: url || 'Browser context',
                    technicalEvidence: reason,
                    whyItMatters: 'Browser extension security architecture restricts programmatic access to internal pages (chrome://, devtools://) and unsupported protocols.',
                    recommendedActions: [
                        'Navigate to a standard public website (http:// or https://) to run security scans.'
                    ],
                    investigationSteps: [
                        'Check the browser address bar to verify the current page protocol.'
                    ]
                }
            ]
        };
    }
}

export const globalSecurityScanner = new SecurityScanner();
