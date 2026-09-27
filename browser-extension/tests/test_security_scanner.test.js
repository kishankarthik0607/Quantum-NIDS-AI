import test from 'node:test';
import assert from 'node:assert/strict';
import { SecurityScanner } from '../scan/security-scanner.js';

test('Security Scanner - Baseline Clean HTTPS Session is SAFE', () => {
    const scanner = new SecurityScanner();
    const report = scanner.runDetailedScan({
        tabId: 1,
        url: 'https://www.amazon.com/dp/B08N5WRWNW',
        cookies: [
            { name: 'session-id', value: 'secret123', secure: true, httpOnly: true, sameSite: 'lax' }
        ],
        domAudit: {
            hiddenIframes: [],
            suspiciousScripts: [],
            suspiciousForms: [],
            storageFindings: [],
            mixedContentResources: []
        },
        recentRequests: [
            'https://www.amazon.com/dp/B08N5WRWNW',
            'https://images-amazon.com/images/I/item.jpg',
            'https://google-analytics.com/collect'
        ]
    });

    assert.equal(report.status, 'SAFE');
    assert.equal(report.riskScore, 0);
    assert.equal(report.findings[0].severity, 'INFO');
    assert.ok(report.findings[0].title.includes('Security Context Verified Safe'));
});

test('Security Scanner - Unencrypted Plaintext HTTP Triggers CRITICAL', () => {
    const scanner = new SecurityScanner();
    const report = scanner.runDetailedScan({
        tabId: 2,
        url: 'http://www.walmart.com/checkout',
        cookies: []
    });

    assert.equal(report.status, 'HIGH-RISK ACTIVITY');
    assert.ok(report.riskScore >= 45, 'HTTP on e-commerce must add significant risk');
    const httpFinding = report.findings.find(f => f.title.includes('Unencrypted Plaintext Connection'));
    assert.ok(httpFinding);
    assert.equal(httpFinding.severity, 'CRITICAL');
    assert.equal(httpFinding.status, 'HIGH-RISK');
    assert.ok(httpFinding.recommendedActions.length > 0);
});

test('Security Scanner - Punycode Homograph Domain Triggers HIGH Severity', () => {
    const scanner = new SecurityScanner();
    const report = scanner.runDetailedScan({
        tabId: 3,
        url: 'https://xn--amazn-7qa.com/login',
        cookies: []
    });

    const punyFinding = report.findings.find(f => f.title.includes('Punycode'));
    assert.ok(punyFinding);
    assert.equal(punyFinding.severity, 'HIGH');
    assert.equal(punyFinding.status, 'SUSPICIOUS');
});

test('Security Scanner - DOM Audit Hidden Iframes & Suspicious Scripts', () => {
    const scanner = new SecurityScanner();
    const report = scanner.runDetailedScan({
        tabId: 4,
        url: 'https://www.bestbuy.com/site/laptop',
        domAudit: {
            hiddenIframes: [{ src: 'https://ad-tracker.biz/iframe' }],
            suspiciousScripts: [{ src: 'https://ngrok.io/malicious.js', hostname: 'ngrok.io' }],
            suspiciousForms: [],
            storageFindings: []
        }
    });

    const iframeFinding = report.findings.find(f => f.title.includes('Hidden Iframe'));
    assert.ok(iframeFinding);
    assert.equal(iframeFinding.severity, 'MEDIUM');

    const scriptFinding = report.findings.find(f => f.title.includes('Suspicious External Script'));
    assert.ok(scriptFinding);
    assert.equal(scriptFinding.severity, 'HIGH');
    assert.equal(scriptFinding.status, 'HIGH-RISK');
});

test('Security Scanner - Formjacking / Magecart Detection Triggers CONFIRMED MALICIOUS', () => {
    const scanner = new SecurityScanner();
    const report = scanner.runDetailedScan({
        tabId: 5,
        url: 'https://www.target.com/co-checkout',
        domAudit: {
            hiddenIframes: [],
            suspiciousScripts: [],
            suspiciousForms: [
                {
                    action: 'https://attacker-data-drop.ru/collect',
                    hostname: 'attacker-data-drop.ru',
                    id: 'checkout-payment-form'
                }
            ],
            storageFindings: []
        }
    });

    assert.equal(report.status, 'CONFIRMED MALICIOUS INDICATOR');
    const formFinding = report.findings.find(f => f.title.includes('Suspicious External Form Action'));
    assert.ok(formFinding);
    assert.equal(formFinding.severity, 'CRITICAL');
    assert.equal(formFinding.status, 'CONFIRMED MALICIOUS');
    assert.ok(formFinding.recommendedActions.some(a => a.includes('DO NOT enter payment information')));
});

test('Security Scanner - False Positive Allowlists for CDNs, Analytics, and Payments', () => {
    const scanner = new SecurityScanner();
    const report = scanner.runDetailedScan({
        tabId: 6,
        url: 'https://www.ebay.com/itm/123',
        recentRequests: [
            'https://ebayimg.com/thumbs/item.png',
            'https://cdnjs.cloudflare.com/ajax/libs/react/18.0.0/react.min.js',
            'https://google-analytics.com/analytics.js',
            'https://js.stripe.com/v3/',
            'https://www.paypalobjects.com/webstatic/checkout.js'
        ]
    });

    // Allowed CDNs, analytics, and payment infrastructure must not trigger unwhitelisted warnings
    const unwhitelistedAlert = report.findings.find(f => f.title.includes('Non-Whitelisted External Domain'));
    assert.equal(unwhitelistedAlert, undefined, 'Allowlisted domains must not trigger warnings');
    assert.equal(report.status, 'SAFE');
});

test('Security Scanner - Unsupported Website Handling', () => {
    const scanner = new SecurityScanner();
    const report = scanner.runDetailedScan({
        tabId: 7,
        url: 'https://random-tech-blog.org/article/1',
        cookies: []
    });

    const infoFinding = report.findings.find(f => f.title.includes('Standard E-Commerce Protection Active'));
    assert.ok(infoFinding);
    assert.equal(infoFinding.severity, 'INFO');
    assert.ok(infoFinding.technicalEvidence.includes('not in specialized 110+ custom rulesets'));
});

test('Security Scanner - Restricted Protocol Returns SCAN INCOMPLETE Gracefully', () => {
    const scanner = new SecurityScanner();
    const report = scanner.runDetailedScan({
        tabId: 8,
        url: 'chrome://extensions',
        cookies: []
    });

    assert.equal(report.status, 'SCAN INCOMPLETE');
    assert.ok(report.summary.includes('Not accessible due to browser security restrictions'));
    assert.equal(report.findingsCount, 1);
    assert.equal(report.findings[0].title, 'Scan Incomplete - Restricted Security Context');
});
