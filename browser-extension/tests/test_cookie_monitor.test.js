import test from 'node:test';
import assert from 'node:assert/strict';
import { CookieMonitor, safeRedactedValue } from '../cookies/cookie-monitor.js';

test('Cookie Monitor - Sensitive Value Redaction & Masking', () => {
    // Sensitive cookie values must never be exposed in plaintext
    const secretSession = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.super_secret_credentials';
    const redactedSession = safeRedactedValue('session_token', secretSession);
    
    assert.ok(redactedSession.startsWith('[REDACTED_SENSITIVE'), 'Sensitive token must be redacted');
    assert.ok(!redactedSession.includes('super_secret_credentials'), 'Raw sensitive string must not leak');
    assert.ok(redactedSession.includes(`length=${secretSession.length}`));
    assert.ok(redactedSession.includes('hash='));

    // Sensitive auth cookie
    const authVal = 'password123!';
    const redactedAuth = safeRedactedValue('user_password', authVal);
    assert.ok(redactedAuth.startsWith('[REDACTED_SENSITIVE'));
    assert.ok(!redactedAuth.includes('password123!'));

    // Non-sensitive tracking cookie
    const affiliateTag = 'partner123';
    const previewAttr = safeRedactedValue('tag', affiliateTag);
    assert.equal(previewAttr, 'partner123', 'Safe non-sensitive attribution key allowed sanitized preview');
});

test('Cookie Monitor - Detects Insecure Sensitive Cookie on HTTPS', () => {
    const monitor = new CookieMonitor();
    const tabId = 101;
    monitor.initTab(tabId, 'amazon.com', 'https://www.amazon.com/your-account');

    const changeInfo = {
        removed: false,
        cause: 'explicit',
        cookie: {
            name: 'session-id',
            value: 'dummy_sensitive_session_val_xyz',
            domain: '.amazon.com',
            path: '/',
            secure: false, // Insecure on HTTPS!
            httpOnly: true,
            sameSite: 'lax'
        }
    };

    const findings = monitor.analyzeCookieChange(changeInfo, tabId, 'https://www.amazon.com/your-account');
    assert.equal(findings.length, 1);
    const f = findings[0];
    assert.equal(f.severity, 'HIGH');
    assert.equal(f.status, 'HIGH-RISK');
    assert.ok(f.title.includes('Insecure Sensitive Cookie'));
    assert.ok(!f.technicalEvidence.includes('dummy_sensitive_session_val_xyz'));
    assert.ok(f.technicalEvidence.includes('REDACTED_SENSITIVE'));
});

test('Cookie Monitor - Detects Attribution Cookie Overwrite', () => {
    const monitor = new CookieMonitor();
    const tabId = 102;
    monitor.initTab(tabId, 'amazon.com', 'https://www.amazon.com/dp/B08N5WRWNW');

    // 1. Establish initial affiliate tag (e.g. from legitimate creator link)
    const initialCookie = {
        removed: false,
        cause: 'explicit',
        cookie: {
            name: 'tag',
            value: 'creator_original_tag-20',
            domain: '.amazon.com',
            path: '/',
            secure: true,
            httpOnly: false,
            sameSite: 'lax'
        }
    };
    const initialFindings = monitor.analyzeCookieChange(initialCookie, tabId, 'https://www.amazon.com/dp/B08N5WRWNW');
    assert.equal(initialFindings.length, 0, 'Initial attribution setting should not trigger alert');

    // 2. Overwrite attribution cookie during normal browsing
    const overwriteCookie = {
        removed: false,
        cause: 'overwrite',
        cookie: {
            name: 'tag',
            value: 'hijacked_affiliate_id-20',
            domain: '.amazon.com',
            path: '/',
            secure: true,
            httpOnly: false,
            sameSite: 'lax'
        }
    };
    const overwriteFindings = monitor.analyzeCookieChange(overwriteCookie, tabId, 'https://www.amazon.com/dp/B08N5WRWNW');
    assert.equal(overwriteFindings.length, 1);
    const f = overwriteFindings[0];
    assert.equal(f.severity, 'MEDIUM');
    assert.equal(f.status, 'SUSPICIOUS');
    assert.equal(f.title, 'Potential Affiliate/Referral Attribution Change Detected');
    assert.equal(f.investigationSteps.length, 10, 'Expected 10-step investigation workflow from Phase 8');
});

test('Cookie Monitor - Detects Attribution Manipulation During Checkout as HIGH Severity', () => {
    const monitor = new CookieMonitor();
    const tabId = 103;
    const checkoutUrl = 'https://www.amazon.com/gp/buy/spc/handlers/display.html?hasWorkingJavascript=1';
    monitor.initTab(tabId, 'amazon.com', checkoutUrl);

    // Initial partner tag
    monitor.analyzeCookieChange({
        removed: false,
        cause: 'explicit',
        cookie: { name: 'aff_id', value: 'partner_legit', domain: '.amazon.com', secure: true }
    }, tabId, checkoutUrl);

    // Overwritten during checkout
    const checkoutOverwrite = monitor.analyzeCookieChange({
        removed: false,
        cause: 'overwrite',
        cookie: { name: 'aff_id', value: 'coupon_extension_hijack', domain: '.amazon.com', secure: true }
    }, tabId, checkoutUrl);

    assert.equal(checkoutOverwrite.length, 1);
    const f = checkoutOverwrite[0];
    assert.equal(f.severity, 'HIGH', 'Attribution overwrite during checkout must be HIGH severity');
    assert.equal(f.status, 'HIGH-RISK');
    assert.ok(f.technicalEvidence.includes('checkout flow: YES'));
});

test('Cookie Monitor - Detects Rapid Cookie Thrashing Bursts', () => {
    const monitor = new CookieMonitor();
    const tabId = 104;
    monitor.initTab(tabId, 'walmart.com', 'https://www.walmart.com');

    let triggeredThrash = false;
    for (let i = 0; i < 30; i++) {
        const findings = monitor.analyzeCookieChange({
            removed: false,
            cause: 'explicit',
            cookie: {
                name: `cookie_${i}`,
                value: `val_${i}`,
                domain: '.walmart.com',
                secure: true
            }
        }, tabId, 'https://www.walmart.com');

        if (findings.some(f => f.title.includes('Excessive Cookie Mutation Burst'))) {
            triggeredThrash = true;
            break;
        }
    }

    assert.equal(triggeredThrash, true, 'Rapid burst of 30 cookie writes must trigger thrashing finding');
});
