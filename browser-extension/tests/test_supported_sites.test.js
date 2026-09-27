import test from 'node:test';
import assert from 'node:assert/strict';
import {
    SUPPORTED_SITES,
    majorEcommerceDomains,
    getSiteConfig,
    isSupportedUrl,
    getCanonicalDomain,
    extractDomainParts
} from '../sites/supported-sites.js';

test('Supported Sites - Schema and List Completeness', () => {
    assert.equal(majorEcommerceDomains.length, 110, 'Expected 110 major retail brands');
    assert.equal(SUPPORTED_SITES.length, 110, 'Expected 110 configured supported site objects');

    for (const site of SUPPORTED_SITES) {
        assert.ok(site.domain, 'Site must have domain string');
        assert.equal(site.category, 'ecommerce');
        assert.equal(site.enabled, true);
        assert.equal(site.monitoringLevel, 'high');
        assert.ok(Array.isArray(site.allowedThirdPartyDomains));
        assert.ok(Array.isArray(site.primarySlds));
        assert.ok(Array.isArray(site.knownDomains));
        assert.deepEqual(site.cookieRules, { maxChangesPerMinute: 10 });
        assert.deepEqual(site.riskRules, { blockHiddenRedirects: true });
    }
});

test('extractDomainParts - Correct Root Domain and SLD Extraction', () => {
    // Standard .com
    const amazon = extractDomainParts('www.amazon.com');
    assert.equal(amazon.rootDomain, 'amazon.com');
    assert.equal(amazon.sld, 'amazon');
    assert.equal(amazon.publicSuffix, 'com');

    // Multi-part suffix .co.uk
    const amazonUk = extractDomainParts('smile.amazon.co.uk');
    assert.equal(amazonUk.rootDomain, 'amazon.co.uk');
    assert.equal(amazonUk.sld, 'amazon');
    assert.equal(amazonUk.publicSuffix, 'co.uk');

    // Multi-part suffix .co.kr
    const elevenSt = extractDomainParts('11st.co.kr');
    assert.equal(elevenSt.rootDomain, '11st.co.kr');
    assert.equal(elevenSt.sld, '11st');
    assert.equal(elevenSt.publicSuffix, 'co.kr');

    // Subdomains on multi-part suffix
    const mercadolivre = extractDomainParts('lista.mercadolivre.com.br');
    assert.equal(mercadolivre.rootDomain, 'mercadolivre.com.br');
    assert.equal(mercadolivre.sld, 'mercadolivre');
});

test('Domain Matching - Verifies Key Brands and Subdomains', () => {
    const validTestCases = [
        { url: 'https://www.amazon.com/dp/B08N5WRWNW', expected: 'amazon' },
        { url: 'https://smile.amazon.co.uk/cart', expected: 'amazon' },
        { url: 'https://pay.amazon.in/', expected: 'amazon' },
        { url: 'https://checkout.walmart.com/order', expected: 'walmart' },
        { url: 'https://www.apple.com/shop/buy-iphone', expected: 'apple' },
        { url: 'https://jd.com/item/12345', expected: 'jd' },
        { url: 'https://item.jd.com/10001.html', expected: 'jd' },
        { url: 'https://11st.co.kr/products/99', expected: '11st' },
        { url: 'https://www.mercadolibre.com.ar/', expected: 'mercado-libre' },
        { url: 'https://www.target.com/p/item', expected: 'target' },
        { url: 'https://www.bestbuy.com/site/laptop', expected: 'bestbuy' },
        { url: 'https://www.homedepot.com/p/hammer', expected: 'homedepot' },
        { url: 'https://www.costco.com/warehouse', expected: 'costco' },
        { url: 'https://www.shein.com/goods', expected: 'shein' },
        { url: 'https://m.aliexpress.com/item', expected: 'aliexpress' },
        { url: 'https://www.ikea.com/us/en/', expected: 'ikea' },
        { url: 'https://www.cvs.com/pharmacy', expected: 'cvs' },
        { url: 'https://www.walgreens.com/store', expected: 'walgreens' },
        { url: 'https://www.sephora.com/product/perfume', expected: 'sephora' },
        { url: 'https://www.nordstrom.com/browse', expected: 'nordstrom' },
        { url: 'https://b2w.digital/', expected: 'b2w' },
        { url: 'https://www.roomstogo.com/furniture', expected: 'roomsdtogo' },
        { url: 'https://www.gamestop.com/video-games', expected: 'gamestop' },
        { url: 'https://www.newegg.com/components', expected: 'newegg' }
    ];

    for (const { url, expected } of validTestCases) {
        const config = getSiteConfig(url);
        assert.ok(config, `Expected ${url} to be matched as supported`);
        assert.equal(config.domain, expected, `Expected brand ${expected} for ${url}`);
        assert.equal(isSupportedUrl(url), true);
        assert.equal(getCanonicalDomain(url), expected);
    }
});

test('Domain Matching - Rejects Phishing, Lookalikes, and Subdomain Spoofs', () => {
    const maliciousLookalikes = [
        'https://not-amazon.com/login',
        'https://amazon-security-update.com/',
        'https://amazon.attacker.com/steal-creds',
        'https://apple-id-verify.com/',
        'https://pineapple.com/store',
        'https://snapple.com/',
        'https://notredame.edu/athletics', // Substring 'jd' test
        'https://badjd.com/item',
        'https://cvss-calculator.com/', // Substring 'cvs' test
        'https://strikeagain.com/news', // Substring 'ikea' test
        'https://walmart-rewards.net/claim',
        'https://target-giftcards.biz/',
        'https://evil-shein.com/checkout'
    ];

    for (const url of maliciousLookalikes) {
        const config = getSiteConfig(url);
        assert.equal(config, null, `Malicious or lookalike URL ${url} must NOT be classified as supported`);
        assert.equal(isSupportedUrl(url), false);
        assert.equal(getCanonicalDomain(url), null);
    }
});

test('Domain Matching - Rejects Non-Web and Unsupported Protocols', () => {
    const restrictedUrls = [
        'chrome://extensions',
        'edge://settings',
        'about:blank',
        'file:///C:/Users/dell/Desktop/test.html',
        'javascript:alert(1)',
        'data:text/html,<h1>test</h1>',
        null,
        undefined,
        '',
        'not-a-valid-url'
    ];

    for (const url of restrictedUrls) {
        assert.equal(getSiteConfig(url), null);
        assert.equal(isSupportedUrl(url), false);
    }
});
