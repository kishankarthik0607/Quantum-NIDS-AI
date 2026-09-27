/**
 * Quantum NIDS Browser Guard - Centralized Security Allowlists & Pattern Configuration
 * Configurable rules for false positive control, sensitive data protection, and attribution monitoring.
 */

// CDNs commonly used by legitimate e-commerce retailers
export const ALLOWED_CDNS = [
    'images-amazon.com',
    'ssl-images-amazon.com',
    'media-amazon.com',
    'ebayimg.com',
    'ebayrtm.com',
    'wal.co',
    'walmartimages.com',
    'targetimg1.com',
    'target.scene7.com',
    'bbystatic.com',
    'bestbuy.com',
    'cloudflare.com',
    'cdnjs.cloudflare.com',
    'cdn.jsdelivr.net',
    'unpkg.com',
    'akamaihd.net',
    'akamaized.net',
    'edgekey.net',
    'edgesuite.net',
    'fastly.net',
    'fastlylb.net',
    'cloudfront.net',
    'aws.amazon.com',
    'gstatic.com',
    'googleapis.com',
    'googleusercontent.com',
    'yimg.com',
    'apple-dns.net',
    'cdn-apple.com'
];

// Legitimate analytics, telemetry, and tag management services
export const ALLOWED_ANALYTICS = [
    'google-analytics.com',
    'googletagmanager.com',
    'analytics.google.com',
    'hotjar.com',
    'hotjar.io',
    'segment.com',
    'segment.io',
    'newrelic.com',
    'nr-data.net',
    'datadoghq.com',
    'criteo.com',
    'criteo.net',
    'bing.com',
    'bat.bing.com',
    'clarity.ms',
    'optimizely.com',
    'adroll.com'
];

// Legitimate payment processors and checkout infrastructure
export const ALLOWED_PAYMENTS = [
    'stripe.com',
    'js.stripe.com',
    'm.stripe.network',
    'paypal.com',
    'paypalobjects.com',
    'adyen.com',
    'braintreegateway.com',
    'braintree-api.com',
    'checkout.com',
    'klarna.com',
    'klarnacdn.net',
    'squareupsandbox.com',
    'squareup.com',
    'visa.com',
    'mastercard.com',
    'americanexpress.com',
    'applepay.cdn-apple.com'
];

// Legitimate affiliate and referral networks
export const ALLOWED_AFFILIATE_NETWORKS = [
    'cj.com',
    'commission-junction.com',
    'anrdoezrs.net',
    'dpbolvw.net',
    'jdoqocy.com',
    'tkqlhce.com',
    'rakuten.com',
    'linksynergy.com',
    'impact.com',
    'impactradius.com',
    'shareasale.com',
    'awin1.com',
    'zenaps.com',
    'pepperjam.com',
    'skimresources.com',
    'viglink.com'
];

// Patterns identifying sensitive cookies that MUST NEVER expose raw values in UI/logs
export const SENSITIVE_COOKIE_PATTERNS = [
    'session',
    'auth',
    'token',
    'jwt',
    'sid',
    'login',
    'password',
    'passwd',
    'secret',
    'key',
    'credential',
    'csrf',
    'xsrf',
    'card',
    'cvv',
    'account'
];

// Known affiliate, partner, campaign, and attribution tracking parameters/cookie names
export const ATTRIBUTION_COOKIE_NAMES = [
    'tag',
    'aff_id',
    'affiliate_id',
    'ref',
    'referrer',
    'click_id',
    'clickid',
    'irclickid',
    'gclid',
    'fbclid',
    'msclkid',
    'partner',
    'partner_id',
    'campaign',
    'campaign_id',
    'utm_campaign',
    'utm_source',
    'utm_medium',
    'utm_content',
    'amzn_assoc',
    'ebay_campid',
    'cj_event',
    'awin_mid',
    'rakuten_id',
    'subid',
    'subid1',
    'subid2',
    'aff_sub',
    'tracking_id',
    'assoc_tag'
];

// Known suspicious script hosting or tunneling patterns
export const SUSPICIOUS_SCRIPT_PATTERNS = [
    'bit.ly',
    'ngrok.io',
    'ngrok-free.app',
    'localtunnel.me',
    'pagekite.me',
    'serveo.net',
    'pastebin.com',
    'hastebin.com',
    'raw.githubusercontent.com',
    'anonfiles.com',
    'tempfile.io'
];

// Helper to check if a hostname is covered by allowlists
export function isAllowlistedDomain(hostname, siteSpecificAllowed = []) {
    if (!hostname) return false;
    const lowerHost = hostname.toLowerCase();

    const matchesList = (list) => list.some(allowed => 
        lowerHost === allowed.toLowerCase() || 
        lowerHost.endsWith('.' + allowed.toLowerCase())
    );

    return (
        matchesList(siteSpecificAllowed) ||
        matchesList(ALLOWED_CDNS) ||
        matchesList(ALLOWED_ANALYTICS) ||
        matchesList(ALLOWED_PAYMENTS) ||
        matchesList(ALLOWED_AFFILIATE_NETWORKS)
    );
}

// Helper to check if a cookie name is security-sensitive
export function isSensitiveCookieName(cookieName) {
    if (!cookieName) return false;
    const lowerName = cookieName.toLowerCase();
    return SENSITIVE_COOKIE_PATTERNS.some(pattern => lowerName.includes(pattern));
}

// Helper to check if a cookie name is an attribution/referral indicator
export function isAttributionCookieName(cookieName) {
    if (!cookieName) return false;
    const lowerName = cookieName.toLowerCase();
    return ATTRIBUTION_COOKIE_NAMES.some(name => lowerName === name || lowerName.includes(name));
}
