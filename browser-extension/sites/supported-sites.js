/**
 * Quantum NIDS Browser Guard - Supported Retail & E-Commerce Websites
 * 
 * Provides validated domain resolution for 110+ major retail and e-commerce platforms.
 * Preserves existing architecture while hardening domain matching against lookalike,
 * typosquatting, and subdomain-spoofing attacks.
 */

import { ALLOWED_CDNS, ALLOWED_ANALYTICS, ALLOWED_PAYMENTS } from '../config/allowlists.js';

// Base list of 110 supported retail & e-commerce brands
export const majorEcommerceDomains = [
    "amazon", "ebay", "walmart", "target", "bestbuy", "homedepot", "lowes", "costco", "macys", "wayfair",
    "apple", "samsung", "nike", "adidas", "zappos", "etsy", "shein", "asos", "zalando", "rakuten",
    "flipkart", "myntra", "meesho", "ajio", "snapdeal", "alibaba", "aliexpress", "taobao", "jd", "pinduoduo",
    "shopee", "lazada", "tokopedia", "bukalapak", "blibli", "coupang", "gmarket", "11st", "mercado-libre", "b2w",
    "magalu", "americanas", "submarino", "carrefour", "tesco", "sainsburys", "asda", "morrisons", "waitrose", "ocado",
    "aldi", "lidl", "kroger", "walgreens", "cvs", "riteaid", "sephora", "ulta", "nordstrom", "bloomingdales",
    "neimanmarcus", "saksfifthavenue", "jcpenney", "kohls", "sears", "kmart", "ikea", "potterybarn", "crateandbarrel", "westelm",
    "williams-sonoma", "cb2", "restorationhardware", "ashleyfurniture", "raymourflanigan", "roomsdtogo", "havertys", "bobsdiscountfurniture", "mattressfirm", "sleepnumber",
    "tempurpedic", "casper", "purple", "nectarsleep", "tuftandneedle", "saatva", "leesa", "helixsleep", "avocadogreenmattress", "dreamcloudsleep",
    "bearmattress", "brooklinen", "parachutehome", "bollandbranch", "snowe", "coyuchi", "frette", "sferra", "matouk", "peacockalley",
    "gamestop", "newegg", "bhphotovideo", "adorama", "microcenter", "sweetwater", "guitarcenter", "musiciansfriend", "samash", "zzounds"
];

// Brand aliases, specific domains, and international domain configurations
const BRAND_DOMAIN_MAP = {
    "amazon": { slds: ["amazon"], customDomains: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazon.co.jp", "amazon.ca", "amazon.fr", "amazon.es", "amazon.it", "amazon.com.au", "amazon.com.br", "amazon.nl", "amazon.sg", "amazon.ae", "amazon.sa"], allowedThirdParty: ["images-amazon.com", "ssl-images-amazon.com", "media-amazon.com", "assoc-amazon.com"] },
    "ebay": { slds: ["ebay"], customDomains: ["ebay.com", "ebay.co.uk", "ebay.de", "ebay.com.au", "ebay.ca", "ebay.fr", "ebay.it", "ebay.es", "ebay.in"], allowedThirdParty: ["ebayimg.com", "ebayrtm.com", "ebaystatic.com"] },
    "walmart": { slds: ["walmart"], customDomains: ["walmart.com", "walmart.ca"], allowedThirdParty: ["wal.co", "walmartimages.com"] },
    "target": { slds: ["target"], customDomains: ["target.com"], allowedThirdParty: ["targetimg1.com", "target.scene7.com"] },
    "bestbuy": { slds: ["bestbuy"], customDomains: ["bestbuy.com", "bestbuy.ca"], allowedThirdParty: ["bbystatic.com"] },
    "apple": { slds: ["apple"], customDomains: ["apple.com"], allowedThirdParty: ["apple-dns.net", "cdn-apple.com"] },
    "jd": { slds: ["jd", "joybuy"], customDomains: ["jd.com", "joybuy.com"], allowedThirdParty: ["jdcache.com", "360buyimg.com"] },
    "11st": { slds: ["11st"], customDomains: ["11st.co.kr"], allowedThirdParty: ["11ststatic.com"] },
    "gmarket": { slds: ["gmarket"], customDomains: ["gmarket.co.kr"], allowedThirdParty: [] },
    "coupang": { slds: ["coupang"], customDomains: ["coupang.com"], allowedThirdParty: ["coupangcdn.com"] },
    "mercado-libre": { slds: ["mercadolibre", "mercadolivre"], customDomains: ["mercadolibre.com", "mercadolivre.com.br", "mercadolibre.com.ar", "mercadolibre.cl", "mercadolibre.com.mx"], allowedThirdParty: ["mlstatic.com"] },
    "b2w": { slds: ["b2w", "b2wdigital"], customDomains: ["b2w.digital", "b2wdigital.com"], allowedThirdParty: [] },
    "magalu": { slds: ["magalu", "magazineluiza"], customDomains: ["magazineluiza.com.br", "magalu.com"], allowedThirdParty: ["luizalabs.com"] },
    "americanas": { slds: ["americanas"], customDomains: ["americanas.com.br"], allowedThirdParty: [] },
    "submarino": { slds: ["submarino"], customDomains: ["submarino.com.br"], allowedThirdParty: [] },
    "roomsdtogo": { slds: ["roomstogo", "roomsdtogo"], customDomains: ["roomstogo.com", "roomsdtogo.com"], allowedThirdParty: [] },
    "williams-sonoma": { slds: ["williams-sonoma"], customDomains: ["williams-sonoma.com"], allowedThirdParty: [] },
    "bobsdiscountfurniture": { slds: ["bobsdiscountfurniture", "mybobs"], customDomains: ["mybobs.com", "bobsdiscountfurniture.com"], allowedThirdParty: [] },
    "snowe": { slds: ["snowe", "snowehome"], customDomains: ["snowehome.com", "snowe.com"], allowedThirdParty: [] },
    "restorationhardware": { slds: ["restorationhardware", "rh"], customDomains: ["restorationhardware.com", "rh.com"], allowedThirdParty: [] },
    "shopee": { slds: ["shopee"], customDomains: ["shopee.com", "shopee.sg", "shopee.co.id", "shopee.ph", "shopee.tw", "shopee.com.my", "shopee.vn", "shopee.com.br"], allowedThirdParty: ["shopeesz.com"] },
    "lazada": { slds: ["lazada"], customDomains: ["lazada.com", "lazada.sg", "lazada.co.id", "lazada.com.ph", "lazada.com.my", "lazada.vn", "lazada.co.th"], allowedThirdParty: ["alicdn.com"] },
    "alibaba": { slds: ["alibaba"], customDomains: ["alibaba.com"], allowedThirdParty: ["alicdn.com", "alipayobjects.com"] },
    "aliexpress": { slds: ["aliexpress"], customDomains: ["aliexpress.com"], allowedThirdParty: ["alicdn.com"] },
    "rakuten": { slds: ["rakuten"], customDomains: ["rakuten.com", "rakuten.co.jp"], allowedThirdParty: ["rakuten-static.com"] },
    "zalando": { slds: ["zalando"], customDomains: ["zalando.com", "zalando.de", "zalando.co.uk", "zalando.fr", "zalando.it", "zalando.es"], allowedThirdParty: [] },
    "asda": { slds: ["asda"], customDomains: ["asda.com"], allowedThirdParty: ["asda.media"] },
    "aldi": { slds: ["aldi"], customDomains: ["aldi.com", "aldi.co.uk", "aldi.us", "aldi.de"], allowedThirdParty: [] },
    "lidl": { slds: ["lidl"], customDomains: ["lidl.com", "lidl.co.uk", "lidl.de"], allowedThirdParty: [] },
    "carrefour": { slds: ["carrefour"], customDomains: ["carrefour.com", "carrefour.fr", "carrefour.es", "carrefour.com.br"], allowedThirdParty: [] },
    "sephora": { slds: ["sephora"], customDomains: ["sephora.com", "sephora.fr"], allowedThirdParty: [] },
    "nordstrom": { slds: ["nordstrom", "nordstromrack"], customDomains: ["nordstrom.com", "nordstromrack.com"], allowedThirdParty: [] },
    "kmart": { slds: ["kmart"], customDomains: ["kmart.com", "kmart.com.au"], allowedThirdParty: [] }
};

// Known multi-part public suffixes for accurate eTLD+1 extraction
const MULTI_PART_SUFFIXES = new Set([
    'co.uk', 'org.uk', 'gov.uk', 'me.uk', 'ltd.uk',
    'co.jp', 'ne.jp', 'or.jp',
    'co.kr', 'or.kr',
    'com.au', 'net.au', 'org.au',
    'com.br', 'org.br', 'net.br',
    'com.mx', 'org.mx',
    'com.ar',
    'co.id', 'web.id',
    'co.th',
    'com.my',
    'com.sg',
    'co.nz',
    'co.za',
    'com.tr',
    'com.tw'
]);

/**
 * Parses a hostname into its root domain and second-level domain (SLD) label.
 * Example: 'smile.amazon.co.uk' -> { rootDomain: 'amazon.co.uk', sld: 'amazon', publicSuffix: 'co.uk' }
 * Example: 'checkout.walmart.com' -> { rootDomain: 'walmart.com', sld: 'walmart', publicSuffix: 'com' }
 */
export function extractDomainParts(hostname) {
    if (!hostname || typeof hostname !== 'string') return null;
    
    // Normalize: lowercase, trim, remove trailing dot, strip leading www.
    let cleanHost = hostname.toLowerCase().trim().replace(/\.$/, '');
    if (cleanHost.startsWith('www.')) {
        cleanHost = cleanHost.slice(4);
    }
    
    const parts = cleanHost.split('.');
    if (parts.length < 2) return null;
    
    // Check if the last two parts form a multi-part suffix (e.g. co.uk)
    let publicSuffix = '';
    let sld = '';
    let rootDomain = '';
    
    if (parts.length >= 3) {
        const potentialTwoPartSuffix = parts.slice(-2).join('.');
        if (MULTI_PART_SUFFIXES.has(potentialTwoPartSuffix)) {
            publicSuffix = potentialTwoPartSuffix;
            sld = parts[parts.length - 3];
            rootDomain = `${sld}.${publicSuffix}`;
            return { hostname: cleanHost, rootDomain, sld, publicSuffix };
        }
    }
    
    // Single-part suffix (e.g. com, net, org, de, in)
    publicSuffix = parts[parts.length - 1];
    sld = parts[parts.length - 2];
    rootDomain = `${sld}.${publicSuffix}`;
    
    return { hostname: cleanHost, rootDomain, sld, publicSuffix };
}

/**
 * Builds the centralized list of supported sites with full backward compatibility.
 */
export const SUPPORTED_SITES = majorEcommerceDomains.map(brand => {
    const brandMeta = BRAND_DOMAIN_MAP[brand] || {};
    const slds = brandMeta.slds || [brand.toLowerCase()];
    const customDomains = brandMeta.customDomains || [`${brand.toLowerCase()}.com`];
    const allowedThirdParty = brandMeta.allowedThirdParty || [];

    return {
        domain: brand,
        brandName: brand.charAt(0).toUpperCase() + brand.slice(1),
        category: "ecommerce",
        enabled: true,
        monitoringLevel: "high",
        allowedThirdPartyDomains: allowedThirdParty,
        primarySlds: slds,
        knownDomains: customDomains,
        cookieRules: { maxChangesPerMinute: 10 },
        riskRules: { blockHiddenRedirects: true }
    };
});

/**
 * Safely resolves a URL to its supported site configuration.
 * Hardened to prevent false-positive matches on lookalike/phishing domains.
 * 
 * @param {string|URL} url - URL string or object
 * @returns {object|null} Matched site config or null if unsupported
 */
export function getSiteConfig(url) {
    if (!url) return null;
    try {
        const parsed = typeof url === 'string' ? new URL(url) : url;
        
        // Only http and https protocols are supported web sessions
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            return null;
        }

        const domainInfo = extractDomainParts(parsed.hostname);
        if (!domainInfo) return null;

        const { sld, rootDomain, hostname } = domainInfo;

        // Find matching site config where:
        // 1. Hostname exactly matches or is a subdomain of a known domain for the brand, OR
        // 2. The extracted SLD matches the brand's authorized SLD list exactly
        const matched = SUPPORTED_SITES.find(site => {
            // Check direct known domains first (e.g. amazon.com, amazon.co.uk)
            const hasExactDomainMatch = site.knownDomains.some(known => 
                hostname === known || hostname.endsWith('.' + known)
            );
            if (hasExactDomainMatch) return true;

            // Check SLD exact match (e.g. sld === 'amazon')
            if (site.primarySlds.includes(sld)) {
                return true;
            }

            return false;
        });

        return matched || null;
    } catch {
        return null;
    }
}

/**
 * Returns true if the URL belongs to a supported e-commerce site.
 */
export function isSupportedUrl(url) {
    return getSiteConfig(url) !== null;
}

/**
 * Returns the canonical brand key or domain for the URL.
 */
export function getCanonicalDomain(url) {
    const config = getSiteConfig(url);
    return config ? config.domain : null;
}
