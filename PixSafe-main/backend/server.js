/**
 * PixSafe Backend — server.js
 * Pure JS threat scanner. No external APIs. No AI dependency.
 * Run: node server.js
 * Requires: npm install express cors
 */

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '25mb' }));

// ─────────────────────────────────────────────
//  THREAT DATABASE
// ─────────────────────────────────────────────

const WHITELIST_DOMAINS = new Set([
    'google.com', 'github.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'youtube.com', 'wikipedia.org', 'linkedin.com',
    'stackoverflow.com', 'twitter.com', 'x.com', 'reddit.com',
    'anthropic.com', 'cloudflare.com', 'mozilla.org', 'npmjs.com',
    'edu.in', 'gov.in', 'ac.in', 'nic.in', 'gov.uk', 'gov.us',
]);

const BLACKLIST_DOMAINS = new Set([
    'malware-test.com', 'login-verify-secure.net', 'get-free-robux.biz',
    'free-gift-cards.ru', 'win-iphone-now.xyz', 'verify-account-now.tk',
    'secure-login-update.com', 'account-verify.ml', 'banking-secure.xyz',
    'paypal-verify-login.com', 'amazon-gift-claim.xyz', 'netflix-login.tk',
    'apple-id-locked.ml', 'google-security-alert.biz',
]);

// Points → keyword map
const SUSPICIOUS_KEYWORDS = {
    login: 22, verify: 22, account: 18, banking: 28, secure: 15,
    update: 15, confirm: 18, authenticate: 20, credential: 24,
    password: 24, wallet: 18, 'crypto-wallet': 20, 'reset-password': 22,
    free: 12, prize: 16, winner: 16, click: 10, urgent: 20, alert: 14,
    suspended: 22, limited: 10, exclusive: 8, otp: 20, kyc: 20,
    recover: 16, unlock: 16, blocked: 18, 'verify-now': 25,
    support: 5, help: 3, service: 3,
};

const RISKY_TLDS = new Set([
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.ru', '.biz', '.info',
    '.top', '.click', '.download', '.zip', '.link', '.work', '.pw',
    '.icu', '.monster', '.rest', '.uno', '.beauty', '.hair', '.skin',
]);

const TRUSTED_BRANDS = [
    'google', 'facebook', 'microsoft', 'apple', 'amazon', 'paypal',
    'netflix', 'instagram', 'twitter', 'linkedin', 'youtube', 'github',
    'whatsapp', 'telegram', 'snapchat', 'tiktok', 'spotify', 'uber',
    'airbnb', 'dropbox', 'slack', 'zoom', 'adobe', 'oracle', 'sbi',
    'hdfc', 'icici', 'phonepe', 'paytm', 'gpay',
];

// ─────────────────────────────────────────────
//  UTILITY — URL helpers
// ─────────────────────────────────────────────

function safeParseURL(raw) {
    try {
        if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
        return new URL(raw);
    } catch { return null; }
}

function shannonEntropy(str) {
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    return Object.values(freq).reduce((h, n) => {
        const p = n / str.length;
        return h - p * Math.log2(p);
    }, 0);
}

function levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, (_, i) =>
        Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0));
    for (let i = 1; i <= m; i++)
        for (let j = 1; j <= n; j++)
            dp[i][j] = a[i - 1] === b[j - 1]
                ? dp[i - 1][j - 1]
                : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    return dp[m][n];
}

function detectTyposquatting(hostname) {
    const stripped = hostname.replace(/\.(com|net|org|io|co|in|biz|info|xyz|tk|ml)$/, '');
    for (const brand of TRUSTED_BRANDS) {
        const d = levenshtein(stripped, brand);
        if (d > 0 && d <= 2 && stripped !== brand) return brand;
    }
    return null;
}

function isIPv4(host) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

function countSubdomains(hostname) {
    return hostname.split('.').slice(0, -2).length;
}

// Check for brand name embedded in subdomain but not as root domain
// e.g. paypal.login-secure.xyz → paypal in subdomain, root is login-secure.xyz
function checkBrandInSubdomain(parsed) {
    const root = parsed.hostname.split('.').slice(-2).join('.');
    const sub = parsed.hostname.replace(root, '').replace(/\.$/, '').toLowerCase();
    for (const brand of TRUSTED_BRANDS) {
        if (sub.includes(brand) && !root.startsWith(brand)) return brand;
    }
    return null;
}

function hasRedirectParam(url) {
    const u = url.toLowerCase();
    return u.includes('redirect=') || u.includes('url=') || u.includes('goto=') || u.includes('return=') || u.includes('next=');
}

function hasExecutableExtension(pathname) {
    return /\.(exe|zip|bat|sh|cmd|ps1|jar|apk|vbs|dll|msi|dmg|deb|rpm)\b/i.test(pathname);
}

// Detect data URI abuse or JS injection fragments
function hasCodeInjectionPatterns(url) {
    const lower = url.toLowerCase();
    return lower.includes('javascript:')
        || lower.includes('data:text/html')
        || lower.includes('<script')
        || lower.includes('vbscript:')
        || lower.includes('%3cscript');
}

// ─────────────────────────────────────────────
//  URL SCORING ENGINE
// ─────────────────────────────────────────────

function analyzeURL(rawUrl) {
    const parsed = safeParseURL(rawUrl);

    if (!parsed) {
        return {
            verdict: 'DANGER',
            score: 85,
            reasons: ['[CRITICAL] URL could not be parsed — malformed or invalid.'],
            details: [{ label: 'Unparseable URL', severity: 'critical', points: 85 }],
        };
    }

    const hostname = parsed.hostname.toLowerCase();
    const fullUrl = rawUrl.toLowerCase();
    const pathname = parsed.pathname.toLowerCase();
    const tld = '.' + hostname.split('.').slice(-1)[0];
    const root = hostname.split('.').slice(-2).join('.');

    // ── Whitelist ─────────────────────────────
    if (WHITELIST_DOMAINS.has(root)) {
        return {
            verdict: 'SAFE',
            score: 2,
            reasons: ['[SAFE] Domain is on the verified trusted whitelist.'],
            details: [{ label: 'Trusted Whitelist Domain', severity: 'safe', points: 0 }],
        };
    }

    // ── Blacklist ─────────────────────────────
    if (BLACKLIST_DOMAINS.has(hostname) || BLACKLIST_DOMAINS.has(root)) {
        return {
            verdict: 'DANGER',
            score: 99,
            reasons: ['[CRITICAL] Domain matches known phishing / malware blacklist.'],
            details: [{ label: 'Blacklisted Domain', severity: 'critical', points: 99 }],
        };
    }

    let score = 0;
    const details = [];

    const add = (label, pts, severity) => {
        score += pts;
        details.push({ label, severity, points: pts });
    };

    // Protocol
    if (parsed.protocol === 'http:') add('No HTTPS (unencrypted connection)', 15, 'high');

    // Risky TLD
    if (RISKY_TLDS.has(tld)) add(`High-risk TLD: ${tld}`, 22, 'high');

    // Subdomains
    const subCount = countSubdomains(hostname);
    if (subCount >= 4) add(`Extreme subdomain depth (${subCount})`, 24, 'high');
    else if (subCount === 3) add(`Excessive subdomain depth (${subCount})`, 14, 'medium');

    // Typosquatting root domain
    const typoTarget = detectTyposquatting(root.split('.')[0]);
    if (typoTarget) add(`Typosquatting — impersonates "${typoTarget}"`, 38, 'critical');

    // Brand in subdomain trick (e.g. paypal.fakeSite.xyz)
    const brandSub = checkBrandInSubdomain(parsed);
    if (brandSub) add(`Brand "${brandSub}" in subdomain — deceptive hostname`, 30, 'critical');

    // Entropy
    const ent = shannonEntropy(hostname.replace(/\./g, ''));
    if (ent > 4.2) add(`Very high hostname entropy (${ent.toFixed(2)}) — looks machine-generated`, 20, 'high');
    else if (ent > 3.5) add(`Moderate hostname entropy (${ent.toFixed(2)})`, 8, 'low');

    // URL length
    if (rawUrl.length > 200) add(`Extremely long URL (${rawUrl.length} chars)`, 20, 'medium');
    else if (rawUrl.length > 100) add(`Long URL (${rawUrl.length} chars)`, Math.min(Math.floor((rawUrl.length - 100) / 20) * 5, 15), 'low');

    // Encoded chars
    const encoded = (fullUrl.match(/%[0-9a-f]{2}/gi) || []).length;
    if (encoded > 5) add(`Heavy encoding (${encoded} encoded chars) — obfuscation likely`, Math.min(encoded * 4, 20), 'high');
    else if (encoded > 2) add(`URL encoding present (${encoded} chars)`, encoded * 2, 'low');

    // IP as host
    if (isIPv4(hostname)) add('IP address as hostname — no domain registration needed', 28, 'high');

    // Punycode
    if (hostname.includes('xn--')) add('Punycode domain — possible homograph/lookalike attack', 22, 'high');

    // JS / code injection patterns
    if (hasCodeInjectionPatterns(rawUrl)) add('Code injection pattern detected in URL', 35, 'critical');

    // Suspicious keywords
    for (const [word, pts] of Object.entries(SUSPICIOUS_KEYWORDS)) {
        if (fullUrl.includes(word)) {
            const sev = pts >= 20 ? 'high' : pts >= 12 ? 'medium' : 'low';
            add(`Suspicious keyword: "${word}"`, pts, sev);
        }
    }

    // Executable extension in path
    if (hasExecutableExtension(pathname)) add('Executable file extension in URL path', 28, 'critical');

    // Open redirect
    if (hasRedirectParam(rawUrl)) add('Open redirect parameter detected', 16, 'medium');

    // Lots of query params (obfuscation)
    const paramCount = [...parsed.searchParams].length;
    if (paramCount > 6) add(`Many query parameters (${paramCount}) — possible tracking/obfuscation`, 10, 'low');

    // Numeric looking domain (e.g. 192abc.com)
    if (/^\d+[a-z]/.test(root.split('.')[0])) add('Numeric-looking domain prefix — often used in scams', 10, 'medium');

    if (details.length === 0) details.push({ label: 'No suspicious patterns detected', severity: 'safe', points: 0 });

    const finalScore = Math.min(Math.round(score), 100);
    // const verdict = finalScore >= 45 ? 'DANGER' : 'SAFE';
    const hasCritical = details.some(d => d.severity === 'critical');
    const verdict = hasCritical || finalScore >= 45 ? 'DANGER' : 'SAFE';

    const reasons = details
        .sort((a, b) => b.points - a.points)
        .map(d => `[${d.severity.toUpperCase()}] ${d.label} (+${d.points})`);

    return { verdict, score: finalScore, reasons, details };
}

// ─────────────────────────────────────────────
//  IMAGE ANALYSIS ENGINE  (no AI, pure heuristics)
// ─────────────────────────────────────────────

// ── Pixel-level scanners ─────────────────────

/**
 * Detect suspicious steganography-like characteristics.
 * Looks at the LSB (least significant bit) distribution of
 * the raw base64-decoded bytes. Genuine photos have roughly
 * uniform LSB distribution; steganographic payloads skew it.
 */
function analyzeLSBEntropy(buffer) {
    // Sample up to 20 000 bytes for speed
    const sample = buffer.slice(0, 20000);
    let lsbOnes = 0;
    for (const byte of sample) lsbOnes += byte & 1;
    const ratio = lsbOnes / sample.length;
    // True uniform = 0.5 ± 0.02. Very far from 0.5 is suspicious.
    const deviation = Math.abs(ratio - 0.5);
    return { ratio, deviation };
}

/**
 * Detect hidden appended data after JPEG/PNG end-of-file markers.
 * Data after the JPEG EOI (0xFF 0xD9) or PNG IEND chunk is a
 * classic technique to hide payloads inside innocent images.
 */
function detectAppendedData(buffer) {
    // JPEG: ends with FF D9
    const jpegEOI = Buffer.from([0xFF, 0xD9]);
    const jpegIdx = buffer.lastIndexOf(jpegEOI[0]);
    if (jpegIdx > 0 && buffer[jpegIdx + 1] === jpegEOI[1]) {
        const trailing = buffer.length - (jpegIdx + 2);
        if (trailing > 512) return { found: true, bytes: trailing, type: 'JPEG' };
    }
    // PNG: ends with IEND chunk (89 50 4E 47 ... 49 45 4E 44 AE 42 60 82)
    const pngEnd = Buffer.from([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);
    const pngIdx = buffer.indexOf(pngEnd);
    if (pngIdx > 0) {
        const trailing = buffer.length - (pngIdx + 8);
        if (trailing > 256) return { found: true, bytes: trailing, type: 'PNG' };
    }
    return { found: false };
}

/**
 * Scan raw bytes for embedded URLs or suspicious strings.
 * Phishing kits sometimes embed URLs in image EXIF data or
 * appended bytes.
 */
function scanBytesForURLs(buffer) {
    const text = buffer.toString('latin1');
    const urlPattern = /https?:\/\/[^\s\x00-\x1F"'<>]{8,}/gi;
    const matches = text.match(urlPattern) || [];
    // Filter to unique
    const unique = [...new Set(matches)].slice(0, 10);
    return unique;
}

/**
 * Check EXIF-like markers in JPEG for suspicious metadata.
 * Looks for APP1 (EXIF) and APP13 (IPTC) markers.
 */
function detectSuspiciousEXIF(buffer, mimeType) {
    if (mimeType !== 'image/jpeg' && mimeType !== 'image/jpg') return { found: false };
    // EXIF marker: FF E1 followed by "Exif" or "http"
    const findings = [];
    for (let i = 0; i < Math.min(buffer.length - 4, 65536); i++) {
        if (buffer[i] === 0xFF && buffer[i + 1] === 0xE1) {
            // APP1 segment
            const segLen = (buffer[i + 2] << 8) | buffer[i + 3];
            const seg = buffer.slice(i + 4, i + 4 + Math.min(segLen, 4096)).toString('latin1');
            if (/http/i.test(seg)) findings.push('HTTP URL found inside EXIF metadata');
            if (/script/i.test(seg)) findings.push('Script tag found inside EXIF metadata — injection attempt');
            if (/eval\s*\(/i.test(seg)) findings.push('eval() found inside EXIF — malicious JS payload');
        }
    }
    return { found: findings.length > 0, details: findings };
}

/**
 * Detect pixel tracker patterns: tiny 1x1 or very small images
 * used for covert tracking.
 */
function detectPixelTracker(fileSize, mimeType) {
    // GIF87a / GIF89a 1x1 pixel is 35 bytes
    // PNG 1x1 px is ~68 bytes
    // JPEG 1x1 px is ~632 bytes
    if (fileSize < 700) {
        return { likely: true, reason: `Extremely small image (${fileSize} bytes) — classic pixel tracker dimensions` };
    }
    if (fileSize < 2000 && mimeType === 'image/gif') {
        return { likely: true, reason: `Tiny GIF (${fileSize} bytes) — likely a tracking pixel` };
    }
    return { likely: false };
}

/**
 * Compute file hash for integrity / known-bad-hash lookup.
 * In a production system you'd compare against a threat DB.
 */
function computeFileHash(buffer) {
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

/**
 * Check MIME type vs actual file magic bytes (polyglot detection).
 * A JPEG claiming to be a PNG, or an EXE claiming to be a JPEG,
 * is a classic polyglot attack.
 */
function detectMIMEMismatch(buffer, declaredMime) {
    const magic = buffer.slice(0, 8);
    const signatures = {
        'image/jpeg': [
            b => b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF,
        ],
        'image/png': [
            b => b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47,
        ],
        'image/gif': [
            b => b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46,
        ],
        'image/webp': [
            b => b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50,
        ],
    };

    // Executable magic bytes
    const exeMagics = [
        { sig: [0x4D, 0x5A], name: 'Windows PE/EXE' },
        { sig: [0x7F, 0x45, 0x4C, 0x46], name: 'Linux ELF executable' },
        { sig: [0x50, 0x4B, 0x03, 0x04], name: 'ZIP archive (possible JAR/APK)' },
        { sig: [0xCA, 0xFE, 0xBA, 0xBE], name: 'Java class file' },
        { sig: [0x23, 0x21], name: 'Shell script (#!)' },
        { sig: [0xD0, 0xCF, 0x11, 0xE0], name: 'MS Office / OLE document' },
        { sig: [0x25, 0x50, 0x44, 0x46], name: 'PDF document' },
    ];

    for (const exe of exeMagics) {
        const matches = exe.sig.every((b, i) => magic[i] === b);
        if (matches) return { mismatch: true, reason: `File is actually a ${exe.name} disguised as an image` };
    }

    const checks = signatures[declaredMime];
    if (checks && !checks.some(fn => fn(magic))) {
        return { mismatch: true, reason: `File magic bytes do not match declared MIME type (${declaredMime})` };
    }

    return { mismatch: false };
}

/**
 * Calculate overall file entropy. Encrypted / compressed payloads
 * have high entropy (~7.9-8.0 bits/byte). Normal images are lower.
 */
function fileEntropy(buffer) {
    const sample = buffer.slice(0, 50000);
    const freq = new Array(256).fill(0);
    for (const b of sample) freq[b]++;
    return freq.reduce((h, n) => {
        if (n === 0) return h;
        const p = n / sample.length;
        return h - p * Math.log2(p);
    }, 0);
}

// ─────────────────────────────────────────────
//  IMAGE SCAN ORCHESTRATOR
// ─────────────────────────────────────────────

function analyzeImage({ fileName, fileSize, base64Image, mimeType }) {
    let score = 0;
    const details = [];

    const add = (label, pts, severity) => {
        score += pts;
        details.push({ label, severity, points: pts });
    };

    // ── Layer 1 : Filename heuristics ──────────
    const lname = (fileName || '').toLowerCase();

    const DANGER_NAMES = ['virus', 'malware', 'trojan', 'hack', 'exploit', 'payload', 'keylog', 'ransomware', 'rootkit'];
    const SCAM_NAMES = ['invoice', 'bank', 'receipt', 'kyc', 'aadhaar', 'pan_card', 'passport', 'otp', 'bankstatement', 'tax'];
    const WARN_NAMES = ['free', 'prize', 'winner', 'claim', 'urgent', 'alert', 'reward', 'congratulations'];

    if (DANGER_NAMES.some(k => lname.includes(k))) add('Filename matches known malware signature pattern', 60, 'critical');
    if (SCAM_NAMES.some(k => lname.includes(k))) add('Filename suggests sensitive document — social engineering risk', 40, 'high');
    if (WARN_NAMES.some(k => lname.includes(k))) add('Filename contains common scam bait keywords', 20, 'medium');

    // Double extension
    if (/\.(exe|bat|sh|js|php|cmd|ps1|vbs|dll)\.(png|jpg|jpeg|gif|webp)$/i.test(fileName || ''))
        add('Double extension — file masquerading as image', 55, 'critical');

    // Suspicious extension disguise
    if (/\.jpg\.zip$|\.png\.rar$|\.gif\.7z$/i.test(fileName || ''))
        add('Image extension followed by archive extension — hidden payload', 50, 'critical');

    // ── Layer 2 : Deep binary analysis ─────────
    if (base64Image) {
        const buffer = Buffer.from(base64Image, 'base64');

        // MIME mismatch
        const mimeCheck = detectMIMEMismatch(buffer, mimeType || '');
        if (mimeCheck.mismatch) add(mimeCheck.reason, 55, 'critical');

        // Appended data
        const appended = detectAppendedData(buffer);
        if (appended.found) add(`Hidden data appended after ${appended.type} EOF marker (${appended.bytes.toLocaleString()} bytes)`, 40, 'critical');

        // EXIF metadata abuse
        const exif = detectSuspiciousEXIF(buffer, mimeType);
        if (exif.found) exif.details.forEach(d => add(d, 30, 'critical'));

        // Embedded URLs in binary
        const embeddedURLs = scanBytesForURLs(buffer);
        if (embeddedURLs.length > 0) {
            add(`${embeddedURLs.length} URL(s) embedded in image binary data`, 25, 'high');
            // Also score each embedded URL and take the worst
            const urlScores = embeddedURLs.map(u => analyzeURL(u));
            const worst = urlScores.sort((a, b) => b.score - a.score)[0];
            if (worst && worst.score > 30) {
                add(`Embedded URL threat score: ${worst.score}/100 — "${worst.verdict}"`, Math.round(worst.score * 0.4), 'high');
            }
        }

        // File entropy (encrypted payload)
        const entBits = fileEntropy(buffer);
        if (entBits > 7.8) add(`Extremely high file entropy (${entBits.toFixed(2)} bits/byte) — likely encrypted payload`, 35, 'critical');
        else if (entBits > 7.5) add(`High file entropy (${entBits.toFixed(2)} bits/byte) — possible obfuscated content`, 18, 'high');

        // LSB steganography
        const lsb = analyzeLSBEntropy(buffer);
        if (lsb.deviation > 0.08) add(`Highly irregular LSB distribution (deviation ${lsb.deviation.toFixed(3)}) — steganography likely`, 28, 'high');
        else if (lsb.deviation > 0.04) add(`Slightly irregular LSB distribution — possible stego`, 10, 'medium');

        // Pixel tracker
        const tracker = detectPixelTracker(fileSize || buffer.length, mimeType);
        if (tracker.likely) add(tracker.reason, 18, 'medium');

        // Very large image (> 8 MB) — steganography vessel
        if (buffer.length > 8_000_000) add(`Very large image file (${(buffer.length / 1e6).toFixed(1)} MB) — possible steganographic vessel`, 15, 'medium');

        // Compute hash
        const hash = computeFileHash(buffer);
        details.push({ label: `File SHA-256: ${hash}`, severity: 'info', points: 0 });
    }

    // ── Layer 3 : File size heuristics ─────────
    if (fileSize) {
        if (!base64Image) {
            // metadata-only mode
            if (fileSize > 4_000_000) add('Large file size — possible steganography carrier', 12, 'medium');
            if (fileSize < 600 && mimeType !== 'image/gif') add('Suspiciously tiny image — possible pixel tracker', 10, 'low');
        }
    }

    if (details.filter(d => d.severity !== 'info').length === 0)
        details.push({ label: 'No threats detected — file structure appears clean', severity: 'safe', points: 0 });

    const finalScore = Math.min(Math.round(score), 100);
    const verdict = finalScore >= 40 ? 'DANGER' : 'SAFE';

    const reasons = details
        .filter(d => d.severity !== 'info')
        .sort((a, b) => b.points - a.points)
        .map(d => `[${d.severity.toUpperCase()}] ${d.label}${d.points > 0 ? ` (+${d.points})` : ''}`);

    const infoLines = details.filter(d => d.severity === 'info').map(d => `[INFO] ${d.label}`);

    return {
        verdict,
        score: finalScore,
        reasons: [...reasons, ...infoLines],
        details,
    };
}

// ─────────────────────────────────────────────
//  ROUTES
// ─────────────────────────────────────────────

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', engine: 'PixSafe v2.0 — No-API Mode', timestamp: new Date().toISOString() });
});

// URL scan
app.post('/api/scan-url', (req, res) => {
    const { url } = req.body;
    if (!url || typeof url !== 'string' || url.trim().length === 0)
        return res.status(400).json({ error: 'Missing or invalid url field in request body.' });

    const result = analyzeURL(url.trim());
    res.json({ url: url.trim(), ...result, timestamp: new Date().toISOString() });
});

// Image scan
app.post('/api/scan-image', (req, res) => {
    const { fileName, fileSize, base64Image, mimeType } = req.body;

    if (!fileName && !base64Image)
        return res.status(400).json({ error: 'Provide at least fileName or base64Image.' });

    const result = analyzeImage({ fileName, fileSize, base64Image, mimeType });
    res.json({ fileName, ...result, timestamp: new Date().toISOString() });
});

// Batch URL scan (up to 20 at once)
app.post('/api/scan-urls-batch', (req, res) => {
    const { urls } = req.body;
    if (!Array.isArray(urls) || urls.length === 0)
        return res.status(400).json({ error: 'Provide an array of urls.' });
    if (urls.length > 20)
        return res.status(400).json({ error: 'Max 20 URLs per batch request.' });

    const results = urls.map(url => ({ url, ...analyzeURL(url.trim()) }));
    res.json({ results, count: results.length, timestamp: new Date().toISOString() });
});

// ─────────────────────────────────────────────
//  OPTIONAL — serve a minimal HTML test page
// ─────────────────────────────────────────────

app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>PixSafe API</title>
  <style>
    body{font-family:monospace;background:#0a0c0f;color:#e8edf5;padding:40px;max-width:800px;margin:0 auto}
    h1{color:#ff3b5c}code{background:#181c22;padding:4px 8px;border-radius:4px;color:#4da6ff}
    pre{background:#111418;border:1px solid #252b35;border-radius:8px;padding:16px;overflow:auto;font-size:13px}
    h2{color:#ffb800;margin-top:32px}
  </style>
</head>
<body>
  <h1>&#128737; PixSafe Backend</h1>
  <p>Pure JS threat scanner — no external APIs.</p>

  <h2>Endpoints</h2>
  <pre>GET  /api/health
POST /api/scan-url          { "url": "https://example.com" }
POST /api/scan-image        { "fileName": "...", "fileSize": 1234, "base64Image": "...", "mimeType": "image/jpeg" }
POST /api/scan-urls-batch   { "urls": ["url1", "url2", ...] }</pre>

  <h2>Quick URL test</h2>
  <pre>curl -X POST http://localhost:${PORT}/api/scan-url \\
  -H "Content-Type: application/json" \\
  -d '{"url":"http://login-verify-secure.net/account?update=1"}'</pre>
</body>
</html>`);
});

// ─────────────────────────────────────────────
//  START
// ─────────────────────────────────────────────

app.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════╗
║     PixSafe Backend  —  No-API Mode       ║
╠═══════════════════════════════════════════╣
║  Server  : http://localhost:${PORT}       ║
║  Engine  : Pure JS heuristics             ║
║  API key : Not required                   ║
╚═══════════════════════════════════════════╝

Routes:
  GET  /api/health
  POST /api/scan-url
  POST /api/scan-image
  POST /api/scan-urls-batch
`);
});