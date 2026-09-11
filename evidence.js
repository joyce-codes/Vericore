/**
 * VERICORE 2.0 — Evidence Object Engine
 * ======================================
 * Fully concrete implementation. No placeholder functions.
 * Every method either calls a real free API, uses deterministic
 * computation, or documents exactly what model to plug in.
 *
 * Free-tier stack used throughout:
 *   Cloudflare D1     → SQLite-compatible database (free tier: 5M rows/day)
 *   Cloudflare KV     → Key-value cache (free tier: 100K reads/day)
 *   Cloudflare R2     → Object storage (free tier: 10GB/month)
 *   HuggingFace API   → AI model inference (free tier: rate-limited)
 *   Wayback CDX API   → Archive lookups (completely free, no key)
 *   RDAP              → WHOIS data (completely free, no key)
 *   OpenTimestamps    → Blockchain timestamps (completely free)
 */

'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// EVIDENCE TYPES
// ─────────────────────────────────────────────────────────────────────────────

const EVIDENCE_TYPES = Object.freeze({
  IMAGE:           'image',
  ARTICLE:         'article',
  VIDEO:           'video',
  AUDIO:           'audio',
  TWEET:           'tweet',
  REDDIT_POST:     'reddit_post',
  DISCORD_ACCOUNT: 'discord_account',
  INSTAGRAM:       'instagram',
  SNAPCHAT:        'snapchat',
  WHATSAPP:        'whatsapp',
  EMAIL:           'email',
  WEBSITE:         'website',
  BLOCKCHAIN_TX:   'blockchain_tx',
  GOVERNMENT_DOC:  'government_doc',
  ACADEMIC_PAPER:  'academic_paper',
  SPOTIFY_ARTIST:  'spotify_artist',
  STOCK_TRADE:     'stock_trade',
  POLYMARKET_BET:  'polymarket_bet',
});

// ─────────────────────────────────────────────────────────────────────────────
// EVIDENCE OBJECT (immutable, versioned)
// ─────────────────────────────────────────────────────────────────────────────

class EvidenceObject {
  constructor(raw, type) {
    if (!Object.values(EVIDENCE_TYPES).includes(type)) {
      throw new Error(`Unknown type: ${type}`);
    }
    this.id        = crypto.randomUUID();
    this.version   = 1;
    this.type      = type;
    this.source    = null;
    this.timestamp = { claimed: null, observed: Date.now(), earliest: null };
    this.author    = {
      realName: null, aliases: [], usernames: [], historicalUsernames: [],
      accountAge: null, crossPlatform: {}, pgpKeys: [],
      emailMatches: [], domainOwnership: [], blockchainOwnership: [],
      governmentVerified: false, organizationVerified: false,
      identityScore: null,
    };
    this.metadata    = {};
    this.hashes      = { sha256: null, perceptual: null, ssdeep: null };
    this.location    = { claimed: null, exif: null, ip: null, consensus: null };
    this.relationships = [];
    this.media       = { url: null, mimeType: null, sizeBytes: null };
    this.references  = [];
    this.signatures  = { pgp: null, blockchain: null };
    this.raw         = raw;
    this.scores      = {
      overall: null, confidence: null, components: {},
      flags: [], factors: [], explanation: null,
    };
    this.chain       = [];  // Full audit history — never deleted
  }

  /**
   * Produces a new versioned EO without mutating the original.
   * LAW 4: Everything versioned, nothing overwritten.
   */
  update(changes) {
    const snapshot = JSON.parse(JSON.stringify(this));
    const next     = new EvidenceObject(this.raw, this.type);
    Object.assign(next, snapshot, changes);
    next.version = this.version + 1;
    next.chain   = [...this.chain, { version: this.version, ts: Date.now(), snapshot }];
    return next;
  }

  toJSON() {
    // Exclude raw binary data from JSON serialization
    const obj = { ...this };
    if (obj.media?.rawBuffer) delete obj.media.rawBuffer;
    return obj;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// CRYPTO UTILITIES (real, no stubs)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * SHA-256 hash of any string or ArrayBuffer.
 * Uses native Web Crypto API — works in Cloudflare Workers.
 */
async function sha256(data) {
  const buf   = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hash  = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Perceptual hash of an image.
 * Algorithm: Average Hash (aHash) — fast, good enough for near-duplicate detection.
 * No external library needed.
 *
 * NOTE: In a browser/Worker context, use OffscreenCanvas.
 * In Node.js, use the 'sharp' package for pixel access.
 */
function perceptualHash(pixels, width, height) {
  // Resize to 8x8 via bilinear sampling
  const SIZE = 8;
  const grid = [];
  for (let y = 0; y < SIZE; y++) {
    for (let x = 0; x < SIZE; x++) {
      const srcX = Math.floor(x * width / SIZE);
      const srcY = Math.floor(y * height / SIZE);
      const idx  = (srcY * width + srcX) * 4;
      // Convert to grayscale
      const gray = 0.299 * pixels[idx] + 0.587 * pixels[idx+1] + 0.114 * pixels[idx+2];
      grid.push(gray);
    }
  }
  const avg  = grid.reduce((s, v) => s + v, 0) / grid.length;
  const bits = grid.map(v => v > avg ? '1' : '0').join('');
  return parseInt(bits, 2).toString(16).padStart(16, '0');
}

/**
 * Hamming distance between two hex perceptual hashes.
 * Returns 0–64 (0 = identical, >10 = likely different images).
 */
function hammingDistance(hash1, hash2) {
  const a = BigInt('0x' + hash1);
  const b = BigInt('0x' + hash2);
  let xor = a ^ b;
  let dist = 0;
  while (xor > 0n) { if (xor & 1n) dist++; xor >>= 1n; }
  return dist;
}

// ─────────────────────────────────────────────────────────────────────────────
// FLAG FACTORY
// ─────────────────────────────────────────────────────────────────────────────

function flag(type, severity, description, data = {}) {
  return { type, severity, description, data, ts: Date.now() };
}

function computeSignalScore(flags) {
  if (flags.length === 0) return 0.9;
  const penalties = { critical: 0.40, high: 0.20, medium: 0.10, low: 0.05, info: 0.01 };
  const total = flags.reduce((s, f) => s + (penalties[f.severity] || 0), 0);
  return Math.max(0, 1 - total);
}

// ─────────────────────────────────────────────────────────────────────────────
// MATH UTILITIES
// ─────────────────────────────────────────────────────────────────────────────

const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const lerp  = (a, b, t) => a + (b - a) * t;
const mean  = arr => arr.length ? arr.reduce((s, v) => s + v, 0) / arr.length : 0;
const variance = arr => {
  if (arr.length < 2) return 0;
  const m = mean(arr);
  return mean(arr.map(v => (v - m) ** 2));
};
const stdDev = arr => Math.sqrt(variance(arr));
const weightedMean = pairs => {
  const tw = pairs.reduce((s, [, w]) => s + w, 0);
  return pairs.reduce((s, [v, w]) => s + v * w, 0) / tw;
};

function extractDomain(url) {
  try {
    return new URL(url.startsWith('http') ? url : `https://${url}`).hostname.replace(/^www\./, '');
  } catch { return url; }
}

module.exports = {
  EVIDENCE_TYPES, EvidenceObject,
  sha256, perceptualHash, hammingDistance,
  flag, computeSignalScore,
  clamp, lerp, mean, variance, stdDev, weightedMean, extractDomain,
};
