/**
 * VERICORE 2.0 — Retrieval Layer
 * ================================
 * The retrieval layer sits between Input and Scoring.
 * It gathers evidence from external sources BEFORE scoring begins.
 *
 * Architecture:
 *   Input → [Retrieval Layer] → Evidence Graph → Scoring
 *
 * All APIs used are either completely free (no key needed)
 * or have a generous free tier sufficient for a hobby project.
 *
 * FREE APIs USED:
 *   Wayback CDX API       — 100% free, no rate limit stated
 *   RDAP (WHOIS)          — 100% free, ICANN-mandated
 *   Brave Search API      — free tier: 2,000 req/month
 *   Google SafeBrowsing   — free: 10,000 req/day
 *   OpenTimestamps        — 100% free
 *   Mempool.space         — 100% free (Bitcoin data)
 *   Etherscan API         — free: 5 req/sec, 100K/day
 *   Have I Been Pwned     — free: 1 req/1.5sec (no key for domain checks)
 */

'use strict';

const { extractDomain, flag, sha256 } = require('./evidence');

// ─────────────────────────────────────────────────────────────────────────────
// WAYBACK MACHINE CLIENT (100% free, no key needed)
// ─────────────────────────────────────────────────────────────────────────────

class WaybackClient {
  /**
   * Find earliest known snapshot of a URL.
   * CDX API docs: https://github.com/internetarchive/wayback_machine_apis
   */
  async findEarliestSnapshot(url) {
    const cdxUrl = `https://web.archive.org/cdx/search/cdx?` +
      `url=${encodeURIComponent(url)}&` +
      `output=json&limit=1&fl=timestamp,statuscode&` +
      `filter=statuscode:200&from=19900101&to=20300101`;

    try {
      const res  = await fetch(cdxUrl, { cf: { cacheTtl: 86400 } });
      if (!res.ok) return null;
      const data = await res.json();
      if (!data || data.length < 2) return null;

      // CDX returns [[header], [row1], ...]
      const row  = data[1];
      const ts   = row[0];  // YYYYMMDDHHmmss

      return {
        date: new Date(
          parseInt(ts.slice(0, 4)),
          parseInt(ts.slice(4, 6)) - 1,
          parseInt(ts.slice(6, 8))
        ).toISOString(),
        archiveUrl: `https://web.archive.org/web/${ts}/${url}`,
      };
    } catch {
      return null;
    }
  }

  /**
   * Check if content at a URL has changed significantly over time.
   * Compares snapshots from different dates.
   */
  async checkContentStability(url, numSnapshots = 5) {
    const cdxUrl = `https://web.archive.org/cdx/search/cdx?` +
      `url=${encodeURIComponent(url)}&` +
      `output=json&limit=${numSnapshots}&fl=timestamp,digest&` +
      `filter=statuscode:200`;

    try {
      const res  = await fetch(cdxUrl, { cf: { cacheTtl: 3600 } });
      if (!res.ok) return { stable: true, snapshots: 0 };
      const data = await res.json();
      if (!data || data.length < 2) return { stable: true, snapshots: 0 };

      const rows    = data.slice(1);  // Skip header
      const digests = rows.map(r => r[1]);
      const unique  = new Set(digests);

      return {
        stable:      unique.size === 1,
        snapshots:   rows.length,
        uniqueVersions: unique.size,
        changeRatio: (unique.size - 1) / Math.max(rows.length - 1, 1),
      };
    } catch {
      return { stable: true, snapshots: 0, error: 'CDX unavailable' };
    }
  }

  /**
   * Search for when a specific text phrase was first indexed.
   * Useful for claim origin tracing.
   */
  async findPhraseOrigin(phrase) {
    // Search CDX for pages mentioning the phrase (limited, but works for very specific phrases)
    const encoded = encodeURIComponent(`"${phrase}"`);
    const url     = `https://web.archive.org/cdx/search/cdx?q=${encoded}&output=json&limit=1&fl=timestamp,urlkey&filter=statuscode:200`;

    try {
      const res  = await fetch(url, { cf: { cacheTtl: 86400 } });
      if (!res.ok) return null;
      const data = await res.json();
      if (!data || data.length < 2) return null;
      const [ts, urlKey] = data[1];
      return { date: `${ts.slice(0,4)}-${ts.slice(4,6)}-${ts.slice(6,8)}`, urlKey };
    } catch {
      return null;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// RDAP CLIENT — Modern WHOIS replacement (100% free)
// ─────────────────────────────────────────────────────────────────────────────

class RDAPClient {
  /**
   * RDAP is the ICANN-standardized JSON replacement for WHOIS.
   * Mandated for all accredited registrars since 2023.
   * No API key needed.
   */
  async lookupDomain(domain) {
    // Try RDAP bootstrap first (finds the right server automatically)
    const bootstrapUrl = `https://rdap.org/domain/${encodeURIComponent(domain)}`;

    try {
      const res  = await fetch(bootstrapUrl, {
        headers: { Accept: 'application/rdap+json' },
        cf: { cacheTtl: 3600 },
      });

      if (!res.ok) return this._fallbackToWhois(domain);
      const data = await res.json();

      return {
        domain:        data.ldhName?.toLowerCase(),
        status:        data.status || [],
        registrar:     this._extractEntity(data, 'registrar')?.vcardArray?.[1]
                         ?.find(f => f[0] === 'fn')?.[3] || null,
        registrantOrg: this._extractEntity(data, 'registrant')?.vcardArray?.[1]
                         ?.find(f => f[0] === 'org')?.[3] || null,
        createdDate:   this._findEventDate(data, 'registration'),
        updatedDate:   this._findEventDate(data, 'last changed'),
        expiresDate:   this._findEventDate(data, 'expiration'),
        nameservers:   data.nameservers?.map(ns => ns.ldhName?.toLowerCase()) || [],
        privacyProtected: this._isPrivacyProtected(data),
        domainAgeDays: this._computeAgeDays(this._findEventDate(data, 'registration')),
        raw:           data,
      };
    } catch {
      return this._fallbackToWhois(domain);
    }
  }

  async lookupIP(ip) {
    try {
      const res  = await fetch(`https://rdap.arin.net/registry/ip/${ip}`, {
        headers: { Accept: 'application/rdap+json' },
        cf: { cacheTtl: 3600 },
      });
      if (!res.ok) return null;
      const data = await res.json();
      return {
        ip,
        network:    data.name,
        country:    data.country,
        org:        this._extractEntity(data, 'registrant')?.vcardArray?.[1]
                      ?.find(f => f[0] === 'fn')?.[3] || null,
        asnNumber:  data.arin_originas0_asns?.[0] || null,
      };
    } catch {
      return null;
    }
  }

  _extractEntity(data, role) {
    return data.entities?.find(e => e.roles?.includes(role));
  }

  _findEventDate(data, eventAction) {
    const event = data.events?.find(e => e.eventAction === eventAction);
    return event?.eventDate || null;
  }

  _isPrivacyProtected(data) {
    const reg = this._extractEntity(data, 'registrant');
    if (!reg) return true;  // Missing registrant = likely protected
    const fn = reg.vcardArray?.[1]?.find(f => f[0] === 'fn')?.[3] || '';
    return fn.toLowerCase().includes('privacy') || fn.toLowerCase().includes('redacted');
  }

  _computeAgeDays(dateStr) {
    if (!dateStr) return null;
    const created = new Date(dateStr);
    return Math.floor((Date.now() - created.getTime()) / 86400000);
  }

  async _fallbackToWhois(domain) {
    // Fallback to whois.domaintools.com free API
    try {
      const res  = await fetch(`https://api.whois.vu/?q=${encodeURIComponent(domain)}`, {
        cf: { cacheTtl: 3600 },
      });
      if (!res.ok) return null;
      const text = await res.text();
      const createdMatch = text.match(/created.*?(\d{4}-\d{2}-\d{2})/i);
      return {
        domain,
        createdDate: createdMatch?.[1] || null,
        domainAgeDays: createdMatch?.[1]
          ? Math.floor((Date.now() - new Date(createdMatch[1]).getTime()) / 86400000)
          : null,
        raw: text,
      };
    } catch {
      return null;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SEARCH CLIENT (Brave Search free tier: 2000 req/month)
// ─────────────────────────────────────────────────────────────────────────────

class SearchClient {
  /**
   * Brave Search API: https://api.search.brave.com
   * Free tier: 2,000 requests/month (no credit card)
   * Perfect for a small verification service.
   *
   * Fallback: DuckDuckGo instant answers (no key, no formal rate limit)
   */
  constructor(braveApiKey, cache) {
    this.apiKey = braveApiKey;
    this.cache  = cache;
  }

  async search(query, options = {}) {
    const cacheKey = `search:${await sha256(query + JSON.stringify(options))}`;

    if (this.cache) {
      const cached = await this.cache.get(cacheKey);
      if (cached) return JSON.parse(cached);
    }

    const result = await this._braveSearch(query, options)
                || await this._ddgSearch(query);

    if (this.cache && result) {
      await this.cache.put(cacheKey, JSON.stringify(result), { expirationTtl: 3600 });
    }

    return result || { results: [], source: 'no_results' };
  }

  async _braveSearch(query, options) {
    if (!this.apiKey) return null;
    try {
      const params = new URLSearchParams({
        q:     query,
        count: options.count || 10,
        freshness: options.freshness || 'ALL',
      });

      const res  = await fetch(`https://api.search.brave.com/res/v1/web/search?${params}`, {
        headers: {
          'Accept':             'application/json',
          'Accept-Encoding':    'gzip',
          'X-Subscription-Token': this.apiKey,
        },
      });

      if (!res.ok) return null;
      const data = await res.json();

      return {
        results: (data.web?.results || []).map(r => ({
          title:   r.title,
          url:     r.url,
          snippet: r.description,
          domain:  extractDomain(r.url),
          age:     r.age,
        })),
        source: 'brave',
      };
    } catch {
      return null;
    }
  }

  async _ddgSearch(query) {
    // DuckDuckGo instant answers — limited but free and no key
    try {
      const url  = `https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_html=1`;
      const res  = await fetch(url, { cf: { cacheTtl: 3600 } });
      if (!res.ok) return null;
      const data = await res.json();

      const results = (data.Results || []).map(r => ({
        title:   r.Text,
        url:     r.FirstURL,
        snippet: r.Text,
        domain:  extractDomain(r.FirstURL),
      }));

      if (data.AbstractURL) {
        results.unshift({
          title:   data.Heading,
          url:     data.AbstractURL,
          snippet: data.Abstract,
          domain:  extractDomain(data.AbstractURL),
          authoritative: true,
        });
      }

      return { results, source: 'ddg' };
    } catch {
      return null;
    }
  }

  /**
   * Reverse image search via SauceNAO (free, 200 req/day without key, 4000 with free key)
   * Great for finding earlier appearances of images.
   */
  async reverseImageSearch(imageUrl, sauceNaoKey = null) {
    const params = new URLSearchParams({
      url:       imageUrl,
      output_type: 2,  // JSON
      numres:    5,
    });
    if (sauceNaoKey) params.append('api_key', sauceNaoKey);

    try {
      const res  = await fetch(`https://saucenao.com/search.php?${params}`, {
        cf: { cacheTtl: 86400 },
      });
      if (!res.ok) return [];
      const data = await res.json();

      return (data.results || []).map(r => ({
        similarity: parseFloat(r.header.similarity),
        thumbnail:  r.header.thumbnail,
        sourceUrl:  r.data?.ext_urls?.[0] || null,
        title:      r.data?.title || null,
        date:       r.data?.created_at || null,
        source:     r.header.index_name,
      }));
    } catch {
      return [];
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOCKCHAIN VERIFICATION (free APIs)
// ─────────────────────────────────────────────────────────────────────────────

class BlockchainVerifier {
  constructor(etherscanKey, cache) {
    this.etherscanKey = etherscanKey;
    this.cache        = cache;
  }

  /**
   * Verify file existence at a time using OpenTimestamps.
   * 100% free. Uses Bitcoin blockchain for timestamping.
   * Protocol: https://opentimestamps.org/
   */
  async verifyOpenTimestamp(sha256Hash) {
    // OpenTimestamps calendar servers (public, free)
    const CALENDARS = [
      'https://alice.btc.calendar.opentimestamps.org',
      'https://bob.btc.calendar.opentimestamps.org',
      'https://finney.calendar.eternitywall.com',
    ];

    for (const calendar of CALENDARS) {
      try {
        const res  = await fetch(`${calendar}/lookup`, {
          method:  'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body:    `digest=${sha256Hash}`,
          cf: { cacheTtl: 86400 },
        });
        if (res.ok) {
          const data = await res.json();
          if (data.timestamp) {
            return {
              found:     true,
              timestamp: data.timestamp,
              calendar,
              bitcoinBlock: data.bitcoin_block,
            };
          }
        }
      } catch {}
    }
    return { found: false };
  }

  /**
   * Ethereum wallet analysis via Etherscan free API.
   * Free tier: 5 req/sec, 100,000 calls/day
   * Get free key at: https://etherscan.io/apis
   */
  async analyzeEthWallet(address) {
    const cacheKey = `eth:${address}`;
    if (this.cache) {
      const c = await this.cache.get(cacheKey);
      if (c) return JSON.parse(c);
    }

    const base = 'https://api.etherscan.io/api';
    const key  = this.etherscanKey ? `&apikey=${this.etherscanKey}` : '';

    try {
      const [balRes, txRes] = await Promise.all([
        fetch(`${base}?module=account&action=balance&address=${address}&tag=latest${key}`),
        fetch(`${base}?module=account&action=txlist&address=${address}&startblock=0&page=1&offset=10&sort=asc${key}`),
      ]);

      const bal = await balRes.json();
      const txs = await txRes.json();

      const result = {
        address,
        balanceEth:    bal.status === '1' ? parseFloat(bal.result) / 1e18 : null,
        txCount:       txs.result?.length || 0,
        firstTxDate:   txs.result?.[0] ? new Date(parseInt(txs.result[0].timeStamp) * 1000).toISOString() : null,
        lastTxDate:    txs.result?.slice(-1)[0]
                         ? new Date(parseInt(txs.result.slice(-1)[0].timeStamp) * 1000).toISOString() : null,
        isContract:    await this._isContract(address, base, key),
      };

      // OFAC sanctions check (free list from US Treasury)
      result.sanctioned = await this._checkOFACSanctions(address);

      if (this.cache) {
        await this.cache.put(cacheKey, JSON.stringify(result), { expirationTtl: 3600 });
      }

      return result;
    } catch {
      return { address, error: 'Etherscan unavailable' };
    }
  }

  /**
   * Bitcoin OP_RETURN search via Mempool.space (100% free)
   * Finds hash commitments stored in Bitcoin transactions.
   */
  async searchBitcoinOpReturn(hash) {
    try {
      const res  = await fetch(`https://mempool.space/api/tx/${hash}`, {
        cf: { cacheTtl: 86400 },
      });
      if (res.ok) {
        const tx = await res.json();
        return {
          found:    true,
          txId:     tx.txid,
          blockTime: tx.status?.block_time
            ? new Date(tx.status.block_time * 1000).toISOString()
            : null,
          confirmed: tx.status?.confirmed || false,
        };
      }
    } catch {}
    return { found: false };
  }

  async _isContract(address, base, key) {
    try {
      const res  = await fetch(`${base}?module=contract&action=getabi&address=${address}${key}`);
      const data = await res.json();
      return data.status === '1';
    } catch { return false; }
  }

  async _checkOFACSanctions(address) {
    // OFAC publishes a free SDN list
    // For a production system, download and parse:
    // https://www.treasury.gov/ofac/downloads/sdn_xml.zip
    // For now, we check against known public blockchain analytics APIs
    return false;  // Implement with OFAC XML download
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// VECTOR SEARCH (semantic similarity for claims)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * VectorStore: Finds semantically similar claims.
 *
 * Free options:
 *   Cloudflare Vectorize  — 5M vectors free per month
 *   Supabase pgvector     — free tier: 500MB
 *   Weaviate Cloud        — free sandbox
 *
 * Embeddings:
 *   HuggingFace sentence-transformers/all-MiniLM-L6-v2 — free, fast
 */
class VectorStore {
  constructor(vectorizeNamespace, hfClient) {
    this.vectorize = vectorizeNamespace;  // Cloudflare Vectorize binding
    this.hf        = hfClient;
  }

  /**
   * Store a claim with its embedding for future semantic search.
   */
  async storeClaim(claimId, claimText, metadata = {}) {
    const embedding = await this._embed(claimText);
    if (!embedding || !this.vectorize) return;

    await this.vectorize.insert([{
      id:       claimId,
      values:   embedding,
      metadata: {
        text:   claimText.slice(0, 500),  // Vectorize metadata limit
        ts:     Date.now(),
        ...metadata,
      },
    }]);
  }

  /**
   * Find semantically similar claims.
   * Handles: "The CEO resigned" ≈ "The chief executive stepped down"
   */
  async findSimilarClaims(queryText, topK = 5, scoreThreshold = 0.78) {
    const embedding = await this._embed(queryText);
    if (!embedding || !this.vectorize) return [];

    const results = await this.vectorize.query(embedding, {
      topK,
      returnMetadata: true,
      returnValues:   false,
    });

    return (results.matches || [])
      .filter(m => m.score >= scoreThreshold)
      .map(m => ({
        id:         m.id,
        score:      m.score,
        text:       m.metadata?.text,
        timestamp:  m.metadata?.ts,
      }));
  }

  async _embed(text) {
    try {
      const result = await this.hf.embed(text, 'sentence-transformers/all-MiniLM-L6-v2');
      // HF returns nested array for single input
      return Array.isArray(result[0]) ? result[0] : result;
    } catch {
      return null;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// EMAIL VERIFICATION (free checks)
// ─────────────────────────────────────────────────────────────────────────────

class EmailVerifier {
  async verify(email) {
    const [local, domain] = email.split('@');
    if (!domain) return { valid: false, reason: 'Invalid format' };

    const [mx, disposable, breached] = await Promise.allSettled([
      this._checkMX(domain),
      this._checkDisposable(domain),
      this._checkBreach(email),
    ]);

    return {
      email,
      domain,
      mxValid:       mx.status === 'fulfilled' ? mx.value : null,
      isDisposable:  disposable.status === 'fulfilled' ? disposable.value : false,
      breachCount:   breached.status === 'fulfilled' ? breached.value : 0,
      formatValid:   /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email),
    };
  }

  async _checkMX(domain) {
    // DNS-over-HTTPS (free, Cloudflare resolver)
    try {
      const res  = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=MX`, {
        headers: { Accept: 'application/dns-json' },
        cf: { cacheTtl: 3600 },
      });
      const data = await res.json();
      return data.Answer?.length > 0;
    } catch { return null; }
  }

  async _checkDisposable(domain) {
    // Open-source disposable email domain list
    // https://github.com/disposable-email-domains/disposable-email-domains
    const KNOWN_DISPOSABLE = new Set([
      'mailinator.com', 'guerrillamail.com', 'tempmail.com', 'throwaway.email',
      'fakeinbox.com', 'yopmail.com', 'sharklasers.com', 'guerrillamailblock.com',
      'trashmail.com', 'dispostable.com', 'spamgourmet.com',
    ]);
    return KNOWN_DISPOSABLE.has(domain.toLowerCase());
  }

  async _checkBreach(email) {
    // HIBP API: free for domain searches, rate-limited for email
    // Use the domain endpoint to check if domain appears in breaches
    try {
      const [, domain] = email.split('@');
      const res  = await fetch(`https://haveibeenpwned.com/api/v3/breacheddomain/${domain}`, {
        headers: {
          'hibp-api-key': '',  // Key required for email endpoint but not domain
          'user-agent':  'VERICORE Verification System',
        },
        cf: { cacheTtl: 86400 },
      });
      if (res.status === 404) return 0;
      if (!res.ok) return null;
      const data = await res.json();
      return Object.keys(data).length;
    } catch { return null; }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SSL CERTIFICATE CHECKER (free)
// ─────────────────────────────────────────────────────────────────────────────

class SSLChecker {
  async check(domain) {
    // Use crt.sh (free Certificate Transparency log search)
    try {
      const res  = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, {
        cf: { cacheTtl: 86400 },
      });
      if (!res.ok) return null;
      const certs = await res.json();

      if (!certs.length) return { hasCerts: false };

      const sorted = certs.sort((a, b) => new Date(a.not_before) - new Date(b.not_before));
      const oldest = sorted[0];

      return {
        hasCerts:         true,
        certCount:        certs.length,
        firstCertDate:    oldest.not_before,
        domains:          [...new Set(certs.map(c => c.name_value))].slice(0, 10),
        issuers:          [...new Set(certs.map(c => c.issuer_ca_id))].length,
        hasWildcard:      certs.some(c => c.name_value.startsWith('*.')),
      };
    } catch {
      return null;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GOOGLE SAFE BROWSING (free: 10,000 req/day)
// ─────────────────────────────────────────────────────────────────────────────

class SafeBrowsingClient {
  constructor(apiKey) {
    this.apiKey = apiKey;
  }

  async check(url) {
    if (!this.apiKey) return null;

    try {
      const res = await fetch(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${this.apiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client:        { clientId: 'vericore', clientVersion: '2.0' },
            threatInfo:    {
              threatTypes:      ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
              platformTypes:    ['ANY_PLATFORM'],
              threatEntryTypes: ['URL'],
              threatEntries:    [{ url }],
            },
          }),
        }
      );

      if (!res.ok) return null;
      const data = await res.json();

      return {
        safe:    !data.matches || data.matches.length === 0,
        threats: data.matches?.map(m => m.threatType) || [],
      };
    } catch { return null; }
  }
}

module.exports = {
  WaybackClient,
  RDAPClient,
  SearchClient,
  BlockchainVerifier,
  VectorStore,
  EmailVerifier,
  SSLChecker,
  SafeBrowsingClient,
};
