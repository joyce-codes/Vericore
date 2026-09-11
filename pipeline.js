/**
 * VERICORE 2.0 — Tiered Processing Queue
 * ========================================
 * Solves the computational expense problem.
 *
 * PROBLEM: Running all checks on every upload is O(N*M) expensive.
 *   Image forensic analysis  — ~500ms
 *   Video deepfake analysis  — ~2-5s
 *   Graph clustering         — ~200ms
 *   Web search (5 queries)   — ~2s
 *   Archive lookups          — ~300ms
 *   Blockchain queries       — ~1s
 *   TOTAL: ~5-10s per request, $$$
 *
 * SOLUTION: 3-tier progressive analysis
 *
 *   TIER 1 — Instant (< 100ms, always runs, free)
 *     Hash check (known good/bad)
 *     Domain age check
 *     URL safety check
 *     Format validation
 *     → Returns preliminary score immediately
 *
 *   TIER 2 — Fast (< 2s, runs for most requests, cheap)
 *     Source trust score
 *     Wayback Machine check
 *     RDAP domain lookup
 *     Email/SSL verification
 *     Text AI detection
 *     Basic image classifier (1 HF model)
 *     → Returns refined score, queues Tier 3 if suspicious
 *
 *   TIER 3 — Deep (< 30s, only for suspicious or high-value content)
 *     Full AI detection ensemble (all models)
 *     Blockchain timestamp verification
 *     Cross-reference search (5+ queries)
 *     Anti-manipulation graph analysis
 *     Identity verification
 *     Historical consistency
 *     Vector similarity search
 *     → Final authoritative score
 *
 * QUEUE IMPLEMENTATION:
 *   Cloudflare Queues (free tier: 5M messages/month)
 *   Worker → Queue → Consumer Worker
 *
 * CACHING STRATEGY:
 *   Every result cached by sha256(input) in KV.
 *   Cache TTL: 24 hours for scores, 7 days for domain/SSL data.
 *   Cache hit = free. Popular content analyzed once.
 */

'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// TIER 1 — Instant checks (no API calls, pure computation)
// ─────────────────────────────────────────────────────────────────────────────

class Tier1Analyzer {
  constructor(kv) {
    this.kv = kv;
  }

  async analyze(input, type, hash) {
    const flags   = [];
    const instant = {};

    // 1. Known hash check (KV lookup: ~1ms)
    const knownResult = await this._checkKnownHash(hash);
    if (knownResult) {
      return {
        tier:    1,
        cached:  true,
        result:  knownResult,
        elapsed: 0,
      };
    }

    // 2. URL/domain age estimate from cache
    if (input.url || typeof input === 'string' && input.startsWith('http')) {
      const url = input.url || input;

      // Check Google Safe Browsing cache
      const sbResult = await this.kv?.get(`safebrowsing:${url}`);
      if (sbResult) {
        const sb = JSON.parse(sbResult);
        if (!sb.safe) {
          flags.push({
            type:        'UNSAFE_URL',
            severity:    'critical',
            description: `URL flagged as ${sb.threats.join(', ')} by Google Safe Browsing`,
          });
        }
        instant.safeBrowsing = sb;
      }
    }

    // 3. Format validation
    const formatCheck = validateFormat(input, type);
    if (!formatCheck.valid) {
      flags.push({
        type:        'FORMAT_INVALID',
        severity:    'medium',
        description: formatCheck.reason,
      });
    }

    // 4. Preliminary score based only on format + flags
    const preliminary = computePreliminaryScore(flags, type);

    return {
      tier:        1,
      cached:      false,
      preliminary,
      flags,
      instant,
      needsTier2:  true,  // Always escalate
    };
  }

  async _checkKnownHash(hash) {
    if (!hash || !this.kv) return null;
    const cached = await this.kv.get(`hash:${hash}`);
    return cached ? JSON.parse(cached) : null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 2 — Fast analysis (2-3 API calls, < 2s)
// ─────────────────────────────────────────────────────────────────────────────

class Tier2Analyzer {
  constructor({ sourceTrust, wayback, rdap, ssl, safeBrowsing, imageAI, textAI, kv }) {
    this.sourceTrust  = sourceTrust;
    this.wayback      = wayback;
    this.rdap         = rdap;
    this.ssl          = ssl;
    this.safeBrowsing = safeBrowsing;
    this.imageAI      = imageAI;
    this.textAI       = textAI;
    this.kv           = kv;
  }

  async analyze(eo, tier1Result) {
    const flags = [...(tier1Result.flags || [])];
    const start = Date.now();

    // Run parallel where possible
    const checks = [];

    // Source trust (always)
    if (eo.source) {
      checks.push(
        this.sourceTrust.computeScore(eo.source)
          .then(r => ({ key: 'sourceTrust', result: r }))
          .catch(e => ({ key: 'sourceTrust', error: e.message }))
      );
    }

    // Wayback Machine (always — free and fast)
    if (eo.source) {
      checks.push(
        this.wayback.findEarliestSnapshot(eo.source)
          .then(r => ({ key: 'wayback', result: r }))
          .catch(e => ({ key: 'wayback', error: e.message }))
      );
    }

    // Google Safe Browsing (if URL, free)
    if (eo.source && this.safeBrowsing) {
      checks.push(
        this.safeBrowsing.check(eo.source)
          .then(r => ({ key: 'safeBrowsing', result: r }))
          .catch(e => ({ key: 'safeBrowsing', error: e.message }))
      );
    }

    // Image AI detection — SINGLE fast model only (save quota)
    if (eo.type === 'image' && eo.media?.base64) {
      checks.push(
        this.imageAI._runSingleModel(eo.media.base64, eo.hashes.sha256)
          .then(r => ({ key: 'imageAI', result: r }))
          .catch(e => ({ key: 'imageAI', error: e.message }))
      );
    }

    // Text AI detection (for articles/tweets)
    if (['article', 'tweet', 'reddit_post'].includes(eo.type) && eo.raw) {
      const text = typeof eo.raw === 'string' ? eo.raw : JSON.stringify(eo.raw);
      checks.push(
        this.textAI.analyze(text.slice(0, 1000), eo.hashes.sha256)
          .then(r => ({ key: 'textAI', result: r }))
          .catch(e => ({ key: 'textAI', error: e.message }))
      );
    }

    const results = await Promise.allSettled(checks.map(p => p));
    const resolved = results
      .filter(r => r.status === 'fulfilled')
      .map(r => r.value);

    const byKey = {};
    for (const r of resolved) byKey[r.key] = r.result || null;

    // Process results into flags
    if (byKey.safeBrowsing && !byKey.safeBrowsing.safe) {
      flags.push({
        type:        'MALICIOUS_URL',
        severity:    'critical',
        description: `Google Safe Browsing: ${byKey.safeBrowsing.threats.join(', ')}`,
      });
    }

    if (byKey.imageAI?.score > 0.75) {
      flags.push({
        type:        'AI_IMAGE_LIKELY',
        severity:    'high',
        description: `Single-model AI image score: ${Math.round(byKey.imageAI.score * 100)}%`,
      });
    }

    // Determine if Tier 3 is needed
    const needsDeep = this._needsDeepAnalysis(flags, byKey, eo);

    const tier2Score = computeTier2Score(byKey, flags);

    return {
      tier:        2,
      elapsed:     Date.now() - start,
      score:       tier2Score,
      flags,
      components:  byKey,
      needsTier3:  needsDeep,
      tier3Reason: needsDeep ? this._tier3Reason(flags, byKey) : null,
    };
  }

  _needsDeepAnalysis(flags, components, eo) {
    const criticalFlags = flags.filter(f => f.severity === 'critical').length;
    const highFlags     = flags.filter(f => f.severity === 'high').length;

    // Always deep-analyze if suspicious
    if (criticalFlags > 0) return true;
    if (highFlags >= 2)    return true;

    // Always deep-analyze certain types
    if (['government_doc', 'academic_paper', 'blockchain_tx'].includes(eo.type)) return true;

    // Deep-analyze if source is unknown (no trust history)
    if (components.sourceTrust?.sampleSize < 5) return true;

    // Deep-analyze if very new content (< 24 hours old, high virality risk)
    if (eo.metadata?.publishedAge && eo.metadata.publishedAge < 86400) return true;

    return false;
  }

  _tier3Reason(flags, components) {
    if (flags.some(f => f.severity === 'critical')) return 'Critical flag detected';
    if (flags.filter(f => f.severity === 'high').length >= 2) return '2+ high-severity flags';
    if (components.sourceTrust?.sampleSize < 5) return 'Unknown source';
    return 'Standard deep analysis';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 3 — Deep analysis (queued, async, comprehensive)
// ─────────────────────────────────────────────────────────────────────────────

class Tier3Analyzer {
  constructor({ imageAI, blockchain, crossRef, antiManip, identity, history, vectorStore, search }) {
    this.imageAI    = imageAI;
    this.blockchain = blockchain;
    this.crossRef   = crossRef;
    this.antiManip  = antiManip;
    this.identity   = identity;
    this.history    = history;
    this.vectorStore = vectorStore;
    this.search     = search;
  }

  async analyze(eo, tier2Result) {
    const flags  = [...(tier2Result.flags || [])];
    const start  = Date.now();
    const deep   = {};

    // Full AI ensemble (all models)
    if (['image', 'video', 'audio'].includes(eo.type)) {
      try {
        const aiResult = await this.imageAI.analyze(
          eo.media?.base64, eo.hashes.sha256, eo.metadata?.exif
        );
        deep.aiEnsemble = aiResult;
        flags.push(...aiResult.signals);
      } catch (e) {
        deep.aiEnsemble = { error: e.message };
      }
    }

    // Blockchain timestamp
    if (eo.hashes.sha256) {
      try {
        const blockResult = await this.blockchain.verifyOpenTimestamp(eo.hashes.sha256);
        deep.blockchain = blockResult;
        if (blockResult.found) {
          // Validate timestamp consistency
          if (eo.timestamp.claimed) {
            const blockDate   = new Date(blockResult.timestamp * 1000);
            const claimedDate = new Date(eo.timestamp.claimed);
            const diffDays    = Math.abs(blockDate - claimedDate) / 86400000;
            if (diffDays > 30) {
              flags.push({
                type:        'BLOCKCHAIN_TIMESTAMP_MISMATCH',
                severity:    'high',
                description: `Blockchain timestamp differs from claimed date by ${Math.round(diffDays)} days`,
              });
            }
          }
        }
      } catch (e) {
        deep.blockchain = { error: e.message };
      }
    }

    // Cross-reference search (most expensive — 5+ API calls)
    if (this.search && eo.raw) {
      try {
        const text = typeof eo.raw === 'string' ? eo.raw.slice(0, 300) : '';
        const corroborations = await this._crossReference(text, eo.source);
        deep.corroborations = corroborations;
      } catch (e) {
        deep.corroborations = { error: e.message };
      }
    }

    // Vector similarity (find semantically similar claims)
    if (this.vectorStore && eo.raw) {
      try {
        const text    = typeof eo.raw === 'string' ? eo.raw.slice(0, 500) : '';
        const similar = await this.vectorStore.findSimilarClaims(text);
        deep.similarClaims = similar;

        if (similar.some(s => s.score > 0.95)) {
          flags.push({
            type:        'NEAR_DUPLICATE_CLAIM',
            severity:    'medium',
            description: `Semantically identical claim found in database (similarity: ${Math.round(similar[0].score * 100)}%)`,
          });
        }
      } catch (e) {
        deep.similarClaims = { error: e.message };
      }
    }

    // Historical consistency
    if (this.history && eo.source) {
      try {
        const histResult = await this.history.checkConsistency(eo);
        deep.historical  = histResult;
        flags.push(...(histResult.contradictions || []).map(c => ({
          type:        c.type,
          severity:    c.severity,
          description: c.description,
        })));
      } catch (e) {
        deep.historical = { error: e.message };
      }
    }

    return {
      tier:      3,
      elapsed:   Date.now() - start,
      flags,
      deep,
      finalScore: computeFinalScore(tier2Result, flags, deep),
    };
  }

  async _crossReference(text, existingSource) {
    const searchResults = await this.search.search(text, { count: 5 });
    const otherSources  = searchResults.results?.filter(
      r => r.domain !== (existingSource ? extractDomain(existingSource) : '')
    ) || [];

    return {
      independentCount: otherSources.length,
      results:          otherSources.slice(0, 5),
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// QUEUE MESSAGE HANDLER (Cloudflare Queue Consumer)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * This function is called by the Cloudflare Queue consumer worker.
 * It processes Tier 3 jobs that were queued by the main worker.
 *
 * In wrangler.toml:
 *   [[queues.consumers]]
 *   queue = "vericore-deep"
 *   max_batch_size = 5
 *   max_batch_timeout = 30
 */
async function handleQueueMessage(batch, env) {
  const { Verifier } = require('./verifier');
  const verifier = Verifier.fromEnv(env);

  for (const message of batch.messages) {
    try {
      const { eoId, tier2Result } = message.body;

      // Load EO from storage
      const eoJson = await env.KV.get(`eo:${eoId}`);
      if (!eoJson) { message.ack(); continue; }

      const eoData = JSON.parse(eoJson);

      // Run Tier 3
      const tier3 = await verifier.tier3.analyze(eoData, tier2Result);

      // Save final result
      await env.KV.put(`result:${eoId}`, JSON.stringify({
        status: 'complete',
        score:  tier3.finalScore,
        flags:  tier3.flags,
        deep:   tier3.deep,
        tier:   3,
        ts:     Date.now(),
      }), { expirationTtl: 86400 * 7 });

      // Notify via D1 (so the frontend can poll)
      await env.DB.prepare(
        'UPDATE verifications SET status = ?, score = ?, updated_at = ? WHERE id = ?'
      ).bind('complete', tier3.finalScore.overall, new Date().toISOString(), eoId).run();

      message.ack();
    } catch (err) {
      console.error('Queue processing error:', err);
      message.retry();
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SCORE COMPUTATION HELPERS
// ─────────────────────────────────────────────────────────────────────────────

function computePreliminaryScore(flags, type) {
  const base = { image: 0.65, article: 0.55, tweet: 0.50, email: 0.60 }[type] || 0.55;
  const penalties = { critical: 0.30, high: 0.15, medium: 0.08 };
  const penalty = flags.reduce((s, f) => s + (penalties[f.severity] || 0), 0);
  return Math.max(0.05, base - penalty);
}

function computeTier2Score(components, flags) {
  const sourceTrust = components.sourceTrust?.trust ?? 0.5;
  const aiPenalty   = components.imageAI?.score > 0.6 ? (components.imageAI.score - 0.6) * 0.5 : 0;
  const flagPenalty = flags.reduce((s, f) => {
    return s + { critical: 0.25, high: 0.12, medium: 0.06, low: 0.02 }[f.severity] || 0;
  }, 0);

  return Math.max(0.05, (sourceTrust * 0.6 + 0.4) / 2 - aiPenalty - flagPenalty);
}

function computeFinalScore(tier2, flags, deep) {
  const components = {
    aiAuthenticity:  deep.aiEnsemble ? 1 - (deep.aiEnsemble.combined || 0) : 0.7,
    provenance:      deep.blockchain?.found ? 0.90 : 0.40,
    corroboration:   Math.min(1, (deep.corroborations?.independentCount || 0) * 0.15 + 0.25),
    sourceReputation: tier2.components?.sourceTrust?.trust || 0.5,
    historicalOk:    deep.historical?.consistencyScore || 0.7,
  };

  const weights = { aiAuthenticity: 0.25, provenance: 0.15, corroboration: 0.25,
                    sourceReputation: 0.20, historicalOk: 0.15 };

  let score = 0;
  for (const [k, w] of Object.entries(weights)) {
    score += (components[k] || 0.5) * w;
  }

  const criticals = flags.filter(f => f.severity === 'critical').length;
  const highs     = flags.filter(f => f.severity === 'high').length;
  score = score * (1 - criticals * 0.25 - highs * 0.10);

  return {
    overall:    Math.max(0.02, Math.min(0.98, score)),
    components,
    flagCount:  flags.length,
    confidence: Math.min(0.95, 0.5 + (deep.corroborations?.independentCount || 0) * 0.08),
  };
}

function validateFormat(input, type) {
  if (type === 'email' && typeof input === 'string') {
    return { valid: /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input), reason: 'Invalid email format' };
  }
  if (type === 'website' && typeof input === 'string') {
    try { new URL(input.startsWith('http') ? input : `https://${input}`); return { valid: true }; }
    catch { return { valid: false, reason: 'Invalid URL' }; }
  }
  return { valid: true };
}

function extractDomain(url) {
  try {
    return new URL(url.startsWith('http') ? url : `https://${url}`).hostname.replace(/^www\./, '');
  } catch { return url; }
}

module.exports = {
  Tier1Analyzer,
  Tier2Analyzer,
  Tier3Analyzer,
  handleQueueMessage,
  computeFinalScore,
};

