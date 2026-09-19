/**
 * VERICORE 2.0 — Cloudflare Worker Entry Point
 * ===============================================
 * This is the main Worker that handles all API requests.
 *
 * Routes:
 *   POST /api/verify          — Submit content for verification
 *   GET  /api/result/:id      — Poll for result (Tier 3 completes async)
 *   GET  /api/status          — System status
 *   POST /api/feedback        — Submit expert outcome (for learning)
 *
 * Bindings needed in wrangler.toml:
 *   [[kv_namespaces]]          KV namespace (VERICORE_KV)
 *   [[d1_databases]]           D1 database (VERICORE_DB)
 *   [[queues.producers]]       Queue (VERICORE_QUEUE) for Tier 3
 *   [[vectorize]]              Vectorize index (VERICORE_VECTORS)
 *
 * Env vars (set in Cloudflare dashboard, encrypted):
 *   HUGGINGFACE_API_KEY
 *   BRAVE_SEARCH_KEY
 *   ETHERSCAN_KEY
 *   GOOGLE_SAFE_BROWSING_KEY
 */

import { EvidenceObject, EVIDENCE_TYPES, sha256, flag } from './evidence.js';
import { HuggingFaceClient, ImageAIDetector, TextAIDetector, AudioAIDetector, VideoAIDetector } from './ai-detection.js';
import { WaybackClient, RDAPClient, SearchClient, BlockchainVerifier, VectorStore, EmailVerifier, SSLChecker, SafeBrowsingClient } from './retrieval.js';
import { SourceTrustEngine } from './source-trust.js';
import { Tier1Analyzer, Tier2Analyzer, Tier3Analyzer, handleQueueMessage } from './pipeline.js';
// ─────────────────────────────────────────────────────────────────────────────
// CORS HEADERS (allow all origins for a public API)
// ─────────────────────────────────────────────────────────────────────────────

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age':       '86400',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

function err(message, status = 400) {
  return json({ error: message }, status);
}

// ─────────────────────────────────────────────────────────────────────────────
// SERVICE FACTORY (builds all dependencies from env bindings)
// ─────────────────────────────────────────────────────────────────────────────

function buildServices(env) {
  const hf         = new HuggingFaceClient(env.HUGGINGFACE_API_KEY, env.VERICORE_KV);
  const rdap       = new RDAPClient();
  const ssl        = new SSLChecker();
  const wayback    = new WaybackClient();
  const search     = new SearchClient(env.BRAVE_SEARCH_KEY, env.VERICORE_KV);
  const blockchain = new BlockchainVerifier(env.ETHERSCAN_KEY, env.VERICORE_KV);
  const vectorStore = env.VERICORE_VECTORS ? new VectorStore(env.VERICORE_VECTORS, hf) : null;
  const emailVer   = new EmailVerifier();
  const safeBrowse = new SafeBrowsingClient(env.GOOGLE_SAFE_BROWSING_KEY);
  const sourceTrust = new SourceTrustEngine(env.VERICORE_DB, env.VERICORE_KV, rdap, ssl);

  const imageAI = new ImageAIDetector(hf);
  const textAI  = new TextAIDetector(hf);
  const audioAI = new AudioAIDetector(hf);
  const videoAI = new VideoAIDetector(hf, imageAI);

  const tier1 = new Tier1Analyzer(env.VERICORE_KV);
  const tier2 = new Tier2Analyzer({ sourceTrust, wayback, rdap, ssl, safeBrowsing: safeBrowse, imageAI, textAI, kv: env.VERICORE_KV });
  const tier3 = new Tier3Analyzer({ imageAI, blockchain, crossRef: null, antiManip: null, identity: null, history: null, vectorStore, search });

  return { hf, rdap, ssl, wayback, search, blockchain, vectorStore, emailVer, safeBrowse,
           sourceTrust, imageAI, textAI, audioAI, videoAI, tier1, tier2, tier3 };
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN HANDLER
// ─────────────────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const url    = new URL(request.url);
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    try {
      // ── Route: Submit for verification ──────────────────────────────────
      if (method === 'POST' && url.pathname === '/api/verify') {
        return handleVerify(request, env, ctx);
      }

      // ── Route: Poll for result ───────────────────────────────────────────
      if (method === 'GET' && url.pathname.startsWith('/api/result/')) {
        const id = url.pathname.split('/').pop();
        return handleResult(id, env);
      }

      // ── Route: Feedback (expert review outcome) ──────────────────────────
      if (method === 'POST' && url.pathname === '/api/feedback') {
        return handleFeedback(request, env);
      }

      // ── Route: System status ─────────────────────────────────────────────
      if (method === 'GET' && url.pathname === '/api/status') {
        return json({ status: 'online', version: '2.0.0', ts: Date.now() });
      }

      // ── Serve static UI (index.html) ─────────────────────────────────────
      if (method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
        return env.ASSETS.fetch(request);
      }

      return err('Not found', 404);
    } catch (e) {
      console.error('Worker error:', e);
      return err('Internal server error', 500);
    }
  },

  // Cloudflare Queue consumer
  async queue(batch, env) {
    return handleQueueMessage(batch, env);
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// VERIFY HANDLER
// ─────────────────────────────────────────────────────────────────────────────

async function handleVerify(request, env, ctx) {
  const body = await request.json().catch(() => null);
  if (!body) return err('Invalid JSON body');

  const { type, content, url: inputUrl, claimedDate } = body;

  // Validate type
  if (!type || !Object.values(EVIDENCE_TYPES).includes(type)) {
    return err(`Invalid type. Must be one of: ${Object.values(EVIDENCE_TYPES).join(', ')}`);
  }

  // Determine raw input
  const rawInput = content || inputUrl;
  if (!rawInput) return err('Provide either "content" or "url"');

  // Create Evidence Object
  const eo = new EvidenceObject(rawInput, type);
  if (inputUrl) eo.source = inputUrl;
  if (claimedDate) eo.timestamp.claimed = claimedDate;

  // Compute hash
  const inputStr = typeof rawInput === 'string' ? rawInput : JSON.stringify(rawInput);
  eo.hashes.sha256 = await sha256(inputStr);

  // Build services
  const services = buildServices(env);

  // TIER 1 — Instant (always synchronous)
  const tier1 = await services.tier1.analyze(rawInput, type, eo.hashes.sha256);

  if (tier1.cached) {
    return json({ id: eo.id, status: 'complete', ...tier1.result });
  }

  // TIER 2 — Fast (synchronous, < 2s)
  const tier2 = await services.tier2.analyze(eo, tier1);

  // Store EO in KV for async Tier 3
  await env.VERICORE_KV?.put(
    `eo:${eo.id}`,
    JSON.stringify(eo.toJSON()),
    { expirationTtl: 3600 }
  );

  // Record in D1
  await env.VERICORE_DB?.prepare(`
    INSERT INTO verifications (id, type, source, status, score, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(
    eo.id, type, eo.source || null,
    tier2.needsTier3 ? 'processing' : 'complete',
    tier2.score, new Date().toISOString()
  ).run().catch(() => {});

  // Queue Tier 3 if needed (async — doesn't block response)
  if (tier2.needsTier3 && env.VERICORE_QUEUE) {
    ctx.waitUntil(
      env.VERICORE_QUEUE.send({
        eoId:       eo.id,
        tier2Result: tier2,
      })
    );
  }

  // Return immediate result with tier 2 score
  return json({
    id:          eo.id,
    status:      tier2.needsTier3 ? 'processing' : 'complete',
    score:       tier2.score,
    flags:       tier2.flags,
    components:  tier2.components,
    tier:        2,
    deepPending: tier2.needsTier3,
    deepReason:  tier2.tier3Reason,
    // Client should poll /api/result/:id if deepPending = true
    pollUrl:     `/api/result/${eo.id}`,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// RESULT POLLING HANDLER
// ─────────────────────────────────────────────────────────────────────────────

async function handleResult(id, env) {
  if (!id || id.length < 10) return err('Invalid ID', 400);

  // Check KV for completed Tier 3 result
  const result = await env.VERICORE_KV?.get(`result:${id}`);
  if (result) return json({ id, status: 'complete', ...JSON.parse(result) });

  // Check D1 for current status
  const row = await env.VERICORE_DB?.prepare(
    'SELECT status, score, updated_at FROM verifications WHERE id = ?'
  ).bind(id).first().catch(() => null);

  if (!row) return err('Verification not found', 404);

  return json({
    id,
    status:    row.status,
    score:     row.score,
    updatedAt: row.updated_at,
    message:   row.status === 'processing' ? 'Deep analysis in progress. Poll again in 5s.' : null,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// FEEDBACK HANDLER (for continuous learning)
// ─────────────────────────────────────────────────────────────────────────────

async function handleFeedback(request, env) {
  const body = await request.json().catch(() => null);
  if (!body) return err('Invalid JSON');

  const { id, correct, groundTruth, botConfirmed, retracted, corrected } = body;
  if (!id) return err('id required');

  const services = buildServices(env);

  // Get the original verification
  const row = await env.VERICORE_DB?.prepare(
    'SELECT source FROM verifications WHERE id = ?'
  ).bind(id).first().catch(() => null);

  if (row?.source) {
    await services.sourceTrust.updateAfterVerification(
      row.source.includes('://') ? new URL(row.source).hostname : row.source,
      { correct: correct ?? true, retracted: retracted ?? false, corrected: corrected ?? false }
    );
  }

  // Store outcome for calibration
  await env.VERICORE_DB?.prepare(`
    INSERT INTO verification_outcomes (eo_id, correct, ground_truth, created_at)
    VALUES (?, ?, ?, ?)
  `).bind(id, correct ? 1 : 0, groundTruth ?? null, new Date().toISOString())
    .run().catch(() => {});

  return json({ success: true, message: 'Feedback recorded. System will learn from this outcome.' });
}
