/**
 * VERICORE — Usage Examples & Integration Guide
 * =============================================
 */

const {
  Verifier,
  EVIDENCE_TYPES,
  PlatformAdapters,
} = require('./vericore');

// ─────────────────────────────────────────────────────────────────────────────
// BOOTSTRAP — Initialize Verifier with your infrastructure adapters
// ─────────────────────────────────────────────────────────────────────────────

const verifier = new Verifier({
  // Your database adapter (MongoDB, PostgreSQL, etc.)
  database: {
    getSource: async (domain) => null,   // Load source trust record
    setSource: async (domain, data) => {},
    getEORecord: async (id) => null,
    addConfirmedBot: async (id) => {},
    addManipulatedImageFingerprint: async (hash) => {},
    addCalibrationPoint: async (point) => {},
  },

  // Blockchain RPC endpoints
  rpcProviders: {
    ethereum: null,   // ethers.js provider or viem client
    bitcoin:  null,   // bitcoin RPC or Mempool.space API
  },

  // Web search API (Brave Search, SerpAPI, Google Custom Search, etc.)
  searchApi: {
    search: async (query, opts) => [],
    reverseImageSearch: async (hash) => [],
  },

  // Source ownership graph (who owns what)
  sourceGraph: {
    getRoot: (domain) => domain,
    getOwner: async (domain) => null,
  },

  // Wayback Machine / Common Crawl client
  archiveClient: {
    compareVersions: async (url) => ({ significantChanges: [] }),
    findEarliestMention: async (eo) => null,
  },

  // Knowledge graph (Neo4j, custom, etc.)
  knowledgeGraph: {
    addClaim: async (eo, rels) => {},
    query: async (claim) => ({ confirms: false, contradicts: false }),
    findSimilarClaims: async (text) => [],
    getRoot: (domain) => domain,
    getNode: async (id) => null,
    upsertNode: async (node) => {},
    addEdge: async (edge) => {},
    findEdges: async (id, type, opts) => [],
    updateNodeScore: async (id, score) => {},
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// EXAMPLE 1 — Verify a news article
// ─────────────────────────────────────────────────────────────────────────────

async function exampleArticle() {
  const result = await verifier.verify(
    'https://www.reuters.com/article/example-story-2024',
    EVIDENCE_TYPES.ARTICLE,
    {
      claimedDate: '2024-03-15T10:00:00Z',
    }
  );

  console.log('=== ARTICLE VERIFICATION ===');
  console.log(result.scores.explanation);
  console.log('\nOverall score:', result.scores.overall);
  console.log('Flags:', result.scores.flags.length);
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// EXAMPLE 2 — Check if an Instagram account is authentic
// ─────────────────────────────────────────────────────────────────────────────

async function exampleInstagram() {
  const result = await verifier.verify(
    'https://www.instagram.com/exampleuser',
    EVIDENCE_TYPES.INSTAGRAM,
  );

  console.log('=== INSTAGRAM VERIFICATION ===');
  console.log('Identity score:', result.author.identityScore?.score);
  console.log('Source trust:', result.scores.components?.sourceReputation);
  console.log('Manipulation score:', result.scores.components?.manipulation);
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// EXAMPLE 3 — Verify a Spotify artist (human vs AI music spam)
// ─────────────────────────────────────────────────────────────────────────────

async function exampleSpotify() {
  const result = await verifier.verify(
    'https://open.spotify.com/artist/exampleartist',
    EVIDENCE_TYPES.SPOTIFY_ARTIST,
  );

  // Key signals for AI music detection are stored in metadata:
  // - Very high release frequency (>5 tracks/month) with 0 live performances
  // - No social presence despite claimed follower count
  // - Follower/listener ratio outside normal bounds
  // - No press playlist placements
  // - Generic or keyword-stuffed biography

  console.log('=== SPOTIFY ARTIST VERIFICATION ===');
  console.log('Release frequency:', result.metadata.releaseFrequency, 'tracks/month');
  console.log('Live events:', result.metadata.livePerformances);
  console.log('Has social links:', result.metadata.socialPresence);
  console.log('Overall score:', result.scores.overall);
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// EXAMPLE 4 — Multi-source claim verification (the gold standard)
// ─────────────────────────────────────────────────────────────────────────────

async function exampleCrossReference() {
  // Step 1: Verify the primary claim
  const primary = await verifier.verify(
    'Earthquake magnitude 7.2 struck off the coast of Japan at 14:32 UTC',
    EVIDENCE_TYPES.ARTICLE,
    { claimedDate: new Date().toISOString() }
  );

  // The cross-reference engine will automatically search for:
  // - USGS seismic data (government source, very high trust)
  // - Japanese Meteorological Agency (government source, very high trust)
  // - Major wire services (Reuters, AP, AFP)
  // - Seismograph readings (scientific instruments)
  // - Social media from affected area (lower weight, but proximity signal)

  console.log('=== CROSS-REFERENCE VERIFICATION ===');
  console.log('Overall score:', primary.scores.overall);
  console.log('Corroboration confidence:', primary.scores.components?.corroboration);
  console.log('Contradictions:', primary.scores.flags.filter(f => f.type.includes('CONTRADICT')).length);
  return primary;
}

// ─────────────────────────────────────────────────────────────────────────────
// EXAMPLE 5 — Blockchain wallet verification
// ─────────────────────────────────────────────────────────────────────────────

async function exampleBlockchain() {
  const result = await verifier.verify(
    '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
    EVIDENCE_TYPES.BLOCKCHAIN_TX,
  );

  console.log('=== BLOCKCHAIN WALLET VERIFICATION ===');
  console.log('Chain:', result.metadata.chain);
  console.log('Tx count:', result.metadata.txCount);
  console.log('First tx:', result.metadata.firstTx);
  console.log('Sanctions list:', result.metadata.sanctionsList);
  console.log('Known labels:', result.metadata.knownLabels);
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// EXAMPLE 6 — Record a learning outcome (after expert review)
// ─────────────────────────────────────────────────────────────────────────────

async function exampleFeedbackLoop(eoId) {
  // After a human expert reviews the content and confirms it was fake:
  await verifier.learning.recordOutcome(eoId, {
    correct:              false,   // Our score was wrong
    groundTruth:          0.05,    // Expert says: nearly 0 truth score
    retracted:            false,
    corrected:            false,
    botConfirmed:         true,    // Author was a confirmed bot
    manipulationConfirmed: true,   // Content was AI-generated
    domain:               'example-fake-news-site.com',
    authorId:             'bot_account_12345',
    imagePHash:           'abc123def456...',
  });

  // This updates:
  // - example-fake-news-site.com trust score (down)
  // - bot_account_12345 added to confirmed bot DB
  // - Manipulated image hash added to reference DB
  // - AI detector calibration data updated

  console.log('Feedback recorded. All subsystems updated.');
}

// ─────────────────────────────────────────────────────────────────────────────
// EXAMPLE 7 — Full pipeline demonstration
// ─────────────────────────────────────────────────────────────────────────────

async function runDemo() {
  console.log('VERICORE — Universal Evidence Verification System');
  console.log('='.repeat(50));
  console.log('');
  console.log('10 Laws of VERICORE:');
  console.log('  1. Everything is an Evidence Object');
  console.log('  2. Trust hashes, not files');
  console.log('  3. No single classifier decides');
  console.log('  4. Everything versioned, nothing overwritten');
  console.log('  5. Explainability is mandatory');
  console.log('  6. Contradiction is a first-class signal');
  console.log('  7. Corroboration is multiplicative');
  console.log('  8. Manipulation leaves patterns');
  console.log('  9. Identity is a probability');
  console.log(' 10. The system learns');
  console.log('');
  console.log('Evidence types supported:', Object.values(EVIDENCE_TYPES).length);
  console.log('Engines:', [
    'SourceTrustEngine',
    'MetadataEngine',
    'AIDetectionEngine',
    'BlockchainLayer',
    'CrossReferenceEngine',
    'HistoricalConsistencyEngine',
    'AntiManipulationEngine',
    'KnowledgeGraph',
    'IdentityEngine',
    'ConfidenceModel',
    'ContinuousLearningSystem',
  ].length);
  console.log('');
  console.log('All systems initialized. Ready to verify.');
}

runDemo();

module.exports = {
  verifier,
  exampleArticle,
  exampleInstagram,
  exampleSpotify,
  exampleCrossReference,
  exampleBlockchain,
  exampleFeedbackLoop,
};
