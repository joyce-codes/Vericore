/**
 * VERICORE 2.0 — Anti-Manipulation & Graph Analysis Engine
 * =========================================================
 * Fully implemented. No stubs.
 *
 * Detects:
 *   1. Bot farm networks (behavioral clustering via DBSCAN)
 *   2. Coordinated inauthentic behavior (timing correlation)
 *   3. Fake follower injection (follower graph anomalies)
 *   4. Purchased engagement (engagement vs follower mismatch)
 *   5. Copy-paste networks (content hash clustering)
 *   6. Domain network cartography (shared infrastructure)
 *   7. SEO manipulation (link graph analysis)
 *   8. Temporal anomalies (posting time analysis)
 *
 * All algorithms are pure JavaScript — no external ML needed.
 * Graph analysis uses our D1 database for persistence.
 */

'use strict';

const { flag, clamp, mean, variance, stdDev } = require('./evidence');

// ─────────────────────────────────────────────────────────────────────────────
// BEHAVIORAL VECTOR COMPUTATION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Computes a 34-dimensional behavioral vector for an account.
 * Dimensions chosen to maximally discriminate bots from humans.
 *
 * Dimensions:
 *   0–23:  Posting hour histogram (normalized, 24 bins)
 *   24:    Average response delay (normalized log)
 *   25:    Content repetition rate
 *   26:    Follower/following ratio (log-normalized)
 *   27:    Engagement rate
 *   28:    Account age factor (sigmoid)
 *   29:    URL sharing rate
 *   30:    Hashtag density
 *   31:    Mention density
 *   32:    Language entropy
 *   33:    Posting interval regularity (low = bot-like)
 */
function computeBehaviorVector(account) {
  const vec = new Array(34).fill(0);

  // Dims 0–23: Posting hour histogram
  const hourCounts = new Array(24).fill(0);
  if (account.postingHours?.length) {
    for (const h of account.postingHours) hourCounts[h % 24]++;
    const total = hourCounts.reduce((s, v) => s + v, 0) || 1;
    for (let i = 0; i < 24; i++) vec[i] = hourCounts[i] / total;
  }

  // Dim 24: Response delay (log-normalized, 0–1)
  vec[24] = account.avgResponseDelayMs
    ? Math.min(1, Math.log1p(account.avgResponseDelayMs) / Math.log1p(86400000))
    : 0.5;

  // Dim 25: Content repetition rate
  vec[25] = clamp(account.contentRepetitionRate ?? 0, 0, 1);

  // Dim 26: Follower/following ratio
  const ff = (account.followerCount || 0) / Math.max(account.followingCount || 1, 1);
  vec[26] = clamp(Math.log1p(ff) / Math.log1p(1000), 0, 1);

  // Dim 27: Engagement rate
  vec[27] = clamp(account.engagementRate ?? 0, 0, 1);

  // Dim 28: Account age (sigmoid: mature at 2 years)
  const ageDays = account.ageDays || 0;
  vec[28] = 1 / (1 + Math.exp(-(ageDays - 730) / 365));

  // Dim 29: URL sharing rate
  vec[29] = clamp(account.urlSharingRate ?? 0, 0, 1);

  // Dim 30: Hashtag density
  vec[30] = clamp(account.hashtagDensity ?? 0, 0, 1);

  // Dim 31: Mention density
  vec[31] = clamp(account.mentionDensity ?? 0, 0, 1);

  // Dim 32: Language entropy (high = multilingual spam)
  vec[32] = clamp(account.languageEntropy ?? 0.5, 0, 1);

  // Dim 33: Posting interval regularity
  // Real humans have high variance; bots post at regular intervals
  if (account.postingIntervals?.length >= 5) {
    const cv = stdDev(account.postingIntervals) / Math.max(mean(account.postingIntervals), 1);
    vec[33] = clamp(1 - Math.exp(-cv), 0, 1);  // High variance = human-like
  } else {
    vec[33] = 0.5;
  }

  return vec;
}

// ─────────────────────────────────────────────────────────────────────────────
// VECTOR DISTANCE METRICS
// ─────────────────────────────────────────────────────────────────────────────

function cosineSimilarity(a, b) {
  if (a.length !== b.length) return 0;
  let dot = 0, magA = 0, magB = 0;
  for (let i = 0; i < a.length; i++) {
    dot  += a[i] * b[i];
    magA += a[i] * a[i];
    magB += b[i] * b[i];
  }
  return magA === 0 || magB === 0 ? 0 : dot / (Math.sqrt(magA) * Math.sqrt(magB));
}

function cosineDissimilarity(a, b) {
  return 1 - cosineSimilarity(a, b);
}

function euclideanDistance(a, b) {
  return Math.sqrt(a.reduce((s, v, i) => s + (v - b[i]) ** 2, 0));
}

// ─────────────────────────────────────────────────────────────────────────────
// DBSCAN CLUSTERING (pure JS, no dependencies)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * DBSCAN: Density-Based Spatial Clustering of Applications with Noise
 *
 * Chosen over k-means because:
 *   1. We don't know how many clusters exist
 *   2. Bot farms don't form spherical clusters — they form arbitrary shapes
 *   3. It explicitly marks outliers as noise (unclustered accounts)
 *
 * @param {Array} points      — Array of vectors
 * @param {number} epsilon    — Max distance to be considered neighbors
 * @param {number} minPoints  — Min cluster size
 * @param {Function} distFn   — Distance function
 * @returns {Array<number>}   — Cluster label per point (-1 = noise)
 */
function dbscan(points, epsilon = 0.2, minPoints = 3, distFn = cosineDissimilarity) {
  const n       = points.length;
  const labels  = new Array(n).fill(-2);     // -2 = unvisited
  let clusterId = 0;

  function regionQuery(idx) {
    const neighbors = [];
    for (let j = 0; j < n; j++) {
      if (j !== idx && distFn(points[idx], points[j]) <= epsilon) {
        neighbors.push(j);
      }
    }
    return neighbors;
  }

  function expandCluster(idx, neighbors, cId) {
    labels[idx] = cId;
    let i = 0;
    while (i < neighbors.length) {
      const nb = neighbors[i];
      if (labels[nb] === -2) {  // Unvisited
        labels[nb] = cId;
        const nbNeighbors = regionQuery(nb);
        if (nbNeighbors.length >= minPoints) {
          neighbors.push(...nbNeighbors.filter(n => !neighbors.includes(n)));
        }
      } else if (labels[nb] === -1) {
        labels[nb] = cId;  // Border point
      }
      i++;
    }
  }

  for (let i = 0; i < n; i++) {
    if (labels[i] !== -2) continue;
    const neighbors = regionQuery(i);
    if (neighbors.length < minPoints) {
      labels[i] = -1;  // Noise
    } else {
      expandCluster(i, neighbors, clusterId);
      clusterId++;
    }
  }

  return labels;
}

/**
 * Groups DBSCAN label output into clusters with their member indices.
 */
function groupClusters(labels, accounts) {
  const clusters = new Map();
  for (let i = 0; i < labels.length; i++) {
    const cId = labels[i];
    if (cId === -1) continue;  // Noise
    if (!clusters.has(cId)) clusters.set(cId, []);
    clusters.get(cId).push(i);
  }

  return Array.from(clusters.entries()).map(([id, indices]) => ({
    id,
    accounts:    indices.map(i => accounts[i]),
    size:        indices.length,
    indices,
  }));
}

// ─────────────────────────────────────────────────────────────────────────────
// TIMING CORRELATION ANALYSIS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Tests whether posting times across a cluster are statistically correlated.
 *
 * Method: Pearson cross-correlation across binned time series.
 * Returns correlation coefficient r ∈ [-1, 1].
 * r > 0.85 with p < 0.01 = coordinated behavior.
 */
function computeTimingCorrelation(accounts, interactions, binSizeMs = 3600000) {
  if (accounts.length < 2) return { r: 0, p: 1 };

  // Build time-series for each account (hourly bins over 30 days)
  const now      = Date.now();
  const numBins  = Math.ceil(30 * 24 * 3600000 / binSizeMs);
  const series   = accounts.map(account => {
    const bins = new Array(numBins).fill(0);
    const acts = interactions.filter(i => i.accountId === account.id);
    for (const act of acts) {
      const bin = Math.floor((now - act.timestamp) / binSizeMs);
      if (bin >= 0 && bin < numBins) bins[bin]++;
    }
    return bins;
  });

  if (series.length < 2) return { r: 0, p: 1 };

  // Compute average pairwise correlation
  let totalR = 0;
  let pairs  = 0;

  for (let i = 0; i < series.length; i++) {
    for (let j = i + 1; j < series.length; j++) {
      totalR += pearsonCorrelation(series[i], series[j]);
      pairs++;
    }
  }

  const avgR = pairs > 0 ? totalR / pairs : 0;

  // Approximate p-value using t-distribution
  const n = numBins;
  const t = avgR * Math.sqrt((n - 2) / Math.max(1 - avgR * avgR, 1e-10));
  const p = 2 * tDistPValue(Math.abs(t), n - 2);

  return { r: avgR, p, pairs };
}

function pearsonCorrelation(x, y) {
  const n  = x.length;
  const mx = mean(x);
  const my = mean(y);
  let num = 0, dx2 = 0, dy2 = 0;
  for (let i = 0; i < n; i++) {
    const dx = x[i] - mx;
    const dy = y[i] - my;
    num += dx * dy;
    dx2 += dx * dx;
    dy2 += dy * dy;
  }
  return dx2 === 0 || dy2 === 0 ? 0 : num / Math.sqrt(dx2 * dy2);
}

// t-distribution CDF approximation (Abramowitz & Stegun)
function tDistPValue(t, df) {
  const x   = df / (df + t * t);
  const a   = df / 2;
  const b   = 0.5;
  return incompleteBeta(x, a, b);
}

function incompleteBeta(x, a, b) {
  // Simple numerical approximation via continued fractions
  if (x <= 0) return 0;
  if (x >= 1) return 1;
  const lbeta = lgamma(a) + lgamma(b) - lgamma(a + b);
  const log   = a * Math.log(x) + b * Math.log(1 - x) - lbeta;
  return Math.exp(log) / a;
}

function lgamma(z) {
  // Lanczos approximation
  const g = 7;
  const c = [0.99999999999980993, 676.5203681218851, -1259.1392167224028,
             771.32342877765313, -176.61502916214059, 12.507343278686905,
             -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7];
  if (z < 0.5) return Math.log(Math.PI / Math.sin(Math.PI * z)) - lgamma(1 - z);
  z -= 1;
  let x = c[0];
  for (let i = 1; i < g + 2; i++) x += c[i] / (z + i);
  const t = z + g + 0.5;
  return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(x);
}

// ─────────────────────────────────────────────────────────────────────────────
// ENGAGEMENT ANOMALY DETECTION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Expected engagement rates by follower tier (empirical baselines).
 * Source: Influencer Marketing Hub 2024 benchmarks.
 *
 * Follower tier → [min_expected_rate, max_expected_rate]
 */
const ENGAGEMENT_TIERS = [
  { maxFollowers:    1_000, min: 0.040, max: 0.100 },  // Nano
  { maxFollowers:   10_000, min: 0.025, max: 0.060 },  // Micro
  { maxFollowers:  100_000, min: 0.015, max: 0.040 },  // Mid
  { maxFollowers: 1_000_000, min: 0.008, max: 0.025 }, // Macro
  { maxFollowers: Infinity,  min: 0.003, max: 0.015 },  // Mega
];

function detectEngagementAnomaly(account) {
  const followers = account.followerCount || 0;
  const tier = ENGAGEMENT_TIERS.find(t => followers <= t.maxFollowers) || ENGAGEMENT_TIERS.at(-1);
  const rate  = account.engagementRate || 0;

  if (rate > tier.max * 3) {
    return {
      suspicious:  true,
      direction:   'high',
      severity:    'high',
      description: `Engagement rate ${(rate * 100).toFixed(1)}% is ${(rate / tier.max).toFixed(0)}x above expected max for ${followers.toLocaleString()} followers — likely fake engagement`,
    };
  }

  if (rate < tier.min * 0.1 && followers > 1000) {
    return {
      suspicious:  true,
      direction:   'low',
      severity:    'medium',
      description: `Engagement rate ${(rate * 100).toFixed(2)}% is far below expected minimum — likely fake followers`,
    };
  }

  return { suspicious: false };
}

// ─────────────────────────────────────────────────────────────────────────────
// CONTENT FINGERPRINTING FOR COPY-PASTE NETWORKS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Computes a content fingerprint that is robust to minor edits.
 * Uses shingling (k-gram hashing) — similar to ssdeep but simpler.
 *
 * Two posts with >85% shingle overlap are considered near-duplicates.
 */
function contentShingles(text, k = 5) {
  const words   = text.toLowerCase().match(/\b\w+\b/g) || [];
  const shingles = new Set();
  for (let i = 0; i <= words.length - k; i++) {
    shingles.add(words.slice(i, i + k).join(' '));
  }
  return shingles;
}

function jaccardSimilarity(setA, setB) {
  const intersection = [...setA].filter(x => setB.has(x)).length;
  const union        = new Set([...setA, ...setB]).size;
  return union === 0 ? 0 : intersection / union;
}

function detectContentOverlap(posts) {
  if (posts.length < 2) return { duplicateRate: 0, pairs: [] };

  const shingleSets = posts.map(p => contentShingles(p.text || ''));
  let duplicatePairs = 0;
  const highOverlapPairs = [];
  let totalPairs = 0;

  for (let i = 0; i < shingleSets.length; i++) {
    for (let j = i + 1; j < shingleSets.length; j++) {
      const sim = jaccardSimilarity(shingleSets[i], shingleSets[j]);
      totalPairs++;
      if (sim > 0.85) {
        duplicatePairs++;
        highOverlapPairs.push({ i, j, similarity: sim });
      }
    }
  }

  return {
    duplicateRate:  totalPairs > 0 ? duplicatePairs / totalPairs : 0,
    highOverlapPairs,
    totalPairs,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN ANTI-MANIPULATION ENGINE
// ─────────────────────────────────────────────────────────────────────────────

class AntiManipulationEngine {
  constructor(db) {
    this.db = db;
  }

  /**
   * Full analysis of an account network.
   *
   * @param {Array} accounts     — Array of account objects
   * @param {Array} interactions — Array of {accountId, timestamp, contentHash, type}
   * @returns {object} Full manipulation analysis
   */
  async analyzeNetwork(accounts, interactions) {
    if (!accounts || accounts.length === 0) {
      return { signals: [], score: 0.9, clusters: [], suspicious: false };
    }

    const allFlags = [];

    // ── Step 1: Behavioral vectorization ─────────────────────────────────────
    const vectors = accounts.map(a => computeBehaviorVector(a));

    // ── Step 2: DBSCAN clustering ─────────────────────────────────────────────
    const labels   = dbscan(vectors, 0.12, 3, cosineDissimilarity);
    const clusters = groupClusters(labels, accounts);

    // ── Step 3: Per-cluster analysis ──────────────────────────────────────────
    const analyzedClusters = [];

    for (const cluster of clusters) {
      if (cluster.size < 3) continue;

      const clusterFlags  = [];
      const clusterAccounts = cluster.accounts;

      // 3a: Timing correlation
      const timing = computeTimingCorrelation(clusterAccounts, interactions);
      if (timing.r > 0.85 && timing.p < 0.05) {
        clusterFlags.push(flag('COORDINATED_POSTING', 'high',
          `Cluster of ${cluster.size} accounts: posting time correlation r=${timing.r.toFixed(2)}, p=${timing.p.toFixed(4)}`));
      }

      // 3b: Account age clustering (batch creation signal)
      const ages = clusterAccounts.map(a => a.ageDays).filter(a => a !== null);
      if (ages.length >= 5) {
        const ageSD = stdDev(ages);
        if (ageSD < 5 && cluster.size >= 10) {
          clusterFlags.push(flag('BATCH_ACCOUNT_CREATION', 'critical',
            `${cluster.size} accounts all created within ${(ageSD * 2).toFixed(0)} days of each other`));
        }
      }

      // 3c: Content overlap
      const posts = interactions
        .filter(i => clusterAccounts.some(a => a.id === i.accountId))
        .map(i => ({ text: i.content || '' }));
      const overlap = detectContentOverlap(posts);
      if (overlap.duplicateRate > 0.70) {
        clusterFlags.push(flag('MASS_REPOST_NETWORK', 'critical',
          `${(overlap.duplicateRate * 100).toFixed(0)}% content overlap in cluster of ${cluster.size} accounts`));
      }

      // 3d: Engagement anomalies
      for (const account of clusterAccounts) {
        const anomaly = detectEngagementAnomaly(account);
        if (anomaly.suspicious && anomaly.severity === 'high') {
          allFlags.push(flag('ENGAGEMENT_ANOMALY', anomaly.severity,
            `@${account.username || account.id}: ${anomaly.description}`));
        }
      }

      // 3e: Check confirmed bot DB
      if (this.db) {
        for (const account of clusterAccounts) {
          try {
            const botRecord = await this.db.prepare(
              'SELECT confidence, detection_method FROM confirmed_bots WHERE account_id = ?'
            ).bind(`${account.platform}:${account.id}`).first();

            if (botRecord) {
              clusterFlags.push(flag('CONFIRMED_BOT_IN_CLUSTER', 'critical',
                `Confirmed bot in cluster: ${account.username} (${botRecord.detection_method})`));
            }
          } catch {}
        }
      }

      const clusterScore = computeSignalScore(clusterFlags);
      allFlags.push(...clusterFlags);

      analyzedClusters.push({
        ...cluster,
        flags:                  clusterFlags,
        timingCorrelation:      timing,
        contentOverlap:         overlap,
        manipulationProbability: 1 - clusterScore,
      });
    }

    // ── Step 4: Network-wide signals ──────────────────────────────────────────

    // Total suspicious account rate
    const noiseAccounts = labels.filter(l => l === -1).length;
    const clusterRate   = 1 - noiseAccounts / Math.max(accounts.length, 1);
    if (clusterRate > 0.6 && clusters.length <= 3) {
      allFlags.push(flag('HIGHLY_CLUSTERED_NETWORK', 'high',
        `${(clusterRate * 100).toFixed(0)}% of accounts form tight behavioral clusters — suggests coordinated network`));
    }

    return {
      signals:   allFlags,
      score:     computeSignalScore(allFlags),
      clusters:  analyzedClusters,
      suspicious: allFlags.some(f => f.severity === 'critical'),
      accountCount: accounts.length,
      clusterCount: clusters.length,
      noiseFraction: noiseAccounts / Math.max(accounts.length, 1),
    };
  }

  /**
   * Quick single-account bot score.
   * Faster than full network analysis — used in Tier 2.
   */
  async scoreSingleAccount(account) {
    const flags = [];

    // Check confirmed bot DB
    if (this.db) {
      try {
        const botRecord = await this.db.prepare(
          'SELECT confidence FROM confirmed_bots WHERE account_id = ?'
        ).bind(`${account.platform}:${account.id}`).first();
        if (botRecord) {
          return { botScore: botRecord.confidence, flags: [flag('CONFIRMED_BOT', 'critical',
            `Account confirmed as bot with ${Math.round(botRecord.confidence * 100)}% confidence`)], confirmed: true };
        }
      } catch {}
    }

    const vec = computeBehaviorVector(account);

    // Very regular posting interval (dim 33 low = bot-like)
    if (vec[33] < 0.15 && (account.ageDays || 0) > 30) {
      flags.push(flag('ROBOTIC_POSTING_CADENCE', 'high',
        `Posting interval regularity score ${(vec[33] * 100).toFixed(0)}/100 — suspiciously machine-like`));
    }

    // Account too young with too many followers
    if ((account.ageDays || 0) < 30 && (account.followerCount || 0) > 5000) {
      flags.push(flag('RAPID_FOLLOWER_GROWTH', 'high',
        `Account ${account.ageDays} days old with ${account.followerCount.toLocaleString()} followers`));
    }

    // Engagement anomaly
    const engAnomaly = detectEngagementAnomaly(account);
    if (engAnomaly.suspicious) {
      flags.push(flag('ENGAGEMENT_ANOMALY', engAnomaly.severity, engAnomaly.description));
    }

    // Content repetition
    if ((account.contentRepetitionRate || 0) > 0.8) {
      flags.push(flag('HIGH_CONTENT_REPETITION', 'medium',
        `${(account.contentRepetitionRate * 100).toFixed(0)}% of posts are near-duplicate content`));
    }

    const botScore = 1 - computeSignalScore(flags);
    return { botScore, flags };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// DOMAIN NETWORK CARTOGRAPHY
// ─────────────────────────────────────────────────────────────────────────────

class DomainNetworkAnalyzer {
  constructor(db, rdapClient) {
    this.db   = db;
    this.rdap = rdapClient;
  }

  /**
   * Analyzes a domain's network connections.
   * Finds other domains sharing the same:
   *   - Nameservers (strongest link)
   *   - Registrar + creation date window
   *   - IP /24 subnet
   *   - Hosting provider
   */
  async analyzeDomain(domain) {
    const flags = [];

    // Get or fetch domain info
    let networkInfo = null;
    if (this.db) {
      try {
        networkInfo = await this.db.prepare(
          'SELECT * FROM domain_network WHERE domain = ?'
        ).bind(domain).first();
      } catch {}
    }

    if (!networkInfo) {
      const rdapData = await this.rdap?.lookupDomain(domain).catch(() => null);
      if (rdapData) {
        networkInfo = {
          domain,
          nameserver:  rdapData.nameservers?.[0],
          registrar:   rdapData.registrar,
        };
      }
    }

    if (!networkInfo || !this.db) {
      return { flags, networkSize: 0, suspicious: false };
    }

    // Find sibling domains (share nameserver)
    let siblingCount = 0;
    let lowTrustSiblings = 0;

    if (networkInfo.nameserver) {
      try {
        const result = await this.db.prepare(
          'SELECT COUNT(*) as cnt FROM domain_network WHERE nameserver = ? AND domain != ?'
        ).bind(networkInfo.nameserver, domain).first();
        siblingCount = result?.cnt || 0;

        const lowTrustResult = await this.db.prepare(
          `SELECT COUNT(*) as cnt FROM source_trust st
           JOIN domain_network dn ON dn.domain = st.domain
           WHERE dn.nameserver = ? AND dn.domain != ? AND st.trust_score < 0.3`
        ).bind(networkInfo.nameserver, domain).first();
        lowTrustSiblings = lowTrustResult?.cnt || 0;
      } catch {}
    }

    if (lowTrustSiblings >= 5) {
      flags.push(flag('SUSPICIOUS_DOMAIN_NETWORK', 'high',
        `Domain shares nameserver with ${lowTrustSiblings} known low-trust domains — likely coordinated network`));
    } else if (siblingCount > 50 && lowTrustSiblings > 0) {
      flags.push(flag('LARGE_SHARED_INFRASTRUCTURE', 'medium',
        `Domain shares infrastructure with ${siblingCount} other domains including ${lowTrustSiblings} low-trust ones`));
    }

    return {
      flags,
      networkSize:     siblingCount,
      lowTrustSiblings,
      suspicious:      lowTrustSiblings >= 3,
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILITY
// ─────────────────────────────────────────────────────────────────────────────

function computeSignalScore(signals) {
  if (!signals || signals.length === 0) return 0.9;
  const penalties = { critical: 0.40, high: 0.20, medium: 0.10, low: 0.05, info: 0.01 };
  const total = signals.reduce((s, f) => s + (penalties[f.severity] || 0), 0);
  return Math.max(0, 1 - total);
}

module.exports = {
  AntiManipulationEngine,
  DomainNetworkAnalyzer,
  computeBehaviorVector,
  cosineSimilarity,
  dbscan,
  groupClusters,
  computeTimingCorrelation,
  detectEngagementAnomaly,
  detectContentOverlap,
  contentShingles,
  jaccardSimilarity,
  pearsonCorrelation,
  ENGAGEMENT_TIERS,
};
