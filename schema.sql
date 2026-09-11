-- ============================================================
-- VERICORE 2.0 — Cloudflare D1 Database Schema
-- ============================================================
-- Run this once to initialize your D1 database.
-- Command: wrangler d1 execute VERICORE_DB --file=db/schema.sql
--
-- D1 is Cloudflare's SQLite-compatible serverless database.
-- Free tier: 5 million rows read/day, 100K writes/day, 5GB storage.
-- ============================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ──────────────────────────────────────────────────────────────
-- EVIDENCE OBJECTS
-- Central table. Every verified item lives here.
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS evidence_objects (
    id               TEXT PRIMARY KEY,           -- UUID v4
    version          INTEGER NOT NULL DEFAULT 1,
    type             TEXT NOT NULL,              -- EVIDENCE_TYPES enum
    source           TEXT,                       -- Origin URL or platform
    source_domain    TEXT,                       -- Extracted domain
    raw_hash         TEXT,                       -- SHA-256 of raw input
    perceptual_hash  TEXT,                       -- pHash for images/video
    timestamp_claimed TEXT,                      -- Claimed date (ISO 8601)
    timestamp_observed TEXT NOT NULL,            -- When WE received it
    timestamp_earliest TEXT,                     -- Earliest proven existence
    score_overall    REAL,                       -- 0.0 – 1.0
    score_confidence REAL,                       -- How confident we are
    score_components TEXT,                       -- JSON blob
    flags            TEXT,                       -- JSON array of flags
    explanation      TEXT,                       -- Human-readable verdict
    status           TEXT DEFAULT 'pending',     -- pending | processing | complete | error
    tier_reached     INTEGER DEFAULT 1,          -- Highest tier completed (1/2/3)
    author_json      TEXT,                       -- Serialized AuthorProfile
    metadata_json    TEXT,                       -- Platform-specific metadata
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_eo_type         ON evidence_objects(type);
CREATE INDEX IF NOT EXISTS idx_eo_source_domain ON evidence_objects(source_domain);
CREATE INDEX IF NOT EXISTS idx_eo_status        ON evidence_objects(status);
CREATE INDEX IF NOT EXISTS idx_eo_raw_hash      ON evidence_objects(raw_hash);
CREATE INDEX IF NOT EXISTS idx_eo_created       ON evidence_objects(created_at);
CREATE INDEX IF NOT EXISTS idx_eo_score         ON evidence_objects(score_overall);

-- ──────────────────────────────────────────────────────────────
-- EVIDENCE OBJECT VERSION HISTORY
-- LAW 4: Nothing overwritten, everything versioned.
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS evidence_versions (
    id               TEXT NOT NULL,
    version          INTEGER NOT NULL,
    snapshot_json    TEXT NOT NULL,             -- Full EO snapshot at this version
    changed_by       TEXT,                      -- 'system' | 'expert' | user_id
    change_reason    TEXT,
    created_at       TEXT NOT NULL,
    PRIMARY KEY (id, version)
);

-- ──────────────────────────────────────────────────────────────
-- SOURCE TRUST RECORDS
-- Dynamic trust scores per domain, updated after each verification.
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS source_trust (
    domain                  TEXT PRIMARY KEY,
    accuracy_history        REAL DEFAULT 0.5,   -- EMA of correct/incorrect
    original_reporting      REAL DEFAULT 0.5,   -- Original vs aggregated
    citation_quality        REAL DEFAULT 0.5,
    fact_check_history      REAL DEFAULT 0.5,
    historical_corrections  REAL DEFAULT 0.5,   -- Positive signal
    retractions_ratio       REAL DEFAULT 0.1,   -- Lower = better
    ai_generated_rate       REAL DEFAULT 0.1,   -- Lower = better
    content_duplication     REAL DEFAULT 0.1,   -- Lower = better
    verified_stories        INTEGER DEFAULT 0,  -- Total verifications
    correct_calls           INTEGER DEFAULT 0,
    incorrect_calls         INTEGER DEFAULT 0,
    domain_age_days         INTEGER,
    is_privacy_protected    INTEGER DEFAULT 1,   -- WHOIS privacy
    nameserver              TEXT,               -- For network detection
    registrar               TEXT,
    trust_score             REAL DEFAULT 0.5,   -- Cached computed score
    score_updated_at        TEXT,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_trust_score     ON source_trust(trust_score);
CREATE INDEX IF NOT EXISTS idx_trust_nameserver ON source_trust(nameserver);

-- ──────────────────────────────────────────────────────────────
-- VERIFICATION OUTCOMES (for weight calibration)
-- Every completed verification stores its outcome here.
-- Nightly calibration trains on this table.
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS verification_outcomes (
    id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    eo_id            TEXT NOT NULL,
    domain           TEXT,
    type             TEXT,
    predicted_score  REAL,                      -- What we predicted
    ground_truth     REAL,                      -- Expert-confirmed score (0 or 1)
    correct          INTEGER,                   -- 1 = prediction was right
    retracted        INTEGER DEFAULT 0,
    corrected        INTEGER DEFAULT 0,
    bot_confirmed    INTEGER DEFAULT 0,
    ai_confirmed     INTEGER DEFAULT 0,
    factor_json      TEXT,                      -- Snapshot of factors used
    created_at       TEXT NOT NULL,
    FOREIGN KEY (eo_id) REFERENCES evidence_objects(id)
);

CREATE INDEX IF NOT EXISTS idx_outcomes_domain  ON verification_outcomes(domain);
CREATE INDEX IF NOT EXISTS idx_outcomes_correct ON verification_outcomes(correct);
CREATE INDEX IF NOT EXISTS idx_outcomes_date    ON verification_outcomes(created_at);

-- ──────────────────────────────────────────────────────────────
-- KNOWN HASHES (fast Tier 1 lookup)
-- Confirmed good/bad hashes cached here for instant verdicts.
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS known_hashes (
    hash             TEXT PRIMARY KEY,          -- SHA-256 or perceptual hash
    hash_type        TEXT NOT NULL,             -- 'sha256' | 'phash' | 'ssdeep'
    verdict          TEXT NOT NULL,             -- 'authentic' | 'manipulated' | 'ai_generated' | 'unknown'
    confidence       REAL NOT NULL,
    source           TEXT,                      -- Where this verdict came from
    notes            TEXT,
    created_at       TEXT NOT NULL,
    expires_at       TEXT                       -- NULL = never expires
);

-- ──────────────────────────────────────────────────────────────
-- IDENTITY PROFILES
-- Aggregated identity data across platforms.
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS identity_profiles (
    id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    real_name        TEXT,
    primary_username TEXT,
    all_usernames    TEXT,                      -- JSON array
    email_matches    TEXT,                      -- JSON array
    cross_platform   TEXT,                      -- JSON: {platform: username}
    pgp_fingerprint  TEXT,
    domain_ownership TEXT,                      -- JSON array of verified domains
    blockchain_addrs TEXT,                      -- JSON array
    govt_verified    INTEGER DEFAULT 0,
    org_verified     INTEGER DEFAULT 0,
    account_age_days INTEGER,
    face_embedding   TEXT,                      -- JSON float array (for similarity)
    identity_score   REAL DEFAULT 0.5,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

-- ──────────────────────────────────────────────────────────────
-- KNOWLEDGE GRAPH NODES
-- Every claim, entity, person, organization is a node.
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS kg_nodes (
    id               TEXT PRIMARY KEY,
    node_type        TEXT NOT NULL,             -- 'claim' | 'entity' | 'person' | 'org' | 'event' | 'location'
    label            TEXT NOT NULL,             -- Human-readable name/summary
    content          TEXT,                      -- Full text of claim
    score            REAL DEFAULT 0.5,          -- Current truth confidence
    version          INTEGER DEFAULT 1,
    source_eo_id     TEXT,                      -- Originating evidence object
    embedding_json   TEXT,                      -- Vector embedding for similarity
    metadata_json    TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_kg_type    ON kg_nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_kg_label   ON kg_nodes(label);
CREATE INDEX IF NOT EXISTS idx_kg_score   ON kg_nodes(score);

-- ──────────────────────────────────────────────────────────────
-- KNOWLEDGE GRAPH EDGES
-- Relationships between nodes.
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS kg_edges (
    id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    from_id          TEXT NOT NULL,
    to_id            TEXT NOT NULL,
    edge_type        TEXT NOT NULL,             -- SUPPORTS | CONTRADICTS | CITES | AUTHORED_BY | etc.
    confidence       REAL DEFAULT 0.5,
    evidence_json    TEXT,                      -- Supporting evidence
    created_at       TEXT NOT NULL,
    FOREIGN KEY (from_id) REFERENCES kg_nodes(id),
    FOREIGN KEY (to_id)   REFERENCES kg_nodes(id)
);

CREATE INDEX IF NOT EXISTS idx_kg_edges_from ON kg_edges(from_id);
CREATE INDEX IF NOT EXISTS idx_kg_edges_to   ON kg_edges(to_id);
CREATE INDEX IF NOT EXISTS idx_kg_edges_type ON kg_edges(edge_type);

-- ──────────────────────────────────────────────────────────────
-- CONFIRMED BOTS
-- Accounts confirmed as bots by experts or platform reports.
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS confirmed_bots (
    account_id       TEXT PRIMARY KEY,          -- Platform:username or platform:uid
    platform         TEXT NOT NULL,
    confidence       REAL DEFAULT 0.9,
    detection_method TEXT,                      -- How we knew
    confirmed_by     TEXT,                      -- 'platform' | 'expert' | 'algorithm'
    created_at       TEXT NOT NULL
);

-- ──────────────────────────────────────────────────────────────
-- MANIPULATED IMAGE FINGERPRINTS
-- Confirmed fake images stored here for fast future matching.
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS manipulated_images (
    phash            TEXT PRIMARY KEY,          -- Perceptual hash
    sha256           TEXT,
    verdict          TEXT NOT NULL,             -- 'ai_generated' | 'edited' | 'misattributed'
    original_source  TEXT,                      -- Where the real image came from
    notes            TEXT,
    confidence       REAL DEFAULT 0.9,
    created_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_manip_sha256 ON manipulated_images(sha256);

-- ──────────────────────────────────────────────────────────────
-- DOMAIN NETWORK GRAPH
-- For detecting coordinated fake news networks.
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS domain_network (
    domain           TEXT NOT NULL,
    nameserver       TEXT,
    registrar        TEXT,
    ip_subnet        TEXT,                      -- /24 subnet
    hosting_provider TEXT,
    parent_org       TEXT,                      -- Corporate owner
    created_at       TEXT NOT NULL,
    PRIMARY KEY (domain)
);

CREATE INDEX IF NOT EXISTS idx_domnet_nameserver ON domain_network(nameserver);
CREATE INDEX IF NOT EXISTS idx_domnet_registrar  ON domain_network(registrar);
CREATE INDEX IF NOT EXISTS idx_domnet_subnet     ON domain_network(ip_subnet);

-- ──────────────────────────────────────────────────────────────
-- CALIBRATION CHECKPOINTS
-- Weight vectors from each nightly calibration run.
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS calibration_checkpoints (
    id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    weights_json     TEXT NOT NULL,             -- Learned weight dict
    training_samples INTEGER,
    validation_auc   REAL,                      -- Area under ROC curve
    run_at           TEXT NOT NULL
);

-- ──────────────────────────────────────────────────────────────
-- API RATE LIMITING (Cloudflare KV is better but D1 works too)
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rate_limits (
    key              TEXT PRIMARY KEY,          -- ip:endpoint or token:endpoint
    count            INTEGER DEFAULT 0,
    window_start     TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

-- ──────────────────────────────────────────────────────────────
-- PUBLIC VERIFICATIONS (for the public feed on the website)
-- ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public_feed (
    id               TEXT PRIMARY KEY,
    eo_id            TEXT NOT NULL,
    type             TEXT NOT NULL,
    source_display   TEXT,                      -- Sanitized display URL
    score_overall    REAL,
    verdict_label    TEXT,                      -- 'Likely Authentic' | 'Likely Fake' etc.
    top_flags        TEXT,                      -- JSON: top 3 flags
    created_at       TEXT NOT NULL,
    FOREIGN KEY (eo_id) REFERENCES evidence_objects(id)
);

CREATE INDEX IF NOT EXISTS idx_feed_created ON public_feed(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_feed_score   ON public_feed(score_overall);
CREATE INDEX IF NOT EXISTS idx_feed_type    ON public_feed(type);
