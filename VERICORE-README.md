# VERICORE — Universal Evidence Verification System
## Architecture & Developer Reference

---

## The 10 Laws

| # | Law | Consequence |
|---|-----|-------------|
| 1 | Everything is an Evidence Object | No input is trusted by type. All inputs are normalized before analysis begins |
| 2 | Trust hashes, not files | Files can be replaced silently. A hash anchored in a blockchain cannot |
| 3 | No single classifier decides | All conclusions emerge from weighted fusion of multiple independent signal families |
| 4 | Everything versioned, nothing overwritten | Scores update; old scores are retained. A retraction is evidence, not erasure |
| 5 | Explainability is mandatory | A score without a reason is useless |
| 6 | Contradiction is a first-class signal | Two facts that cannot both be true are more informative than ten consistent facts |
| 7 | Corroboration is multiplicative, not additive | 20 independent sources is exponentially stronger than 20 reshares of 1 source |
| 8 | Manipulation leaves patterns | Bot farms and coordinated campaigns produce detectable statistical anomalies |
| 9 | Identity is a probability, not a binary | "Verified" is never 100%; "Unknown" is not "Fake" |
| 10 | The system learns | Every verification outcome feeds back into all scoring subsystems |

---

## System Architecture

```
INPUT (any type)
      │
      ▼
┌─────────────────────┐
│  Platform Adapters  │  ← Normalize to EvidenceObject
└─────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────┐
│                   ENGINES                    │
│                                              │
│  ┌────────────┐  ┌─────────────────────────┐│
│  │ Metadata   │  │ AI Detection Ensemble   ││
│  │ Engine     │  │ (8 models, not 1)       ││
│  └────────────┘  └─────────────────────────┘│
│  ┌────────────┐  ┌─────────────────────────┐│
│  │ Identity   │  │ Blockchain Layer        ││
│  │ Engine     │  │ (hash → timestamp)      ││
│  └────────────┘  └─────────────────────────┘│
│  ┌────────────┐  ┌─────────────────────────┐│
│  │ Source     │  │ Cross-Reference         ││
│  │ Trust      │  │ (independence required) ││
│  └────────────┘  └─────────────────────────┘│
│  ┌────────────┐  ┌─────────────────────────┐│
│  │ Historical │  │ Anti-Manipulation       ││
│  │ Consistency│  │ (graph analysis)        ││
│  └────────────┘  └─────────────────────────┘│
└──────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────┐
│   Confidence Model          │
│   (Bayesian weighted fusion)│
└─────────────────────────────┘
      │
      ▼
┌─────────────────────────────┐
│   Knowledge Graph           │
│   (living, versioned)       │
└─────────────────────────────┘
      │
      ▼
┌─────────────────────────────┐
│   Continuous Learning       │
│   (feedback → subsystems)   │
└─────────────────────────────┘
      │
      ▼
SCORED & EXPLAINED EvidenceObject
```

---

## Evidence Object Schema

Every input converts to this standardized format before any analysis.

```
EvidenceObject {
  id           UUID v4
  version      Increments on re-analysis (never overwritten)
  type         EVIDENCE_TYPES enum
  source       Origin URL / platform / file path
  timestamp {
    claimed    What the artifact claims
    observed   When VERICORE received it
    earliest   Earliest provable existence (blockchain/archive)
  }
  author       AuthorProfile (identity signals)
  metadata     Raw metadata (EXIF, HTTP headers, platform data)
  hashes {
    sha256     Cryptographic hash
    perceptual pHash/dHash for images/video
    ssdeep     Fuzzy hash for near-duplicate detection
  }
  location {
    claimed    From content
    exif       From metadata
    ip         From network
    consensus  After reconciliation
  }
  relationships  [{targetId, type, confidence}]
  media        {url, mimeType, sizeBytes, duration, dimensions}
  references   Citations / sources mentioned in content
  signatures   {pgp, jwt, blockchain}
  scores       ScoreBundle (populated during analysis)
  chain        Full audit history of all past versions
}
```

---

## Score Components

| Component | Weight | What It Measures |
|-----------|--------|-----------------|
| authenticity | 20% | Is this what it claims to be? (metadata analysis) |
| corroboration | 20% | How many independent sources agree? |
| consistency | 18% | Is it internally consistent with historical record? |
| provenance | 15% | Can we trace its origin and chain of custody? |
| manipulation | 12% | Signs of AI generation, editing, or fabrication? |
| sourceReputation | 10% | Dynamic trust score of the publishing source |
| identityTrust | 5% | Confidence in the claimed author |

**Final formula:**  
`overall = weightedSum × (1 - contradictionPenalty) × corroborationBonus`  
`confidence = f(dataCompleteness, signalConsistency, corroborationFactor)`

---

## Source Trust Factors

Sources are scored dynamically. These factors update continuously:

| Factor | Direction | Weight | Notes |
|--------|-----------|--------|-------|
| accuracyHistory | ↑ higher is better | 25% | Verified true / total verified stories |
| originalReportingRatio | ↑ | 12% | Original vs. aggregated content |
| citationQuality | ↑ | 10% | Quality of sources cited |
| factCheckHistory | ↑ | 10% | Consistency with PolitiFact, Snopes, etc. |
| ownershipTransparency | ↑ | 8% | Publicly known ownership |
| historicalCorrections | ↑ | 6% | **Sources that correct themselves score HIGHER** |
| domainAge | ↑ | 5% | Older established domains |
| retractionsRatio | ↓ inverted | 7% | Fewer unexplained retractions = better |
| aiGeneratedRate | ↓ inverted | 3% | High AI content rate = lower trust |
| botInteractionRate | ↓ inverted | 2% | Engagement from bot accounts |
| trafficAnomalies | ↓ inverted | 2% | Artificial traffic spikes |

---

## AI Detection Ensemble (8 Models)

Never rely on a single classifier. All 8 signals are fused:

| Model | Detects | Weight |
|-------|---------|--------|
| GAN Artifact Detector | Checkerboard patterns, spectral peaks | 15% |
| Diffusion Artifact Detector | Step-wise blending artifacts | 15% |
| Texture Anomaly Detector | Implausible skin/surface textures | 12% |
| Frequency Analyzer | DCT frequency domain analysis | 12% |
| Watermark Detector | C2PA, Invisible Watermark | 10% |
| Model Fingerprinter | Known model artifact signatures | 15% |
| Prompt Residue Detector | Semantic inconsistencies | 10% |
| Semantic Analyzer | Physical/contextual incoherence | 11% |

Images are also analyzed in 8×8 patch grids — local artifact variation reveals partial edits.

---

## Anti-Manipulation Detection

Graph analysis detects coordinated inauthentic behavior:

**Bot farm signals:**
- Posting time correlation > 0.85 across cluster
- Content overlap > 80% within cluster  
- Account creation within 3-day window (batch creation)
- Engagement rate 5× above tier baseline (fake engagement)
- Engagement rate < 5% of baseline (fake followers)

**Behavioral vector dimensions (per account):**
Posting hour histogram (24 dims) + response delay + content repetition + follower/following ratio + engagement rate + account age + URL sharing rate + hashtag density + mention density + language entropy

**Clustering:** DBSCAN on cosine dissimilarity with independence threshold 0.92

---

## Corroboration Rules (Critical)

**Independence requires ALL of:**
- Different ownership
- Different journalists / authors  
- Different root source (traced genealogically)
- Not sharing hosting infrastructure

**Independence formula:**  
`P(claim true | N independent confirmations)` using Bayesian log-odds fusion:  
`log_odds(posterior) = log_odds(prior) + Σ log(p_i / (1 - p_i))`

20 reshares of 1 AP wire story = 1 confirmation, not 20.  
3 truly independent government agencies confirming = very strong signal.

---

## Historical Consistency Checks

The system always asks: **"Has this happened before? Does the timeline add up?"**

**Timeline rules enforced:**
- Domain registration date ≤ claimed founding date
- Camera model release date ≤ photo claimed date
- Earliest known online mention ≤ claimed publication date
- Account creation ≤ first activity
- Content must not predate the platform it claims to originate from

**Backdating detection:**  
If first known online mention (via Wayback Machine / Common Crawl) is >30 days after claimed date → BACKDATING_SUSPECTED flag. >365 days → CRITICAL flag.

---

## Supported Evidence Types

| Type | Platform/Format | Key Signals |
|------|----------------|-------------|
| IMAGE | Any image | EXIF, GPS, shadow, sensor fingerprint, AI ensemble |
| ARTICLE | Any news/web | Source trust, authorship, citations, corroboration |
| VIDEO | Any video | Frame timing, lip sync, deepfake ensemble, encoding |
| AUDIO | Any audio | Spectrogram, breathing patterns, AI voice, cuts |
| TWEET | X/Twitter | Account age, engagement, network analysis |
| INSTAGRAM | Instagram | Follower ratio, engagement, cross-platform |
| SPOTIFY_ARTIST | Spotify | Release freq, live events, social presence |
| EMAIL | Email address | DNS records (MX/SPF/DKIM/DMARC), domain age |
| WEBSITE | Any domain | WHOIS, SSL history, domain age, traffic |
| BLOCKCHAIN_TX | ETH/BTC/etc. | Wallet age, sanctions, wash trading |
| STOCK_TRADE | Any market | Volume anomaly, timing correlation, news proximity |
| POLYMARKET_BET | Polymarket | Wallet age, market concentration, oracle integrity |
| GOVERNMENT_DOC | Official docs | Archive consistency, signature verification |
| ACADEMIC_PAPER | Papers | DOI, citation graph, retraction watch |

---

## Continuous Learning

Every verification outcome feeds back into all subsystems:

```
Expert Review → recordOutcome() →
  ├── SourceTrustEngine.updateAfterVerification()
  ├── Database.addConfirmedBot()           (if bot confirmed)
  ├── Database.addManipulatedFingerprint() (if manipulation confirmed)
  ├── KnowledgeGraph.updateScore()
  └── AIDetector.addCalibrationPoint()
```

Learning uses exponential moving average (α = 0.05) to weight recent performance while preserving long-term history. Human expert overrides are treated as ground truth.

---

## Integration Notes

**Recommended external integrations:**
- OpenTimestamps / Ethereum notary contracts → blockchain timestamps
- WHOIS APIs (RDAP) → domain ownership history  
- Wayback Machine CDX API → earliest content appearance
- PolitiFact, Snopes, FactCheck.org → fact-check history
- OFAC sanctions API → blockchain wallet screening
- Mempool.space API → Bitcoin OP_RETURN search
- C2PA content credentials → AI watermark verification
- IPFS/Filecoin → decentralized content anchoring

**Database recommendations:**
- Neo4j or Amazon Neptune → Knowledge Graph
- PostgreSQL → Source trust records, EO storage  
- Redis → Score caches, bot databases
- S3/equivalent → Raw EO archives (never deleted, versioned)

**ML model integration points** (documented stubs in vericore.js):
- `runGANDetector(frames)` — return 0–1 score
- `runDiffusionDetector(frames)` — return 0–1 score
- `detectAIVoice(spectrogram, buffer)` — return `{combined: 0–1}`
- `computeStylometricFingerprint(text)` — return feature vector

---

*VERICORE v1.0.0 — All scores are probabilistic estimates, not ground truth declarations.*
