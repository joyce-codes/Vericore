/**
 * VERICORE — Universal Evidence Verification Algorithm
 * =====================================================
 * Version: 1.0.0
 * Architecture: Modular, layered, continuously learning
 *
 * LAWS OF VERICORE:
 *
 * LAW 1 — Everything is an Evidence Object (EO).
 *   No input is trusted by type. Every piece of information — image, article,
 *   tweet, audio, blockchain record — is converted to a standardized EO before
 *   any analysis begins.
 *
 * LAW 2 — Hashes, not files.
 *   Trust cryptographic hashes over raw files. A file can be replaced;
 *   a hash anchored in a blockchain record cannot be silently altered.
 *
 * LAW 3 — No single classifier decides.
 *   Individual ML models, even strong ones, are often fooled. All conclusions
 *   emerge from weighted fusion of multiple independent signal families.
 *
 * LAW 4 — Everything is versioned, nothing overwritten.
 *   Scores update; old scores are retained. A retraction is evidence, not erasure.
 *
 * LAW 5 — Explainability is mandatory.
 *   A score without a reason is useless. Every confidence value ships with a
 *   structured explanation traceable to raw evidence.
 *
 * LAW 6 — Contradiction is a first-class signal.
 *   Two plausible facts that cannot both be true are more informative than
 *   ten consistent facts. Contradiction detection runs on every EO graph.
 *
 * LAW 7 — Corroboration is multiplicative, not additive.
 *   20 independent sources each believing the same thing is exponentially
 *   stronger evidence than 20 reshares of 1 source.
 *
 * LAW 8 — Manipulation leaves patterns.
 *   Bot farms, coordinated campaigns, and artificial amplification all produce
 *   statistical anomalies detectable via graph and temporal analysis.
 *
 * LAW 9 — Identity is a probability, not a binary.
 *   Verification yields a confidence range. "Verified" is never 100%;
 *   "Unknown" is not "fake."
 *
 * LAW 10 — The system learns.
 *   Every verification outcome feeds back into source trust, AI detector
 *   calibration, domain scores, and identity confidence.
 */
'use strict';
// ─────────────────────────────────────────────────────────────────────────────
// SECTION 1 — EVIDENCE OBJECT SCHEMA
// ─────────────────────────────────────────────────────────────────────────────

/**
 * EvidenceObject: The universal container for any verifiable artifact.
 *
 * RULE: Every input must be normalized to this schema before analysis.
 * RULE: Once created, EOs are immutable. Updates produce new versioned EOs.
 * RULE: The `relationships` field links this EO to others in the knowledge graph.
 */
class EvidenceObject {
  constructor(raw, type) {
    this.id          = generateId();          // UUID v4
    this.version     = 1;                     // Increments on re-analysis
    this.type        = validateType(type);    // See EVIDENCE_TYPES enum
    this.source      = null;                  // URL, platform, file path
    this.timestamp   = {
      claimed:   null,                        // What the artifact claims
      observed:  Date.now(),                  // When WE received it
      earliest:  null,                        // Earliest provable existence
    };
    this.author      = new AuthorProfile();
    this.metadata    = {};                    // Raw metadata (EXIF, HTTP headers, etc.)
    this.hashes      = {
      sha256:    null,
      perceptual: null,                       // For images/video (pHash, dHash)
      ssdeep:    null,                        // Fuzzy hash for near-duplicate detection
    };
    this.location    = {
      claimed:   null,                        // From content
      exif:      null,                        // From metadata
      ip:        null,                        // From network
      consensus: null,                        // After reconciliation
    };
    this.relationships = [];                  // Array of {targetId, relationshipType, confidence}
    this.media       = {
      url:       null,
      mimeType:  null,
      sizeBytes: null,
      duration:  null,                        // For audio/video
      dimensions: null,                       // For images/video
    };
    this.references  = [];                    // Citations, sources mentioned in content
    this.signatures  = {
      pgp:       null,
      jwt:       null,
      blockchain: null,
    };
    this.raw         = raw;                   // Original unmodified input
    this.scores      = new ScoreBundle();     // Populated during analysis
    this.chain       = [];                    // Audit chain of all past versions
  }

  /**
   * Creates an updated version of this EO without mutating the original.
   * RULE: All modifications must go through this method.
   */
  update(changes) {
    const next = Object.assign(Object.create(Object.getPrototypeOf(this)), this);
    next.version = this.version + 1;
    next.chain = [...this.chain, { version: this.version, snapshot: deepFreeze(this) }];
    return Object.assign(next, changes);
  }
}

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
// SECTION 2 — AUTHOR / IDENTITY PROFILE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * AuthorProfile: Aggregates all identity signals across platforms.
 *
 * RULE: Identity is probabilistic. confidence ∈ [0.0, 1.0].
 * RULE: Each identity factor is independently weighted and fused.
 * RULE: Cross-platform consistency lifts score; inconsistency lowers it.
 */
class AuthorProfile {
  constructor() {
    this.realName        = null;
    this.aliases         = [];
    this.usernames       = [];
    this.historicalUsernames = [];
    this.accountAge      = null;             // Days since creation
    this.crossPlatform   = {};               // {platform: username}
    this.faceSimilarity  = null;             // 0–1 match to claimed identity
    this.voiceSimilarity = null;             // 0–1 match to claimed identity
    this.emailMatches    = [];               // Known associated emails
    this.domainOwnership = [];               // WHOIS-confirmed domains
    this.pgpKeys         = [];               // Verified public keys
    this.phoneVerified   = false;
    this.blockchainOwnership = [];          // Verified wallet addresses
    this.governmentVerified  = false;
    this.organizationVerified = false;
    this.identityScore   = null;            // Computed by IdentityEngine
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 3 — SCORE BUNDLE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * ScoreBundle: All confidence scores attached to an EO.
 *
 * RULE: Each score must include a `factors` array explaining its derivation.
 * RULE: `overall` is a weighted combination of component scores — never a guess.
 * RULE: `confidence` reflects how certain we are of the overall score itself.
 */
class ScoreBundle {
  constructor() {
    this.overall      = null;               // 0.0–1.0 composite truth score
    this.confidence   = null;               // 0.0–1.0 certainty of the overall score
    this.components   = {
      authenticity:   null,                 // Is this what it claims to be?
      provenance:     null,                 // Can we trace its origin?
      consistency:    null,                 // Is it internally consistent?
      corroboration:  null,                 // How many independent sources agree?
      manipulation:   null,                 // Signs of AI/edit/fabrication? (1.0 = clean)
      sourceReputation: null,               // Trust of the publishing source
      identityTrust:  null,                 // Trust in the claimed author
    };
    this.flags        = [];                 // [{type, severity, description}]
    this.factors      = [];                 // [{key, value, weight, description}]
    this.explanation  = null;              // Human-readable explanation string
    this.timestamp    = Date.now();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 4 — SOURCE TRUST ENGINE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * SourceTrustEngine: Maintains and computes dynamic trust scores for domains/sources.
 *
 * RULE: Trust scores are dynamic and decay if a source repeatedly posts
 *       content that is later disproven.
 * RULE: Anonymous sources always start at 0.3 baseline trust.
 * RULE: AI-generated content rate degrades trust proportionally.
 * RULE: Retraction history is POSITIVE signal — sources that correct themselves
 *       are more trustworthy than sources that never retract.
 */
class SourceTrustEngine {
  constructor(database) {
    this.db = database;                     // Persistent store for source history
    this.cache = new Map();                 // In-memory TTL cache
  }

  /**
   * Computes a trust score for a given source domain.
   *
   * Factors (each 0–1, weighted):
   *   historicalCorrections  — sources that issue corrections score HIGHER
   *   retractionsRatio       — retractions / total stories (lower is better)
   *   accuracyHistory        — verified true / total verified stories
   *   politicalBiasIndex     — center-balanced = higher score
   *   ownershipTransparency  — publicly known ownership
   *   factCheckHistory       — PolitiFact, Snopes, etc. consistency
   *   originalReportingRatio — original vs. aggregated content
   *   citationQuality        — quality of sources cited
   *   anonymousSourceUsage   — over-reliance on anonymous sources lowers score
   *   aiGeneratedRate        — percentage of AI-generated content
   *   botInteractionRate     — engagement from bot accounts
   *   archiveConsistency     — Wayback Machine / cache consistency
   *   brokenLinkRate         — lowers credibility of old references
   *   domainAge              — older established domains score higher
   *   sslHistory             — consistent HTTPS record
   *   whoisHistory           — stable ownership history
   *   trafficAnomalies       — sudden artificial traffic spikes
   *   contentDuplication     — republishing without attribution
   */
  async computeScore(sourceUrl) {
    const domain = extractDomain(sourceUrl);

    if (this.cache.has(domain)) {
      const cached = this.cache.get(domain);
      if (Date.now() - cached.ts < 3_600_000) return cached.score;  // 1-hour TTL
    }

    const record = await this.db.getSource(domain) || defaultSourceRecord(domain);

    const weights = {
      accuracyHistory:          0.25,
      originalReportingRatio:   0.12,
      citationQuality:          0.10,
      factCheckHistory:         0.10,
      ownershipTransparency:    0.08,
      retractionsRatio:         0.07,  // INVERTED: fewer retractions = higher score
      historicalCorrections:    0.06,  // POSITIVE: corrections = good faith
      domainAge:                0.05,
      archiveConsistency:       0.05,
      politicalBiasIndex:       0.04,
      sslHistory:               0.03,
      anonymousSourceUsage:     0.03,
      aiGeneratedRate:          0.03,  // INVERTED
      botInteractionRate:       0.02,  // INVERTED
      brokenLinkRate:           0.02,  // INVERTED
      trafficAnomalies:         0.02,  // INVERTED
      contentDuplication:       0.02,  // INVERTED
      whoisHistory:             0.01,
    };

    const INVERTED = new Set([
      'retractionsRatio', 'aiGeneratedRate', 'botInteractionRate',
      'brokenLinkRate', 'trafficAnomalies', 'contentDuplication',
      'anonymousSourceUsage',
    ]);

    let weightedSum = 0;
    const factors = [];

    for (const [key, weight] of Object.entries(weights)) {
      let raw = record[key] ?? 0.5;             // Default: unknown = 0.5
      const value = INVERTED.has(key) ? 1 - raw : raw;
      weightedSum += value * weight;
      factors.push({ key, raw, value, weight });
    }

    const score = {
      domain,
      trust: clamp(weightedSum, 0, 1),
      factors,
      computed: Date.now(),
      sampleSize: record.verifiedStories ?? 0,
    };

    this.cache.set(domain, { score, ts: Date.now() });
    return score;
  }

  /**
   * Updates a source's trust record after a verification outcome.
   * Called by the continuous learning loop.
   */
  async updateAfterVerification(domain, outcome) {
    const record = await this.db.getSource(domain) || defaultSourceRecord(domain);
    record.verifiedStories = (record.verifiedStories || 0) + 1;

    // Exponential moving average to prioritize recent behavior
    const alpha = 0.05;
    record.accuracyHistory = lerp(record.accuracyHistory ?? 0.5, outcome.correct ? 1 : 0, alpha);

    if (outcome.retracted) {
      record.retractionsRatio = lerp(record.retractionsRatio ?? 0, 1, alpha);
    }
    if (outcome.corrected) {
      record.historicalCorrections = lerp(record.historicalCorrections ?? 0.5, 1, alpha);
    }

    await this.db.setSource(domain, record);
    this.cache.delete(domain);  // Invalidate cache
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 5 — METADATA ANALYSIS ENGINE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * MetadataEngine: Deep inspection of file and content metadata.
 *
 * RULE: Metadata contradiction is a high-severity flag but not proof of fakery —
 *       metadata can be stripped, corrupted, or legitimately absent.
 * RULE: Absence of expected metadata is itself a signal.
 */
class MetadataEngine {
  /**
   * Analyzes image metadata.
   *
   * Checks:
   *   EXIF completeness       — Missing EXIF on camera-claimed photos is suspicious
   *   GPS consistency         — GPS vs. claimed location vs. time zone
   *   Camera model            — Does claimed device produce this EXIF signature?
   *   Compression artifacts   — Mismatched compression chains indicate re-saves
   *   Thumbnail mismatch      — EXIF thumbnail differs from image content = tampering
   *   JPEG quantization       — Quantization table fingerprints the original encoder
   *   Noise pattern           — Sensor noise pattern = camera fingerprint
   *   Lighting consistency    — Shadow directions must not contradict sun position
   *   Shadow direction        — Cross-check against GPS + timestamp solar position
   *   Reflection analysis     — Reflections in surfaces constrain scene geometry
   */
  analyzeImage(exifData, rawPixels) {
    const signals = [];

    if (!exifData || Object.keys(exifData).length === 0) {
      signals.push(flag('EXIF_ABSENT', 'medium',
        'No EXIF data found. May indicate stripping (privacy) or fabrication.'));
    } else {
      // Thumbnail mismatch detection
      if (exifData.thumbnail && rawPixels) {
        const thumbHash  = perceptualHash(exifData.thumbnail);
        const imageHash  = perceptualHash(rawPixels);
        const similarity = hammingDistance(thumbHash, imageHash) / thumbHash.length;
        if (similarity < 0.85) {
          signals.push(flag('THUMBNAIL_MISMATCH', 'high',
            `EXIF thumbnail similarity ${(similarity * 100).toFixed(1)}% — possible tampering`));
        }
      }

      // GPS vs. claimed location
      if (exifData.gps && exifData.gps.claimed) {
        const dist = haversineDistance(exifData.gps, exifData.gps.claimed);
        if (dist > 50_000) {  // 50 km threshold
          signals.push(flag('GPS_LOCATION_MISMATCH', 'high',
            `GPS metadata places image ${(dist / 1000).toFixed(0)} km from claimed location`));
        }
      }

      // Timestamp plausibility
      if (exifData.dateTimeOriginal) {
        const claimedDate = new Date(exifData.dateTimeOriginal);
        if (claimedDate > new Date()) {
          signals.push(flag('FUTURE_TIMESTAMP', 'critical',
            'EXIF timestamp is in the future — strongly indicates manipulation'));
        }
        // Camera model was released after the claimed date?
        if (exifData.model && isCameraReleaseAfter(exifData.model, claimedDate)) {
          signals.push(flag('ANACHRONISTIC_CAMERA', 'high',
            `Camera model "${exifData.model}" was not yet released on the claimed date`));
        }
      }

      // JPEG quantization fingerprint
      if (exifData.quantizationTables) {
        const knownSoftware = matchQuantizationTable(exifData.quantizationTables);
        if (knownSoftware) {
          signals.push(flag('QUANTIZATION_MATCH', 'info',
            `JPEG quantization matches ${knownSoftware}`));
        }
      }
    }

    // Lighting consistency (requires pixel data)
    if (rawPixels) {
      const shadowAnalysis = analyzeShadowConsistency(rawPixels);
      if (shadowAnalysis.contradictionDetected) {
        signals.push(flag('SHADOW_INCONSISTENCY', 'high',
          `Shadow directions conflict with each other (angle spread: ${shadowAnalysis.spreadDegrees}°)`));
      }
    }

    return {
      score: computeSignalScore(signals),
      signals,
    };
  }

  /**
   * Analyzes video metadata and content signals.
   *
   * Checks:
   *   Frame timing regularity — irregular PTS/DTS gaps indicate spliced content
   *   Encoding fingerprint    — encoder version + settings
   *   Compression artifacts   — double-compression = re-encoded from another video
   *   Dropped frames          — unusual patterns around potential edit points
   *   Deepfake artifacts      — facial geometry flicker, blending artifacts
   *   Motion consistency      — camera motion should be physically coherent
   *   Lip sync                — audio-visual alignment (SYNCNET-style)
   *   Audio sync              — waveform alignment with video events
   *   Scene continuity        — lighting/shadows across cuts
   */
  analyzeVideo(frames, audioTrack, containerMetadata) {
    const signals = [];

    // Double-compression detection
    if (containerMetadata.encodingHistory?.length > 1) {
      signals.push(flag('DOUBLE_COMPRESSION', 'medium',
        `Video has been re-encoded ${containerMetadata.encodingHistory.length} times — common in edited content`));
    }

    // Frame timing anomalies
    const timingAnomalies = detectFrameTimingAnomalies(containerMetadata.framePts);
    if (timingAnomalies.length > 0) {
      signals.push(flag('FRAME_TIMING_ANOMALY', 'medium',
        `${timingAnomalies.length} irregular PTS gaps detected — possible edit points at frames: ${timingAnomalies.join(', ')}`));
    }

    // Deepfake artifact detection (ensemble)
    if (frames) {
      const deepfakeScore = this._runDeepfakeEnsemble(frames);
      if (deepfakeScore.combined > 0.7) {
        signals.push(flag('DEEPFAKE_DETECTED', 'critical',
          `Deepfake probability: ${(deepfakeScore.combined * 100).toFixed(0)}% (ensemble of ${deepfakeScore.models.length} detectors)`));
      } else if (deepfakeScore.combined > 0.4) {
        signals.push(flag('DEEPFAKE_SUSPECTED', 'high',
          `Moderate deepfake indicators: ${(deepfakeScore.combined * 100).toFixed(0)}%`));
      }
    }

    // Lip sync analysis
    if (audioTrack && frames) {
      const syncScore = analyzeLipSync(frames, audioTrack);
      if (syncScore.offset_ms > 100) {
        signals.push(flag('AUDIO_VIDEO_DESYNC', 'medium',
          `Audio offset ${syncScore.offset_ms}ms from video — may indicate dubbing or splicing`));
      }
    }

    return { score: computeSignalScore(signals), signals };
  }

  /**
   * Analyzes audio content.
   *
   * Checks:
   *   Microphone fingerprint  — each microphone type leaves a characteristic response
   *   Compression history     — MP3 re-encoding artifacts
   *   Spectrogram anomalies   — cuts/splices visible in spectrogram
   *   AI voice detection      — resemblance to TTS/voice clone artifacts
   *   Breathing patterns      — authentic speech has physiologically constrained breathing
   *   Echo consistency        — room acoustics must be consistent throughout
   *   Noise floor consistency — background noise changing = spliced environment
   */
  analyzeAudio(audioBuffer, sampleRate) {
    const signals = [];
    const spectrogram = computeSpectrogram(audioBuffer, sampleRate);

    // Noise floor consistency
    const noiseFloor = measureNoiseFloor(audioBuffer, sampleRate);
    if (noiseFloor.varianceHigh) {
      signals.push(flag('NOISE_FLOOR_INCONSISTENCY', 'medium',
        `Background noise floor changes ${noiseFloor.changePoints.length} times — suggests spliced segments`));
    }

    // AI voice detection ensemble
    const aiVoiceScore = detectAIVoice(spectrogram, audioBuffer);
    if (aiVoiceScore.combined > 0.75) {
      signals.push(flag('AI_VOICE_DETECTED', 'critical',
        `AI-generated voice probability: ${(aiVoiceScore.combined * 100).toFixed(0)}%`));
    }

    // Breathing pattern analysis
    const breathing = analyzeBreathingPatterns(audioBuffer, sampleRate);
    if (!breathing.plausible) {
      signals.push(flag('UNNATURAL_BREATHING', 'medium',
        `Breathing intervals are statistically unlikely for human speech: ${breathing.anomalyDescription}`));
    }

    // Spectrogram cut detection
    const cuts = detectSpectrogramCuts(spectrogram);
    if (cuts.length > 0) {
      signals.push(flag('AUDIO_CUTS_DETECTED', 'high',
        `${cuts.length} potential edit points detected in spectrogram at timestamps: ${cuts.map(c => c.time_s.toFixed(2) + 's').join(', ')}`));
    }

    return { score: computeSignalScore(signals), signals };
  }

  /**
   * Runs a MULTI-MODEL ensemble for deepfake detection.
   *
   * RULE: Never trust a single classifier. Combine weak signals.
   *
   * Models in ensemble:
   *   1. GAN artifact detector    — checkerboard patterns, spectral peaks
   *   2. Diffusion artifact det.  — step-wise blending artifacts
   *   3. Texture anomaly detector — implausible skin/surface textures
   *   4. Frequency analyzer       — DCT frequency domain analysis
   *   5. Watermark detector       — C2PA, Invisible Watermark, etc.
   *   6. Model fingerprinter      — identifies artifacts specific to known models
   *   7. Prompt residue detector  — semantic content inconsistencies
   *   8. Semantic inconsistency   — content that doesn't cohere physically
   */
  _runDeepfakeEnsemble(frames) {
    // NOTE: In production, these call actual ML inference endpoints.
    // Shown here as stubs with documented signatures.
    const models = [
      { name: 'GAN_ARTIFACT',       score: runGANDetector(frames),          weight: 0.15 },
      { name: 'DIFFUSION_ARTIFACT', score: runDiffusionDetector(frames),    weight: 0.15 },
      { name: 'TEXTURE_ANOMALY',    score: runTextureAnalyzer(frames),      weight: 0.12 },
      { name: 'FREQUENCY',          score: runFrequencyAnalyzer(frames),    weight: 0.12 },
      { name: 'WATERMARK',          score: runWatermarkDetector(frames),    weight: 0.10 },
      { name: 'MODEL_FINGERPRINT',  score: runModelFingerprinter(frames),   weight: 0.15 },
      { name: 'PROMPT_RESIDUE',     score: runPromptResidueDetector(frames), weight: 0.10 },
      { name: 'SEMANTIC',           score: runSemanticAnalyzer(frames),     weight: 0.11 },
    ];

    const combined = models.reduce((sum, m) => sum + m.score * m.weight, 0);
    return { combined, models };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 6 — AI DETECTION ENGINE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * AIDetectionEngine: Specialized detection for AI-generated content across modalities.
 *
 * RULE: Do NOT use a single model. Ensemble signals across:
 *       GAN artifacts, diffusion artifacts, texture, frequency, watermarks,
 *       model fingerprints, prompt residue, semantic consistency.
 *
 * RULE: AI detection for images requires spatial analysis across patches,
 *       not just whole-image classification (local artifacts are often diagnostic).
 *
 * RULE: Text AI detection is highly unreliable. Only flag at >90% confidence
 *       and always note the uncertainty. NEVER use text AI detection as sole proof.
 */
class AIDetectionEngine {
  async detectAIImage(imageData) {
    const patchAnalysis = this._analyzePatchGrid(imageData, 8);  // 8x8 patch grid

    return {
      ganScore:           detectGANArtifacts(imageData),
      diffusionScore:     detectDiffusionArtifacts(imageData),
      textureScore:       detectTextureAnomalies(imageData),
      frequencyScore:     analyzeFrequencyDomain(imageData),
      watermarkPresent:   detectAIWatermark(imageData),
      modelFingerprint:   identifyAIModel(imageData),         // e.g., "Stable Diffusion XL"
      patchInconsistency: patchAnalysis.inconsistencyScore,  // Local vs global coherence
      combined:           this._fuseImageSignals(patchAnalysis),
    };
  }

  async detectAIText(text) {
    // NOTE: Text AI detection has ~30% false positive rate even for best models.
    // Returns a score but ALWAYS includes an uncertainty warning.
    const burstiness    = computeBurstiness(text);         // Human text has higher variance
    const perplexity    = computePerplexity(text);         // AI text typically low perplexity
    const ngramPatterns = analyzeNgramDistributions(text);
    const stylometric   = runStylometricAnalysis(text);    // Author fingerprinting

    const combined = weightedMean([
      [burstiness.score,    0.30],
      [perplexity.score,    0.25],
      [ngramPatterns.score, 0.25],
      [stylometric.score,   0.20],
    ]);

    return {
      combined,
      uncertainty: 'HIGH — text AI detection has significant false positive rate',
      burstiness, perplexity, ngramPatterns, stylometric,
      flagOnly: combined > 0.90,  // Only flag high-confidence cases
    };
  }

  _analyzePatchGrid(imageData, gridSize) {
    const patches = splitIntoPatchGrid(imageData, gridSize);
    const patchScores = patches.map(patch => ({
      position: patch.position,
      ganScore: detectGANArtifacts(patch.data),
      textureScore: detectTextureAnomalies(patch.data),
    }));

    // High variance across patches = partial edit or localized generation
    const scoreVariance = variance(patchScores.map(p => p.ganScore));
    return {
      patchScores,
      inconsistencyScore: Math.min(1, scoreVariance * 4),
      highAnomalyPatches: patchScores.filter(p => p.ganScore > 0.7),
    };
  }

  _fuseImageSignals({ patchScores, inconsistencyScore }) {
    const avgPatch = mean(patchScores.map(p => p.ganScore));
    return clamp(avgPatch * 0.7 + inconsistencyScore * 0.3, 0, 1);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 7 — BLOCKCHAIN VERIFICATION LAYER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * BlockchainLayer: Anchors evidence to immutable timestamped records.
 *
 * RULE: A blockchain record does not verify TRUTH — it verifies EXISTENCE AT TIME.
 *       "This hash was registered on Block #X" proves the file existed then,
 *       not that the file is authentic or its claims are true.
 *
 * RULE: Verify the chain of custody. A hash in block 800,000 means nothing
 *       if the original file claiming to be from 2005 was first seen online in 2024.
 *
 * RULE: Smart contract interactions must be traced to verify authenticity
 *       of Polymarket predictions and DEX trades — wash trading is common.
 */
class BlockchainLayer {
  constructor(rpcProviders) {
    this.rpc = rpcProviders;  // Map of {chainId: rpcUrl}
  }

  /**
   * Verifies a file hash against known blockchain timestamp records.
   * Checks: OpenTimestamps, Ethereum, Bitcoin (via OP_RETURN), custom registries.
   */
  async verifyFileTimestamp(sha256Hash) {
    const results = await Promise.allSettled([
      this._checkOpenTimestamps(sha256Hash),
      this._checkEthereumRegistry(sha256Hash),
      this._checkBitcoinOpReturn(sha256Hash),
    ]);

    const confirmed = results
      .filter(r => r.status === 'fulfilled' && r.value.found)
      .map(r => r.value);

    return {
      found: confirmed.length > 0,
      records: confirmed,
      earliestBlock: confirmed.length > 0
        ? confirmed.reduce((a, b) => a.blockTime < b.blockTime ? a : b)
        : null,
    };
  }

  /**
   * Analyzes a stock trade for manipulation signals.
   *
   * Checks:
   *   Wash trading         — buyer and seller share wallet/IP
   *   Pump patterns        — volume spike → price spike → dump
   *   Coordinated timing   — trades clustered tighter than Poisson would predict
   *   Options anomalies    — unusual put/call ratios before news events
   *   Whale alerts         — single address controlling > X% of volume
   */
  async analyzeStockTrade(tradeRecord) {
    const signals = [];

    const volumeAnomaly = detectVolumeAnomaly(tradeRecord.symbol, tradeRecord.volume);
    if (volumeAnomaly.zscore > 3.0) {
      signals.push(flag('VOLUME_ANOMALY', 'high',
        `Volume is ${volumeAnomaly.zscore.toFixed(1)} standard deviations above 30-day average`));
    }

    const timingCluster = analyzeTradeTimingClustering(tradeRecord.timestamps);
    if (timingCluster.pValue < 0.01) {
      signals.push(flag('COORDINATED_TIMING', 'high',
        `Trade timing is statistically non-random (p=${timingCluster.pValue.toFixed(4)}) — possible coordination`));
    }

    const newsProximity = await checkNewsProximity(tradeRecord.symbol, tradeRecord.timestamp);
    if (newsProximity.withinHours < 24 && tradeRecord.size > newsProximity.largeThreshold) {
      signals.push(flag('PRE_NEWS_LARGE_TRADE', 'critical',
        `Large trade placed ${newsProximity.withinHours}h before significant news event`));
    }

    return { signals, score: computeSignalScore(signals) };
  }

  /**
   * Verifies a Polymarket prediction market bet.
   *
   * Checks:
   *   Wallet ownership        — KYC-linked wallet?
   *   Position concentration  — single actor controlling >20% of a side?
   *   Oracle manipulation     — oracle data source integrity
   *   Resolution disputes     — contested resolutions
   */
  async analyzePolymarketBet(betRecord) {
    const signals = [];

    const walletAnalysis = await this._analyzeWalletHistory(betRecord.walletAddress);
    if (walletAnalysis.newWallet && betRecord.amountUsd > 10_000) {
      signals.push(flag('NEW_WALLET_LARGE_BET', 'medium',
        `Wallet created <30 days ago placing $${betRecord.amountUsd.toLocaleString()} bet`));
    }

    const marketConcentration = await this._checkMarketConcentration(betRecord.marketId);
    if (marketConcentration.topHolderPct > 0.20) {
      signals.push(flag('MARKET_CONCENTRATION', 'medium',
        `Top holder controls ${(marketConcentration.topHolderPct * 100).toFixed(0)}% of one side`));
    }

    return { signals, score: computeSignalScore(signals) };
  }

  async _checkOpenTimestamps(hash) {
    // OpenTimestamps API verification
    const response = await fetch(`https://ots.tools/verify/${hash}`);
    if (!response.ok) return { found: false };
    const data = await response.json();
    return {
      found: data.verified,
      blockTime: data.blockTime,
      chain: 'bitcoin',
      proof: data.proof,
    };
  }

  async _checkEthereumRegistry(hash) {
    // Check known Ethereum content registries
    // (e.g., Chainlink proof of reserve, custom notary contracts)
    const contract = this.rpc.ethereum?.notaryContract;
    if (!contract) return { found: false };
    const result = await contract.getTimestamp(hash);
    return {
      found: result.exists,
      blockTime: result.timestamp,
      chain: 'ethereum',
      txHash: result.txHash,
    };
  }

  async _checkBitcoinOpReturn(hash) {
    // Search Bitcoin OP_RETURN outputs for the hash
    const query = `https://mempool.space/api/search?q=${hash}`;
    const response = await fetch(query);
    if (!response.ok) return { found: false };
    const results = await response.json();
    return {
      found: results.txs?.length > 0,
      blockTime: results.txs?.[0]?.blockTime,
      chain: 'bitcoin',
      txid: results.txs?.[0]?.txid,
    };
  }

  async _analyzeWalletHistory(address) {
    // Check wallet age, transaction history, known associations
    return {
      newWallet: false,
      agedays: 0,
      knownActor: null,
    };
  }

  async _checkMarketConcentration(marketId) {
    return { topHolderPct: 0 };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 8 — CROSS-REFERENCE ENGINE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * CrossReferenceEngine: Finds independent corroboration across sources.
 *
 * RULE: Independence is essential. 20 sites copying the same AP wire story
 *       are NOT 20 independent confirmations.
 *
 * RULE: Source genealogy tracking — trace all claims back to their root source.
 *       Corroboration only counts when it comes from a DIFFERENT root source.
 *
 * RULE: "Independent" requires:
 *       - Different ownership
 *       - Different journalists / authors
 *       - Different geographic region (ideally)
 *       - Not sharing infrastructure (same parent company, same server)
 */
class CrossReferenceEngine {
  constructor(searchEngine, sourceGraph) {
    this.search = searchEngine;
    this.sourceGraph = sourceGraph;  // Graph of source ownership relationships
  }

  /**
   * Finds independent corroborations for a claim.
   * Returns only sources that are genuinely independent.
   */
  async findCorroborations(claim, existingSources = []) {
    const rawResults = await this.search.searchClaim(claim);

    const corroborations = [];
    const rootSources = new Set(existingSources.map(s => this._findRootSource(s)));

    for (const result of rawResults) {
      const rootSource = this._findRootSource(result.domain);

      // Skip if this is the same root source as something we already have
      if (rootSources.has(rootSource)) continue;

      // Skip if owned by same parent company
      if (await this._shareOwnership(result.domain, [...existingSources])) continue;

      rootSources.add(rootSource);
      corroborations.push({
        ...result,
        rootSource,
        independenceScore: await this._computeIndependenceScore(result.domain, [...existingSources]),
      });
    }

    return {
      corroborations,
      independentCount: corroborations.length,
      // Bayesian: P(claim true | N independent confirmations)
      combinedConfidence: this._bayesianCombine(
        corroborations.map(c => c.trustScore * c.independenceScore)
      ),
    };
  }

  /**
   * Bayesian combination of independent evidence.
   *
   * FORMULA: P(H|E1,E2,...,En) assuming conditional independence
   *   = P(H) * ∏ P(Ei|H) / P(Ei)
   *
   * In practice, we use log-odds form to avoid underflow:
   *   log-odds(posterior) = log-odds(prior) + Σ log-likelihood-ratios
   */
  _bayesianCombine(evidenceScores) {
    if (evidenceScores.length === 0) return 0.5;

    const prior = 0.5;  // No prior belief
    let logOdds = Math.log(prior / (1 - prior));

    for (const score of evidenceScores) {
      // Each piece of evidence with strength s contributes log(s / (1-s))
      const s = clamp(score, 0.01, 0.99);
      logOdds += Math.log(s / (1 - s));
    }

    return 1 / (1 + Math.exp(-logOdds));
  }

  _findRootSource(domain) {
    // Walk up the ownership graph to find the root publisher
    return this.sourceGraph.getRoot(domain) || domain;
  }

  async _shareOwnership(domain, otherDomains) {
    const owners = await Promise.all(
      [domain, ...otherDomains].map(d => this.sourceGraph.getOwner(d))
    );
    const domainOwner = owners[0];
    return owners.slice(1).some(o => o === domainOwner);
  }

  async _computeIndependenceScore(domain, existingSources) {
    const sharedInfrastructure = await this._checkSharedInfrastructure(domain, existingSources);
    const geographicDiversity  = await this._checkGeographicDiversity(domain, existingSources);

    // Lower score if shared IP ranges, same CDN, same hosting provider
    return clamp(1 - sharedInfrastructure * 0.5 + geographicDiversity * 0.1, 0, 1);
  }

  async _checkSharedInfrastructure(domain, others) {
    // Check for shared IP ranges, WHOIS, name servers
    return 0;  // Stub
  }

  async _checkGeographicDiversity(domain, others) {
    return 0;  // Stub
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 9 — HISTORICAL CONSISTENCY ENGINE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * HistoricalConsistencyEngine: Checks claims against recorded history.
 *
 * RULE: Contradiction between a claim's stated timeline and verifiable
 *       historical records is a high-severity flag.
 *
 * RULE: "Has this happened before?" is always asked.
 *       New events claiming to be old events are suspicious.
 *
 * Examples of contradictions to detect:
 *   - Company website says "Founded 2004" but WHOIS shows domain registered 2018
 *   - Person claims to be in Location A at Time T but photo EXIF places them elsewhere
 *   - Event claimed at Date D but first known online mention is Date D+30
 *   - Scientific claim contradicting established peer-reviewed consensus
 */
class HistoricalConsistencyEngine {
  constructor(archiveClient, knowledgeGraph) {
    this.archive = archiveClient;       // Wayback Machine / Common Crawl client
    this.kg = knowledgeGraph;           // Internal knowledge graph
  }

  async checkConsistency(eo) {
    const contradictions = [];
    const confirmations  = [];

    // 1. Timeline consistency
    const timeline = await this._buildTimeline(eo);
    for (const conflict of timeline.conflicts) {
      contradictions.push({
        type: 'TIMELINE_CONFLICT',
        severity: 'high',
        description: conflict.description,
        evidence: [conflict.claimedRecord, conflict.historicalRecord],
      });
    }

    // 2. Archive consistency (does this content match its archived history?)
    if (eo.source) {
      const archiveCheck = await this.archive.compareVersions(eo.source);
      if (archiveCheck.significantChanges.length > 0) {
        for (const change of archiveCheck.significantChanges) {
          contradictions.push({
            type: 'ARCHIVE_INCONSISTENCY',
            severity: 'medium',
            description: `Content changed significantly on ${change.date}: ${change.description}`,
          });
        }
      }
    }

    // 3. Existence precedes claim
    const earliestMention = await this.archive.findEarliestMention(eo);
    if (earliestMention && eo.timestamp.claimed) {
      const claimed = new Date(eo.timestamp.claimed);
      const earliest = new Date(earliestMention.date);
      if (earliest > claimed) {
        // First known online mention is AFTER the claimed date
        const daysDiff = Math.round((earliest - claimed) / 86_400_000);
        contradictions.push({
          type: 'BACKDATING_SUSPECTED',
          severity: daysDiff > 365 ? 'critical' : 'high',
          description: `First known mention is ${daysDiff} days after claimed date`,
          evidence: [earliestMention],
        });
      }
    }

    // 4. Scientific/empirical consistency
    if (eo.type === EVIDENCE_TYPES.ARTICLE || eo.type === EVIDENCE_TYPES.TWEET) {
      const empiricalCheck = await this._checkEmpiricalClaims(eo);
      contradictions.push(...empiricalCheck.contradictions);
      confirmations.push(...empiricalCheck.confirmations);
    }

    return {
      contradictions,
      confirmations,
      consistencyScore: this._computeConsistencyScore(contradictions, confirmations),
    };
  }

  /**
   * Builds a complete timeline for an EO and checks for internal contradictions.
   *
   * For a company:   domain registration ≤ founding claim ≤ first news mention
   * For a person:    birth date ≤ account creation ≤ first verified activity
   * For an event:    setup signals ≤ event date ≤ aftermath signals
   */
  async _buildTimeline(eo) {
    const events = [];
    const conflicts = [];

    // Collect all timestamped evidence
    if (eo.metadata.domainRegistered) events.push({ label: 'Domain registered', date: eo.metadata.domainRegistered });
    if (eo.author.accountAge)          events.push({ label: 'Account created', date: eo.author.accountAge });
    if (eo.timestamp.claimed)          events.push({ label: 'Claimed date', date: eo.timestamp.claimed });
    if (eo.timestamp.earliest)         events.push({ label: 'Earliest known', date: eo.timestamp.earliest });

    // Sort and check for logical order violations
    events.sort((a, b) => new Date(a.date) - new Date(b.date));

    // Domain registered MUST come before domain-dependent events
    const domainReg = events.find(e => e.label === 'Domain registered');
    const claimedFounding = events.find(e => e.label === 'Claimed founding');
    if (domainReg && claimedFounding && new Date(domainReg.date) > new Date(claimedFounding.date)) {
      conflicts.push({
        description: `Domain registered (${domainReg.date}) after claimed founding date (${claimedFounding.date})`,
        claimedRecord: claimedFounding,
        historicalRecord: domainReg,
      });
    }

    return { events, conflicts };
  }

  async _checkEmpiricalClaims(eo) {
    // Extract factual claims from text and cross-check against knowledge graph
    const claims = await extractFactualClaims(eo.raw);
    const contradictions = [];
    const confirmations = [];

    for (const claim of claims) {
      const kgResult = await this.kg.query(claim);
      if (kgResult.contradicts) {
        contradictions.push({
          type: 'FACTUAL_CONTRADICTION',
          severity: 'high',
          description: `Claim contradicts established record: "${claim.text}"`,
          source: kgResult.source,
        });
      } else if (kgResult.confirms) {
        confirmations.push({ claim, source: kgResult.source });
      }
    }

    return { contradictions, confirmations };
  }

  _computeConsistencyScore(contradictions, confirmations) {
    const criticalCount = contradictions.filter(c => c.severity === 'critical').length;
    const highCount     = contradictions.filter(c => c.severity === 'high').length;
    const mediumCount   = contradictions.filter(c => c.severity === 'medium').length;

    const penalty = criticalCount * 0.4 + highCount * 0.2 + mediumCount * 0.1;
    const bonus   = confirmations.length * 0.05;

    return clamp(1 - penalty + bonus, 0, 1);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 10 — ANTI-MANIPULATION ENGINE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * AntiManipulationEngine: Detects coordinated inauthentic behavior.
 *
 * RULE: Manipulation leaves statistical fingerprints.
 *       Natural networks look very different from manufactured ones.
 *
 * Detects:
 *   Bot farms              — accounts with machine-like behavior patterns
 *   Coordinated campaigns  — statistically unlikely timing correlations
 *   Mass reposts           — identical content across unconnected accounts
 *   Fake followers         — follower graphs with bot signatures
 *   Purchased engagement   — engagement patterns inconsistent with audience size
 *   Click farms            — unnaturally uniform geographic engagement
 *   SEO manipulation       — link networks, keyword stuffing patterns
 *   Shared infrastructure  — multiple "independent" sources sharing hosting
 *   Timing anomalies       — coordinated posting times across platforms
 *   Graph anomalies        — network topology inconsistent with organic growth
 */
class AntiManipulationEngine {
  /**
   * Analyzes a set of accounts for coordinated inauthentic behavior.
   * Uses graph analysis to detect clusters of accounts behaving unusually similarly.
   *
   * ALGORITHM:
   *   1. Build interaction graph (who follows/retweets/replies whom)
   *   2. Compute behavioral vectors for each account
   *      (posting times, content types, response delays, language patterns)
   *   3. Detect clusters using cosine similarity > threshold
   *   4. Test timing correlations using cross-correlation
   *   5. Check content fingerprints for near-duplicate posts
   *   6. Assign manipulation probability to each cluster
   */
  async analyzeAccountNetwork(accounts, interactions) {
    const signals = [];

    // Step 1: Build behavioral vectors
    const vectors = accounts.map(acc => this._computeBehaviorVector(acc));

    // Step 2: Find suspicious clusters
    const clusters = this._clusterBySimilarity(vectors, 0.92);

    for (const cluster of clusters) {
      if (cluster.accounts.length < 5) continue;  // Minimum cluster size

      // Step 3: Test timing correlation within cluster
      const timingCorrelation = this._testTimingCorrelation(cluster.accounts, interactions);
      if (timingCorrelation.r > 0.85) {
        signals.push(flag('COORDINATED_TIMING_CLUSTER', 'high',
          `Cluster of ${cluster.accounts.length} accounts with posting time correlation r=${timingCorrelation.r.toFixed(2)}`));
      }

      // Step 4: Content fingerprint overlap
      const contentOverlap = this._testContentOverlap(cluster.accounts);
      if (contentOverlap.duplicateRate > 0.8) {
        signals.push(flag('MASS_REPOST_NETWORK', 'critical',
          `${(contentOverlap.duplicateRate * 100).toFixed(0)}% content overlap in cluster of ${cluster.accounts.length} accounts`));
      }

      // Step 5: Account age distribution
      const ageDistribution = cluster.accounts.map(a => a.ageDays);
      const stdDev = standardDeviation(ageDistribution);
      if (stdDev < 3 && cluster.accounts.length > 20) {
        signals.push(flag('BATCH_ACCOUNT_CREATION', 'critical',
          `${cluster.accounts.length} accounts created within ${(stdDev * 2).toFixed(0)} days of each other`));
      }
    }

    // Engagement anomaly detection
    for (const account of accounts) {
      const engagementAnomaly = this._detectEngagementAnomaly(account);
      if (engagementAnomaly.suspicious) {
        signals.push(flag('ENGAGEMENT_ANOMALY', 'medium',
          `@${account.username}: ${engagementAnomaly.description}`));
      }
    }

    return {
      signals,
      clusters: clusters.map(c => ({
        ...c,
        manipulationProbability: this._estimateManipulationProbability(c, signals),
      })),
      overallScore: computeSignalScore(signals),
    };
  }

  /**
   * Behavioral vector for an account. Dimensions:
   *   [postingHourHistogram(24), avgResponseDelay, contentRepetitionRate,
   *    followerToFollowingRatio, engagementRate, accountAgeDays,
   *    urlSharingRate, hashtagDensity, mentionDensity, languageEntropy]
   */
  _computeBehaviorVector(account) {
    return [
      ...normalizeHourHistogram(account.postingHours),  // 24 dims
      normalizeLog(account.avgResponseDelay),
      account.contentRepetitionRate,
      account.followerCount / Math.max(account.followingCount, 1),
      account.engagementRate,
      Math.log1p(account.ageDays) / 10,
      account.urlSharingRate,
      account.hashtagDensity,
      account.mentionDensity,
      account.languageEntropy,
    ];
  }

  _clusterBySimilarity(vectors, threshold) {
    // DBSCAN clustering on cosine similarity
    return dbscan(vectors, {
      epsilon: 1 - threshold,  // Convert similarity threshold to distance
      minPoints: 5,
      distance: cosineDissimilarity,
    });
  }

  _testTimingCorrelation(accounts, interactions) {
    const timeSeriesList = accounts.map(a =>
      interactions.filter(i => i.accountId === a.id).map(i => i.timestamp)
    );
    return crossCorrelationMax(timeSeriesList);
  }

  _testContentOverlap(accounts) {
    const hashes = accounts.flatMap(a => a.recentPosts.map(p => p.contentHash));
    const unique = new Set(hashes);
    return {
      duplicateRate: 1 - unique.size / Math.max(hashes.length, 1),
    };
  }

  _detectEngagementAnomaly(account) {
    // Expected engagement rate by follower tier (based on empirical baselines)
    const expectedRate = getExpectedEngagementRate(account.followerCount);
    const ratio = account.engagementRate / expectedRate;

    if (ratio > 5) return {
      suspicious: true,
      description: `Engagement rate ${ratio.toFixed(0)}x higher than expected for follower count — suggests fake engagement`,
    };
    if (ratio < 0.05) return {
      suspicious: true,
      description: `Engagement rate ${(ratio * 100).toFixed(1)}% of expected — suggests fake followers`,
    };

    return { suspicious: false };
  }

  _estimateManipulationProbability(cluster, signals) {
    const relatedSignals = signals.filter(s => s.clusterId === cluster.id);
    return clamp(relatedSignals.reduce((acc, s) => acc + severityToScore(s.severity) * 0.2, 0.1), 0, 1);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 11 — KNOWLEDGE GRAPH
// ─────────────────────────────────────────────────────────────────────────────

/**
 * KnowledgeGraph: Living graph of all verified and contested claims.
 *
 * RULE: All claims are versioned. Old states are never deleted.
 * RULE: Contradictions are tracked as edges, not removed.
 * RULE: The graph continuously updates as new evidence arrives.
 * RULE: Graph analysis reveals circular references, contradiction clusters,
 *       and information genealogy.
 *
 * Node types: Claim, Entity, Source, Person, Organization, Event, Location
 * Edge types: SUPPORTS, CONTRADICTS, CITES, AUTHORED_BY, PUBLISHED_BY,
 *             OCCURRED_AT, INVOLVES, SAME_AS, DERIVED_FROM
 */
class KnowledgeGraph {
  constructor(graphDb) {
    this.db = graphDb;
    this.cache = new LRUCache(10_000);
  }

  async addClaim(eo, relationships = []) {
    const node = {
      id: eo.id,
      type: 'Claim',
      content: eo.raw,
      score: eo.scores.overall,
      timestamp: eo.timestamp.observed,
      version: eo.version,
    };

    await this.db.upsertNode(node);

    for (const rel of relationships) {
      await this.db.addEdge({
        from: eo.id,
        to: rel.targetId,
        type: rel.type,           // SUPPORTS | CONTRADICTS | etc.
        confidence: rel.confidence,
        evidence: rel.evidence,
        timestamp: Date.now(),
      });
    }

    // Trigger contradiction cascade check
    await this._propagateContradictions(eo.id);
  }

  async query(claim) {
    const matches = await this.db.findSimilarClaims(claim.text);
    return {
      confirming:   matches.filter(m => m.edgeType === 'SUPPORTS'),
      contradicting: matches.filter(m => m.edgeType === 'CONTRADICTS'),
      confirms: matches.some(m => m.edgeType === 'SUPPORTS'),
      contradicts: matches.some(m => m.edgeType === 'CONTRADICTS'),
    };
  }

  /**
   * When a new claim is added, check if it contradicts existing confirmed claims.
   * If so, propagate score adjustments to all dependent claims.
   */
  async _propagateContradictions(newClaimId) {
    const contradictions = await this.db.findEdges(newClaimId, 'CONTRADICTS');

    for (const edge of contradictions) {
      const affected = await this.db.getNode(edge.to);
      if (!affected) continue;

      // Reduce confidence of contradicted claim
      const penalty = edge.confidence * 0.1;
      await this.db.updateNodeScore(affected.id, affected.score - penalty);

      // Recursively propagate to claims that depend on the affected claim
      const dependents = await this.db.findEdges(affected.id, 'SUPPORTS', { direction: 'incoming' });
      for (const dep of dependents) {
        await this.db.updateNodeScore(dep.from, (await this.db.getNode(dep.from)).score - penalty * 0.5);
      }
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 12 — IDENTITY VERIFICATION ENGINE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * IdentityEngine: Computes identity scores across platforms.
 *
 * Factors (each 0–1, with documented weight rationale):
 *
 *   accountAge (0.10)            — older accounts are harder to manufacture
 *   crossPlatformConsistency (0.15) — same name, bio, avatar across platforms
 *   verifiedBadge (0.08)         — official platform verification (not proof, but signal)
 *   domainOwnership (0.10)       — WHOIS-confirmed ownership of claimed domain
 *   pgpVerification (0.12)       — signed content verifiable with known public key
 *   blockchainProof (0.10)       — cryptographically provable claims
 *   governmentVerification (0.20) — state-issued ID or notarized documents
 *   organizationVerification (0.10) — institutional affiliation confirmed
 *   behavioralConsistency (0.05) — consistent writing style over time (stylometry)
 */
class IdentityEngine {
  async computeIdentityScore(authorProfile) {
    const factors = [];

    // Account age: sigmoid curve, matures around 2 years
    if (authorProfile.accountAge !== null) {
      const ageFactor = 1 / (1 + Math.exp(-(authorProfile.accountAge - 365) / 180));
      factors.push({ key: 'accountAge', value: ageFactor, weight: 0.10 });
    }

    // Cross-platform consistency
    const platformCount = Object.keys(authorProfile.crossPlatform).length;
    if (platformCount > 0) {
      const consistencyScore = await this._checkCrossPlatformConsistency(authorProfile.crossPlatform);
      factors.push({ key: 'crossPlatformConsistency', value: consistencyScore, weight: 0.15 });
    }

    // PGP verification
    if (authorProfile.pgpKeys.length > 0) {
      const pgpValid = await verifyPGPKeychain(authorProfile.pgpKeys);
      factors.push({ key: 'pgpVerification', value: pgpValid ? 0.9 : 0.1, weight: 0.12 });
    }

    // Government verification (highest weight)
    if (authorProfile.governmentVerified) {
      factors.push({ key: 'governmentVerification', value: 0.95, weight: 0.20 });
    } else {
      factors.push({ key: 'governmentVerification', value: 0.0, weight: 0.20 });
    }

    // Domain ownership
    if (authorProfile.domainOwnership.length > 0) {
      const domainValid = await verifyDomainOwnership(authorProfile.domainOwnership);
      factors.push({ key: 'domainOwnership', value: domainValid ? 0.85 : 0.2, weight: 0.10 });
    }

    // Blockchain proof
    if (authorProfile.blockchainOwnership.length > 0) {
      factors.push({ key: 'blockchainProof', value: 0.80, weight: 0.10 });
    }

    // Behavioral consistency (stylometry across writing samples)
    const styleScore = await this._checkStylometricConsistency(authorProfile);
    factors.push({ key: 'behavioralConsistency', value: styleScore, weight: 0.05 });

    const totalWeight = factors.reduce((s, f) => s + f.weight, 0);
    const weightedScore = factors.reduce((s, f) => s + f.value * f.weight, 0);

    return {
      score: totalWeight > 0 ? clamp(weightedScore / totalWeight, 0, 1) : 0.5,
      factors,
      dataPoints: factors.length,
    };
  }

  async _checkCrossPlatformConsistency(crossPlatform) {
    // Fetch profiles from each platform and compare
    const profiles = await Promise.allSettled(
      Object.entries(crossPlatform).map(([platform, username]) =>
        fetchPublicProfile(platform, username)
      )
    );

    const valid = profiles.filter(p => p.status === 'fulfilled').map(p => p.value);
    if (valid.length < 2) return 0.5;

    // Compare: profile photos (face similarity), bios, linked URLs
    const photoConsistency = await computeAveragePhotoSimilarity(valid.map(p => p.photo));
    const bioConsistency   = computeTextSimilarity(valid.map(p => p.bio));
    const linkConsistency  = computeLinkOverlap(valid.map(p => p.links));

    return weightedMean([[photoConsistency, 0.4], [bioConsistency, 0.3], [linkConsistency, 0.3]]);
  }

  async _checkStylometricConsistency(authorProfile) {
    // Compare writing samples using stylometric fingerprinting
    if (!authorProfile.writingSamples || authorProfile.writingSamples.length < 3) return 0.5;

    const fingerprints = authorProfile.writingSamples.map(computeStylometricFingerprint);
    const similarity   = computeAveragePairwiseSimilarity(fingerprints);

    // High similarity across samples = consistent author
    return clamp(similarity, 0, 1);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 13 — MATHEMATICAL CONFIDENCE MODEL
// ─────────────────────────────────────────────────────────────────────────────

/**
 * ConfidenceModel: Produces the final composite truth score.
 *
 * ARCHITECTURE:
 *   1. Gather all component scores from all engines
 *   2. Weight by evidence quality (more data → higher weight)
 *   3. Apply contradiction penalty
 *   4. Apply corroboration bonus
 *   5. Compute calibrated confidence interval
 *   6. Generate human-readable explanation
 *
 * FORMULA (simplified):
 *
 *   overall = (
 *     w₁ × authenticity +
 *     w₂ × provenance +
 *     w₃ × consistency +
 *     w₄ × corroboration +
 *     w₅ × manipulation +
 *     w₆ × sourceReputation +
 *     w₇ × identityTrust
 *   ) × (1 - contradictionPenalty) × corroborationMultiplier
 *
 *   confidence = f(sampleSize, consistency, cross-validation)
 */
class ConfidenceModel {
  computeOverallScore(components, contradictions, corroborations) {
    const WEIGHTS = {
      authenticity:      0.20,
      provenance:        0.15,
      consistency:       0.18,
      corroboration:     0.20,
      manipulation:      0.12,
      sourceReputation:  0.10,
      identityTrust:     0.05,
    };

    // Weighted sum of component scores
    let weightedSum = 0;
    let totalWeight = 0;
    const factorsUsed = [];

    for (const [key, weight] of Object.entries(WEIGHTS)) {
      const value = components[key];
      if (value === null || value === undefined) continue;

      weightedSum += value * weight;
      totalWeight += weight;
      factorsUsed.push({ key, value, weight });
    }

    let overall = totalWeight > 0 ? weightedSum / totalWeight : 0.5;

    // Contradiction penalty (multiplicative, not additive)
    const criticalContradictions = contradictions.filter(c => c.severity === 'critical').length;
    const highContradictions     = contradictions.filter(c => c.severity === 'high').length;
    const contradictionPenalty   = Math.min(0.8, criticalContradictions * 0.3 + highContradictions * 0.1);
    overall *= (1 - contradictionPenalty);

    // Corroboration multiplier (bounded at 1.0 — cannot exceed certainty)
    const corroborationBonus = Math.min(0.15, corroborations.independentCount * 0.02);
    overall = Math.min(1.0, overall + corroborationBonus);

    // Calibrated confidence interval (how certain are we of the overall score?)
    const confidence = this._computeConfidence(factorsUsed, corroborations);

    return {
      overall:   clamp(overall, 0, 1),
      confidence: confidence,
      low:       Math.max(0, overall - (1 - confidence) * 0.2),
      high:      Math.min(1, overall + (1 - confidence) * 0.2),
      factors:   factorsUsed,
    };
  }

  /**
   * Confidence in the overall score (meta-confidence).
   * Higher when: more data, consistent signals, strong corroboration.
   * Lower when: conflicting signals, sparse data, no corroboration.
   */
  _computeConfidence(factors, corroborations) {
    const dataCompleteness = factors.length / 7;        // 7 total components
    const signalConsistency = 1 - variance(factors.map(f => f.value));
    const corroborationFactor = Math.min(1, corroborations.independentCount / 5);

    return weightedMean([
      [dataCompleteness,      0.35],
      [signalConsistency,     0.40],
      [corroborationFactor,   0.25],
    ]);
  }

  /**
   * Generates a human-readable explanation for the score.
   *
   * RULE: Every score must explain itself.
   * RULE: Explanation must list the top contributing factors.
   * RULE: Explanation must list all critical flags.
   */
  generateExplanation(scoreResult, eo, flags, corroborations) {
    const lines = [];
    const score = scoreResult.overall;
    const pct   = Math.round(score * 100);

    lines.push(`Overall truth score: ${pct}/100 (confidence: ${Math.round(scoreResult.confidence * 100)}%)`);
    lines.push('');

    if (score >= 0.8)       lines.push('✓ HIGH CONFIDENCE — This content shows strong indicators of authenticity.');
    else if (score >= 0.6)  lines.push('⚠ MODERATE CONFIDENCE — Some indicators present but verification is incomplete.');
    else if (score >= 0.4)  lines.push('⚠ LOW CONFIDENCE — Significant uncertainty or contradictory signals detected.');
    else                    lines.push('✗ LIKELY INAUTHENTIC — Multiple strong indicators of manipulation or fabrication.');

    lines.push('');
    lines.push('SUPPORTING EVIDENCE:');

    if (corroborations.independentCount > 0) {
      lines.push(`  • ${corroborations.independentCount} independent source${corroborations.independentCount > 1 ? 's' : ''} corroborate this content`);
    }

    const strongFactors = scoreResult.factors.filter(f => f.value > 0.7);
    for (const f of strongFactors.slice(0, 3)) {
      lines.push(`  • ${factorToDescription(f.key, f.value)}`);
    }

    if (flags.length > 0) {
      lines.push('');
      lines.push('FLAGS:');
      const criticalFlags = flags.filter(f => f.severity === 'critical');
      const highFlags     = flags.filter(f => f.severity === 'high');

      for (const f of criticalFlags) lines.push(`  ✗ [CRITICAL] ${f.description}`);
      for (const f of highFlags)     lines.push(`  ! [HIGH]     ${f.description}`);
      if (flags.length > criticalFlags.length + highFlags.length) {
        lines.push(`  … and ${flags.length - criticalFlags.length - highFlags.length} lower-severity flags`);
      }
    }

    lines.push('');
    lines.push(`Score range: ${Math.round(scoreResult.low * 100)}–${Math.round(scoreResult.high * 100)}/100`);
    lines.push(`Analysis timestamp: ${new Date().toISOString()}`);

    return lines.join('\n');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 14 — SEARCH ENGINE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * SearchEngine: Controlled search for valid reference verification.
 *
 * RULE: Only use high-trust sources as authoritative references.
 * RULE: Search results are scored by source trust before inclusion.
 * RULE: Results must be deduplicated by root source.
 *
 * PREFERRED SOURCES (configurable by domain):
 *   Government: .gov domains, official government press releases
 *   Science:    PubMed, DOI-linked papers, peer-reviewed journals
 *   Legal:      PACER, official court records, official bar associations
 *   Finance:    SEC EDGAR, FINRA, official exchange feeds
 *   History:    National archives, major university archives, Wayback Machine
 *   General:    Reuters, AP, AFP, BBC, major newspapers with high trust scores
 *
 * AVOIDED SOURCES:
 *   Anonymous forums, content farms, sites with <0.4 trust score,
 *   sites with known misinformation history, recently registered domains
 */
class VerifiedSearchEngine {
  constructor(sourceTrustEngine, apiClient) {
    this.trust = sourceTrustEngine;
    this.api = apiClient;
  }

  async searchClaim(claim, options = {}) {
    const minTrust = options.minTrust ?? 0.5;
    const maxResults = options.maxResults ?? 10;

    const rawResults = await this.api.search(claim.text, {
      dateRange: options.dateRange,
      language: options.language,
    });

    // Score and filter results
    const scored = await Promise.all(
      rawResults.map(async result => {
        const trustScore = await this.trust.computeScore(result.url);
        return { ...result, trustScore: trustScore.trust };
      })
    );

    return scored
      .filter(r => r.trustScore >= minTrust)
      .sort((a, b) => b.trustScore - a.trustScore)
      .slice(0, maxResults);
  }

  async reverseImageSearch(imageHash) {
    // Check known image databases for prior existence
    const results = await this.api.reverseImageSearch(imageHash);
    return {
      earliestKnownDate: results[0]?.date ?? null,
      earliestKnownUrl:  results[0]?.url  ?? null,
      allInstances:      results,
      // Was this image originally from somewhere it's now claimed not to be?
      possibleMisattribution: results.length > 0 && results[0].context !== null,
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 15 — CONTINUOUS LEARNING SYSTEM
// ─────────────────────────────────────────────────────────────────────────────

/**
 * ContinuousLearningSystem: Feeds verified outcomes back into all subsystems.
 *
 * RULE: Every verified outcome updates the relevant scoring systems.
 * RULE: Learning is gradual (exponential moving average) to prevent
 *       individual cases from dominating long-term scores.
 * RULE: False positives and false negatives are weighted equally.
 * RULE: Human expert overrides are treated as ground truth.
 *
 * Updates:
 *   Source trust scores      — correct prediction → trust up, wrong → down
 *   AI detector calibration  — adjust detector thresholds based on outcomes
 *   Domain trust             — domain-level accuracy tracking
 *   Journalist accuracy      — individual journalist accuracy tracking
 *   Account trust            — account-level credibility tracking
 *   Bot databases            — confirmed bots added to ban list
 *   Image fingerprints       — confirmed manipulated images added to reference DB
 */
class ContinuousLearningSystem {
  constructor({ sourceTrustEngine, aiDetectionEngine, knowledgeGraph, database }) {
    this.source   = sourceTrustEngine;
    this.aiDetect = aiDetectionEngine;
    this.kg       = knowledgeGraph;
    this.db       = database;
  }

  async recordOutcome(eoId, outcome) {
    const {
      correct,          // boolean: did our score match reality?
      groundTruth,      // 0–1: actual truth score from expert review
      retracted,        // boolean: did source retract?
      corrected,        // boolean: did source issue a correction?
      botConfirmed,     // boolean: account confirmed as bot?
      manipulationConfirmed, // boolean: confirmed AI/edited content?
      domain,
      authorId,
      imagePHash,
    } = outcome;

    const updates = [];

    // Update source trust
    if (domain) {
      updates.push(this.source.updateAfterVerification(domain, outcome));
    }

    // Add confirmed bots to ban list
    if (botConfirmed && authorId) {
      updates.push(this.db.addConfirmedBot(authorId));
    }

    // Add confirmed manipulated image to reference database
    if (manipulationConfirmed && imagePHash) {
      updates.push(this.db.addManipulatedImageFingerprint(imagePHash));
    }

    // Update knowledge graph with ground truth
    updates.push(this.kg.addClaim({ id: eoId, scores: { overall: groundTruth } }));

    // Recalibrate AI detector thresholds
    if (manipulationConfirmed !== undefined) {
      updates.push(this._recalibrateAIDetectors(eoId, manipulationConfirmed));
    }

    await Promise.allSettled(updates);
  }

  async _recalibrateAIDetectors(eoId, wasActuallyAI) {
    const record = await this.db.getEORecord(eoId);
    if (!record?.aiDetectionResult) return;

    const { combined: predictedScore } = record.aiDetectionResult;
    const actual = wasActuallyAI ? 1 : 0;
    const error  = actual - predictedScore;

    // Store calibration data point for threshold adjustment
    await this.db.addCalibrationPoint({ predictedScore, actual, error });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 16 — PLATFORM-SPECIFIC ADAPTERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * PlatformAdapters: Platform-specific evidence collection methods.
 *
 * Each adapter normalizes platform data into an EvidenceObject.
 * Adapters are responsible for collecting all available public metadata.
 */

const PlatformAdapters = {

  async instagram(profileUrl) {
    const data = await fetchInstagramProfile(profileUrl);
    const eo   = new EvidenceObject(data, EVIDENCE_TYPES.INSTAGRAM);
    eo.source  = profileUrl;
    eo.author.usernames     = [data.username];
    eo.author.accountAge    = data.accountAge;
    eo.metadata.followerCount = data.followerCount;
    eo.metadata.followingCount = data.followingCount;
    eo.metadata.postCount   = data.postCount;
    eo.metadata.verifiedBadge = data.verified;
    eo.metadata.businessAccount = data.isBusinessAccount;
    eo.metadata.avgLikes    = data.avgLikes;
    eo.metadata.avgComments = data.avgComments;
    // Cross-check engagement rate against follower count
    eo.metadata.engagementRate = (data.avgLikes + data.avgComments) / Math.max(data.followerCount, 1);
    return eo;
  },

  async twitter(tweetUrl) {
    const data = await fetchTweetData(tweetUrl);
    const eo   = new EvidenceObject(data, EVIDENCE_TYPES.TWEET);
    eo.source  = tweetUrl;
    eo.author.usernames     = [data.authorUsername];
    eo.author.accountAge    = data.authorCreatedDaysAgo;
    eo.timestamp.claimed    = data.createdAt;
    eo.metadata.retweetCount = data.retweetCount;
    eo.metadata.likeCount   = data.likeCount;
    eo.metadata.replyCount  = data.replyCount;
    eo.metadata.quoteCount  = data.quoteCount;
    eo.metadata.verifiedBadge = data.authorVerified;
    eo.metadata.isReply     = data.isReply;
    eo.metadata.hasMedia    = data.hasMedia;
    return eo;
  },

  async spotifyArtist(artistUrl) {
    // Checks if an artist is real/human vs. AI-generated music spam
    const data = await fetchSpotifyArtistData(artistUrl);
    const eo   = new EvidenceObject(data, EVIDENCE_TYPES.SPOTIFY_ARTIST);
    eo.source  = artistUrl;
    eo.author.realName = data.artistName;

    // Key signals for AI music detection:
    eo.metadata.monthlyListeners = data.monthlyListeners;
    eo.metadata.followerCount    = data.followerCount;
    eo.metadata.trackCount       = data.trackCount;
    eo.metadata.albumCount       = data.albumCount;
    eo.metadata.releaseFrequency = data.releaseFrequency;  // Tracks per month
    eo.metadata.pressSaves       = data.pressSaves;        // Editorial playlist placements
    eo.metadata.socialPresence   = data.hasSocialLinks;
    eo.metadata.livePerformances = data.liveEventCount;
    eo.metadata.labelSigned      = data.labelName;

    // AI music spam signals:
    //   Very high release frequency + no social presence + no live shows
    //   + generic/keyword-stuffed bio + abnormal listener/follower ratio
    return eo;
  },

  async email(emailAddress) {
    const eo = new EvidenceObject(emailAddress, EVIDENCE_TYPES.EMAIL);
    eo.source = emailAddress;
    const [localPart, domain] = emailAddress.split('@');
    eo.metadata.domain     = domain;
    eo.metadata.localPart  = localPart;
    // DNS checks
    eo.metadata.mxRecords  = await checkMXRecords(domain);
    eo.metadata.spfRecord  = await checkSPFRecord(domain);
    eo.metadata.dkimRecord = await checkDKIMRecord(domain);
    eo.metadata.dmarcRecord = await checkDMARCRecord(domain);
    // Domain age and reputation
    eo.metadata.domainAge  = await getDomainAge(domain);
    eo.metadata.disposable = await isDisposableEmailDomain(domain);
    eo.metadata.breachHistory = await checkBreachHistory(emailAddress);
    return eo;
  },

  async website(url) {
    const eo = new EvidenceObject(url, EVIDENCE_TYPES.WEBSITE);
    eo.source = url;
    const domain = extractDomain(url);
    eo.metadata.whois        = await getWhoisData(domain);
    eo.metadata.sslCert      = await getSSLCertInfo(url);
    eo.metadata.domainAge    = eo.metadata.whois?.created;
    eo.metadata.registrar    = eo.metadata.whois?.registrar;
    eo.metadata.nameServers  = eo.metadata.whois?.nameServers;
    eo.metadata.ipAddress    = await resolveIP(domain);
    eo.metadata.hostingInfo  = await getHostingInfo(eo.metadata.ipAddress);
    eo.metadata.httpHeaders  = await fetchHttpHeaders(url);
    eo.metadata.alexa        = await getTrafficRank(domain);
    eo.metadata.waybackFirst = await getWaybackFirstSeen(domain);
    return eo;
  },

  async blockchainWallet(address, chainId = 'ethereum') {
    const data = await fetchWalletData(address, chainId);
    const eo   = new EvidenceObject(data, EVIDENCE_TYPES.BLOCKCHAIN_TX);
    eo.source  = `${chainId}:${address}`;
    eo.metadata.chain          = chainId;
    eo.metadata.balance        = data.balance;
    eo.metadata.txCount        = data.transactionCount;
    eo.metadata.firstTx        = data.firstTransactionDate;
    eo.metadata.lastTx         = data.lastTransactionDate;
    eo.metadata.knownLabels    = data.knownLabels;   // e.g., "Binance Hot Wallet"
    eo.metadata.sanctionsList  = data.isOnSanctionsList;  // OFAC, etc.
    eo.metadata.contractInteractions = data.uniqueContractsInteracted;
    return eo;
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 17 — MAIN VERIFIER ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verifier: The top-level orchestrator.
 *
 * Coordinates all engines, applies all laws, produces the final scored
 * and explained EvidenceObject.
 *
 * PROCESSING PIPELINE:
 *   1. Normalize input → EvidenceObject
 *   2. Extract metadata
 *   3. Run identity verification
 *   4. Run source trust check
 *   5. Run metadata analysis (type-specific)
 *   6. Run AI detection ensemble
 *   7. Run blockchain timestamp check
 *   8. Run cross-reference search
 *   9. Run historical consistency check
 *  10. Run anti-manipulation check
 *  11. Compute composite score
 *  12. Generate explanation
 *  13. Store in knowledge graph
 *  14. Return scored EO
 */
class Verifier {
  constructor(config) {
    this.db          = config.database;
    this.metadata    = new MetadataEngine();
    this.aiDetect    = new AIDetectionEngine();
    this.blockchain  = new BlockchainLayer(config.rpcProviders);
    this.identity    = new IdentityEngine();
    this.sourceTrust = new SourceTrustEngine(config.database);
    this.search      = new VerifiedSearchEngine(this.sourceTrust, config.searchApi);
    this.crossRef    = new CrossReferenceEngine(this.search, config.sourceGraph);
    this.history     = new HistoricalConsistencyEngine(config.archiveClient, config.knowledgeGraph);
    this.antiManip   = new AntiManipulationEngine();
    this.kg          = config.knowledgeGraph;
    this.confidence  = new ConfidenceModel();
    this.learning    = new ContinuousLearningSystem({
      sourceTrustEngine: this.sourceTrust,
      aiDetectionEngine: this.aiDetect,
      knowledgeGraph:    this.kg,
      database:          this.db,
    });
  }

  /**
   * Main verification entry point.
   *
   * @param {any}    input — Raw input (URL, file, text, object)
   * @param {string} type  — EVIDENCE_TYPES constant
   * @param {object} options — {context, locale, claimedDate, relatedEOs}
   * @returns {EvidenceObject} — Fully scored and explained EO
   */
  async verify(input, type, options = {}) {
    // ── STEP 1: Normalize to EvidenceObject ─────────────────────────────────
    let eo = type in PlatformAdapters
      ? await PlatformAdapters[type](input)
      : new EvidenceObject(input, type);

    if (options.claimedDate) eo.timestamp.claimed = options.claimedDate;

    const allFlags = [];

    // ── STEP 2: Identity verification ───────────────────────────────────────
    const identityResult = await this.identity.computeIdentityScore(eo.author);
    eo.author.identityScore = identityResult.score;

    // ── STEP 3: Source trust ─────────────────────────────────────────────────
    const sourceTrust = eo.source
      ? await this.sourceTrust.computeScore(eo.source)
      : { trust: 0.5, factors: [] };

    // ── STEP 4: Metadata analysis (type-specific) ───────────────────────────
    let metadataResult = { score: null, signals: [] };

    if (type === EVIDENCE_TYPES.IMAGE) {
      metadataResult = this.metadata.analyzeImage(eo.metadata.exif, eo.media.rawPixels);
    } else if (type === EVIDENCE_TYPES.VIDEO) {
      metadataResult = this.metadata.analyzeVideo(
        eo.media.frames, eo.media.audioTrack, eo.metadata.container
      );
    } else if (type === EVIDENCE_TYPES.AUDIO) {
      metadataResult = this.metadata.analyzeAudio(eo.media.audioBuffer, eo.media.sampleRate);
    }

    allFlags.push(...metadataResult.signals);

    // ── STEP 5: AI detection ─────────────────────────────────────────────────
    let aiResult = null;
    if ([EVIDENCE_TYPES.IMAGE, EVIDENCE_TYPES.VIDEO].includes(type)) {
      aiResult = await this.aiDetect.detectAIImage(eo.media.rawPixels);
      if (aiResult.combined > 0.7) {
        allFlags.push(flag('AI_GENERATED_CONTENT', 'critical',
          `AI-generated content probability: ${(aiResult.combined * 100).toFixed(0)}%`));
      }
    }

    // ── STEP 6: Blockchain timestamp ─────────────────────────────────────────
    let blockchainResult = null;
    if (eo.hashes.sha256) {
      blockchainResult = await this.blockchain.verifyFileTimestamp(eo.hashes.sha256);
      if (blockchainResult.found) {
        const blockTime = new Date(blockchainResult.earliestBlock.blockTime);
        // Is the blockchain timestamp consistent with the claimed date?
        if (eo.timestamp.claimed) {
          const claimed = new Date(eo.timestamp.claimed);
          const diffDays = Math.abs(blockTime - claimed) / 86_400_000;
          if (diffDays > 30) {
            allFlags.push(flag('BLOCKCHAIN_TIMESTAMP_MISMATCH', 'high',
              `Blockchain timestamp (${blockTime.toDateString()}) differs from claimed date by ${Math.round(diffDays)} days`));
          }
        }
        eo.timestamp.earliest = blockchainResult.earliestBlock.blockTime;
      }
    }

    // ── STEP 7: Cross-reference search ───────────────────────────────────────
    const corroborations = await this.crossRef.findCorroborations(
      { text: eo.raw },
      eo.source ? [eo.source] : []
    );

    // ── STEP 8: Historical consistency ───────────────────────────────────────
    const historyResult = await this.history.checkConsistency(eo);
    allFlags.push(...historyResult.contradictions.map(c =>
      flag(c.type, c.severity, c.description)
    ));

    // ── STEP 9: Anti-manipulation (if we have account data) ──────────────────
    let manipulationResult = { overallScore: 0.9, signals: [] };
    if (eo.metadata.relatedAccounts) {
      manipulationResult = await this.antiManip.analyzeAccountNetwork(
        eo.metadata.relatedAccounts,
        eo.metadata.interactions || []
      );
      allFlags.push(...manipulationResult.signals);
    }

    // ── STEP 10: Compute composite score ─────────────────────────────────────
    const components = {
      authenticity:      metadataResult.score,
      provenance:        blockchainResult?.found ? 0.9 : 0.4,
      consistency:       historyResult.consistencyScore,
      corroboration:     corroborations.combinedConfidence,
      manipulation:      aiResult ? 1 - aiResult.combined : manipulationResult.overallScore,
      sourceReputation:  sourceTrust.trust,
      identityTrust:     identityResult.score,
    };

    const scoreResult = this.confidence.computeOverallScore(
      components,
      allFlags.filter(f => ['critical', 'high'].includes(f.severity)),
      corroborations
    );

    // ── STEP 11: Generate explanation ────────────────────────────────────────
    const explanation = this.confidence.generateExplanation(
      scoreResult, eo, allFlags, corroborations
    );

    // ── STEP 12: Store in knowledge graph ────────────────────────────────────
    eo = eo.update({
      scores: Object.assign(eo.scores, {
        overall:    scoreResult.overall,
        confidence: scoreResult.confidence,
        components,
        flags:      allFlags,
        factors:    scoreResult.factors,
        explanation,
      }),
    });

    await this.kg.addClaim(eo, options.relatedEOs?.map(r => ({
      targetId:   r.id,
      type:       r.relationship,
      confidence: r.confidence,
    })));

    return eo;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 18 — UTILITY FUNCTIONS
// ─────────────────────────────────────────────────────────────────────────────

function generateId() {
  // UUID v4
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

function validateType(type) {
  if (!Object.values(EVIDENCE_TYPES).includes(type)) {
    throw new Error(`Unknown evidence type: ${type}. Must be one of: ${Object.values(EVIDENCE_TYPES).join(', ')}`);
  }
  return type;
}

function flag(type, severity, description, data = {}) {
  return { type, severity, description, data, timestamp: Date.now() };
}

function clamp(v, min, max) { return Math.min(max, Math.max(min, v)); }

function lerp(a, b, t) { return a + (b - a) * t; }

function mean(arr) {
  if (arr.length === 0) return 0;
  return arr.reduce((s, v) => s + v, 0) / arr.length;
}

function variance(arr) {
  if (arr.length < 2) return 0;
  const m = mean(arr);
  return mean(arr.map(v => (v - m) ** 2));
}

function standardDeviation(arr) { return Math.sqrt(variance(arr)); }

function weightedMean(pairs) {
  const totalWeight = pairs.reduce((s, [, w]) => s + w, 0);
  return pairs.reduce((s, [v, w]) => s + v * w, 0) / totalWeight;
}

function extractDomain(url) {
  try {
    return new URL(url.startsWith('http') ? url : `https://${url}`).hostname
      .replace(/^www\./, '');
  } catch {
    return url;
  }
}

function computeSignalScore(signals) {
  if (signals.length === 0) return 0.9;  // No signals = probably clean
  const penalties = {
    critical: 0.40,
    high:     0.20,
    medium:   0.10,
    low:      0.05,
    info:     0.01,
  };
  const totalPenalty = signals.reduce((s, sig) => s + (penalties[sig.severity] || 0), 0);
  return clamp(1 - totalPenalty, 0, 1);
}

function severityToScore(severity) {
  return { critical: 1.0, high: 0.75, medium: 0.5, low: 0.25, info: 0.1 }[severity] || 0;
}

function defaultSourceRecord(domain) {
  return {
    domain,
    accuracyHistory:        0.5,
    originalReportingRatio: 0.5,
    citationQuality:        0.5,
    factCheckHistory:       0.5,
    ownershipTransparency:  0.5,
    retractionsRatio:       0.1,
    historicalCorrections:  0.5,
    domainAge:              0.3,
    archiveConsistency:     0.5,
    politicalBiasIndex:     0.5,
    sslHistory:             0.5,
    anonymousSourceUsage:   0.3,
    aiGeneratedRate:        0.1,
    botInteractionRate:     0.1,
    brokenLinkRate:         0.1,
    trafficAnomalies:       0.1,
    contentDuplication:     0.1,
    whoisHistory:           0.5,
    verifiedStories:        0,
  };
}

function deepFreeze(obj) {
  Object.getOwnPropertyNames(obj).forEach(name => {
    const value = obj[name];
    if (value && typeof value === 'object') deepFreeze(value);
  });
  return Object.freeze(obj);
}

function factorToDescription(key, value) {
  const descriptions = {
    authenticity:      `Metadata analysis: ${pctStr(value)} authentic`,
    provenance:        `Provenance: ${pctStr(value)} traceable`,
    consistency:       `Historical consistency: ${pctStr(value)}`,
    corroboration:     `${pctStr(value)} corroboration confidence`,
    manipulation:      `Manipulation detection: ${pctStr(value)} clean`,
    sourceReputation:  `Source reputation: ${pctStr(value)}`,
    identityTrust:     `Identity confidence: ${pctStr(value)}`,
  };
  return descriptions[key] || `${key}: ${pctStr(value)}`;
}

function pctStr(v) { return `${Math.round(v * 100)}%`; }

// Stub implementations for ML functions (documented interface for integration)
function runGANDetector(frames)         { return 0; }  // Replace with actual model
function runDiffusionDetector(frames)   { return 0; }  // Replace with actual model
function runTextureAnalyzer(frames)     { return 0; }  // Replace with actual model
function runFrequencyAnalyzer(frames)   { return 0; }  // Replace with actual model
function runWatermarkDetector(frames)   { return 0; }  // Replace with actual model
function runModelFingerprinter(frames)  { return 0; }  // Replace with actual model
function runPromptResidueDetector(fr)   { return 0; }  // Replace with actual model
function runSemanticAnalyzer(frames)    { return 0; }  // Replace with actual model
function perceptualHash(data)           { return ''; }  // e.g., pHash library
function hammingDistance(a, b)          { return 0; }
function haversineDistance(a, b)        { return 0; }
function detectGANArtifacts(data)       { return 0; }
function detectDiffusionArtifacts(d)    { return 0; }
function detectTextureAnomalies(d)      { return 0; }
function analyzeFrequencyDomain(d)      { return 0; }
function detectAIWatermark(data)        { return false; }
function identifyAIModel(data)          { return null; }
function splitIntoPatchGrid(d, g)       { return []; }
function detectAIVoice(spec, buf)       { return { combined: 0 }; }
function computeSpectrogram(buf, sr)    { return null; }
function measureNoiseFloor(buf, sr)     { return { varianceHigh: false, changePoints: [] }; }
function analyzeBreathingPatterns(b, r) { return { plausible: true }; }
function detectSpectrogramCuts(spec)    { return []; }
function detectFrameTimingAnomalies(p)  { return []; }
function analyzeLipSync(frames, audio)  { return { offset_ms: 0 }; }
function matchQuantizationTable(tables) { return null; }
function isCameraReleaseAfter(m, date)  { return false; }
function analyzeShadowConsistency(p)    { return { contradictionDetected: false }; }
function computeBurstiness(text)        { return { score: 0.5 }; }
function computePerplexity(text)        { return { score: 0.5 }; }
function analyzeNgramDistributions(t)   { return { score: 0.5 }; }
function runStylometricAnalysis(text)   { return { score: 0.5 }; }
function computeStylometricFingerprint(t){ return []; }
function computeAveragePairwiseSimilarity(fps) { return 0.5; }
function computeTextSimilarity(texts)   { return 0.5; }
function computeLinkOverlap(links)      { return 0.5; }
function computeAveragePhotoSimilarity(photos) { return Promise.resolve(0.5); }
function fetchPublicProfile(p, u)       { return Promise.resolve({}); }
function verifyPGPKeychain(keys)        { return Promise.resolve(true); }
function verifyDomainOwnership(domains) { return Promise.resolve(true); }
function extractFactualClaims(text)     { return Promise.resolve([]); }
function detectVolumeAnomaly(sym, vol)  { return { zscore: 0 }; }
function analyzeTradeTimingClustering(ts) { return { pValue: 1 }; }
function checkNewsProximity(sym, ts)    { return Promise.resolve({ withinHours: 999 }); }
function normalizeHourHistogram(hours)  { return new Array(24).fill(1/24); }
function normalizeLog(v)                { return v ? Math.log1p(v) / 20 : 0.5; }
function dbscan(vectors, opts)          { return []; }
function cosineDissimilarity(a, b)      { return 0; }
function crossCorrelationMax(series)    { return { r: 0 }; }
function getExpectedEngagementRate(n)   { return 0.02; }
function checkMXRecords(d)              { return Promise.resolve([]); }
function checkSPFRecord(d)              { return Promise.resolve(null); }
function checkDKIMRecord(d)             { return Promise.resolve(null); }
function checkDMARCRecord(d)            { return Promise.resolve(null); }
function getDomainAge(d)                { return Promise.resolve(null); }
function isDisposableEmailDomain(d)     { return Promise.resolve(false); }
function checkBreachHistory(e)          { return Promise.resolve([]); }
function getWhoisData(d)                { return Promise.resolve({}); }
function getSSLCertInfo(u)              { return Promise.resolve({}); }
function resolveIP(d)                   { return Promise.resolve(null); }
function getHostingInfo(ip)             { return Promise.resolve({}); }
function fetchHttpHeaders(u)            { return Promise.resolve({}); }
function getTrafficRank(d)              { return Promise.resolve(null); }
function getWaybackFirstSeen(d)         { return Promise.resolve(null); }
function fetchWalletData(addr, chain)   { return Promise.resolve({}); }
function fetchInstagramProfile(url)     { return Promise.resolve({}); }
function fetchTweetData(url)            { return Promise.resolve({}); }
function fetchSpotifyArtistData(url)    { return Promise.resolve({}); }

class LRUCache {
  constructor(max) {
    this.max = max;
    this.cache = new Map();
  }
  get(key) {
    if (!this.cache.has(key)) return undefined;
    const val = this.cache.get(key);
    this.cache.delete(key);
    this.cache.set(key, val);
    return val;
  }
  set(key, val) {
    if (this.cache.size >= this.max) {
      this.cache.delete(this.cache.keys().next().value);
    }
    this.cache.set(key, val);
  }
  has(key) { return this.cache.has(key); }
  delete(key) { this.cache.delete(key); }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 19 — EXPORTS
// ─────────────────────────────────────────────────────────────────────────────

module.exports = {
  // Core classes
  Verifier,
  EvidenceObject,
  AuthorProfile,
  ScoreBundle,

  // Engines (for standalone use or custom orchestration)
  SourceTrustEngine,
  MetadataEngine,
  AIDetectionEngine,
  BlockchainLayer,
  CrossReferenceEngine,
  HistoricalConsistencyEngine,
  AntiManipulationEngine,
  KnowledgeGraph,
  IdentityEngine,
  ConfidenceModel,
  ContinuousLearningSystem,
  VerifiedSearchEngine,

  // Platform adapters
  PlatformAdapters,

  // Constants
  EVIDENCE_TYPES,

  // Utilities
  flag,
  clamp,
  computeSignalScore,
  extractDomain,
};
