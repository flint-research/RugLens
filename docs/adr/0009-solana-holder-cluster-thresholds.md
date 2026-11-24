# 0009 — Solana holder and cluster thresholds are explicit heuristics

- **Status:** Accepted
- **Date:** 2026-11-24
- **Context:** Solana rug tools publish different concentration bands and cluster definitions.
  A single opaque "rug score" is not explainable. The user needs creator %, top-holder %, and a
  cluster chance, but those numbers must not be presented as calibrated ground truth.
- **Decision:** Use configurable, documented defaults:
  - Creator: 10% MEDIUM, 20% HIGH.
  - Largest retail holder: 10% MEDIUM, 20% HIGH.
  - Top-10 retail holders: 30% MEDIUM, 50% HIGH.
  - Funding cluster: at least 3 wallets sharing an earliest funder; 10% MEDIUM, 30% HIGH; a
    creator-linked 2-wallet group at ≥5% is MEDIUM.
  - Cluster probability heuristic:
    `min(0.95, 0.20 + 0.15 × (members − 1) + 0.60 × share + (0.10 if creator_linked))`;
    0.05 when no group exists.
  - Exclude burn addresses and off-curve/program-controlled accounts from retail circulating
    supply and concentrate on owners rather than token accounts.
  - Disclose that common funding is correlation, exchange-funded wallets can create false
    groups, the signature window is bounded, and the probability is not statistical.
- **Consequences:**
  - Findings are explainable and thresholds can be tuned for a deployment.
  - The tool avoids an unexplainable 0–100 dev score.
  - Solana assessments may trend to MODERATE for early tokens with concentrated supply; this is
    intentional and visible.
  - Any future calibration must be based on executed, family-deduplicated benchmarks, not
    intuition.
