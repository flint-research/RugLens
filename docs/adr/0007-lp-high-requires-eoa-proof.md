# 0007 — Unlocked-LP HIGH requires EOA-majority proof

- **Status:** Accepted
- **Date:** 2026-11-24
- **Context:** The taxonomy describes HIGH liquidity risk as ">80% LP unlocked in EOA". An earlier
  implementation emitted HIGH whenever burned + recognized-locker supply was below 20%. That
  treats unrecognized lockers, custody contracts, and ordinary LP holders as if they were a
  malicious EOA, producing false positives on legitimate tokens.
- **Decision:** When unlocked LP exceeds the high threshold, run a bounded LP Transfer-log replay,
  identify the largest non-burn/non-locker holder, verify its current LP balance with
  `balanceOf`, and check its bytecode. HIGH is emitted only if the holder is an EOA (no code) and
  controls at least the high threshold of LP supply. Log truncation, RPC failure, missing holder
  data, or a contract holder downgrades the result to MEDIUM with explicit limitations. A 50–80%
  unlocked position remains MEDIUM without holder-type proof.
- **Consequences:**
  - HIGH LP findings are executable evidence, not a heuristic about unknown holders.
  - Blue-chip or locked-by-unknown-contract LP is less likely to produce a false HIGH.
  - The detector performs one bounded log replay and a balance/code check only on the high-risk
    path.
  - The MEDIUM finding still exposes material unlocked liquidity; it does not hide the risk.
