# 0008 — Native Solana path with its own coverage profile

- **Status:** Accepted
- **Date:** 2026-11-24
- **Context:** Solana has SPL/Token-2022 mints, Base58 accounts, PDAs, Metaplex metadata,
  program-controlled token accounts, and a JSON-RPC API with no EVM bytecode or `eth_call`.
  Forcing it into the EVM `TokenContext`/simulation abstraction would either fail or hide
  important evidence. Solana also has no canonical V2-style swap call for a local sell
  simulation.
- **Decision:**
  - Use engine selector `101` for Solana mainnet (a RugLens convention; Solana has no EIP-155
    chain id).
  - Add separate `SolanaTokenContext`, `SolanaChainAdapter`, `BaseSolanaDetector`,
    `SolanaRpcClient`, and `SolanaAssessmentService`.
  - Keep `Finding`, `AssessmentReport`, coverage/consensus gates, storage, CLI/API/SDK shared.
  - Use a Solana coverage profile: authorities 0.30, holders 0.30, clusters 0.25, liquidity
    custody 0.15. No dynamic-trade weight is fabricated.
  - Implement Base58, PDA derivation, Ed25519 on-curve checks, mint/account parsing, and Metaplex
    decoding in Python so no Rust/Solana SDK is required.
  - Record the observed confirmed slot; reject `--block` because standard JSON-RPC cannot pin
    historical account state.
- **Consequences:**
  - Solana evidence is first-class rather than forced through EVM concepts.
  - A clean Solana token can reach LOW only if authority, holder, cluster, and custody detectors
    succeed. A failed cluster detector leaves coverage at 0.75 and therefore UNKNOWN.
  - V1 cannot claim honeypot simulation, exact pool depth, or LP lock status on Solana. Those
    gaps are explicit in findings/limitations and coverage, not hidden.
  - Future Solana venue adapters can be added behind the same service and report contract.
