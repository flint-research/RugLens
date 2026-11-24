# Solana Methodology

RugLens V1 supports Solana mainnet natively. Solana is **not** forced through the EVM bytecode
pipeline: it has its own account parser, RPC adapter, detectors, evidence profile, and metrics.
The shared layers are the categorical risk model, `Finding` schema, report contract, storage,
CLI/API/SDK, and persistence.

This document records the evidence rules, the public research they are based on, and the
limitations so the numbers are not mistaken for guarantees.

## 1. What the user provides

A Solana **mint address** (Base58, 32-byte public key) and an optional chain selector
(`--chain solana`). `ruglens assess <mint> --chain solana --rpc <URL>` runs the native profile.

The assessment records the observed confirmed **slot** in `block_number`. Standard Solana
JSON-RPC does not offer arbitrary historical account reads, so V1 rejects `--block` for Solana
instead of pretending a historical snapshot is reproducible.

## 2. Hydration

All reads are direct JSON-RPC, never a third-party security API:

1. `getSlot` — observation marker.
2. `getAccountInfo(mint, jsonParsed)` — SPL Token or Token-2022 mint; supply, decimals, mint
   authority, freeze authority, Token-2022 extensions.
3. Derive the Metaplex metadata PDA with seeds `["metadata", metadata_program, mint]` and read it
   with Base64 encoding. Parse Borsh strings, update authority, creators, and mutability.
   For Token-2022 mints without Metaplex metadata, use the `tokenMetadata` mint extension.
4. Infer creator:
   - first verified/highest-share Metaplex creator (excluding known programs), or
   - the fee payer of the earliest mint transaction **only if** the mint's signature window is
     smaller than the method limit. If the window is saturated, creator inference is skipped and
     disclosed rather than guessed.
5. `getTokenLargestAccounts` — up to 20 largest token accounts.
6. `getMultipleAccounts` — parse token-account owners and balances.
7. Classify each owner:
   - burn (incinerator/system address),
   - EOA-like wallet (on-curve, System-owned or missing system account),
   - SPL multisig (`parsed.type == "multisig"`),
   - executable program,
   - off-curve PDA/program-controlled account (pool vault, bonding curve, vesting vault, etc.).
8. `getTokenAccountsByOwner(creator, mint)` — all creator token accounts, not just top accounts.
9. Compute:
   - circulating = supply − burned − program-controlled custody,
   - creator share, top-1/top-10 retail owner shares (aggregate token accounts by owner),
   - program-controlled custody percentage.
10. For each of the top N retail wallets (default 8), bounded `getSignaturesForAddress` and
    `getTransaction(maxSupportedTransactionVersion: 1)`. The earliest transaction's native
    balance delta identifies a probable original funder.

## 3. Evidence rules and thresholds

All percentages are shares of **circulating supply** after burn and program-controlled custody,
unless stated otherwise. They are configurable.

### 3.1 Authorities and Token-2022

| Signal | Default severity | Rationale |
| --- | --- | --- |
| Mint authority active, single wallet | HIGH | Unlimited dilution capability |
| Mint authority active, multisig/program | MEDIUM | Capability remains, unilateral action reduced |
| Freeze authority active, single wallet | HIGH | Can freeze holders' accounts |
| Freeze authority active, multisig/program | MEDIUM | Capability remains, governance required |
| Metadata update authority, mutable, single wallet | MEDIUM | Can change name/symbol/URI |
| Metadata update authority, governed | LOW | Metadata can change under governance |
| Permanent delegate | HIGH | Can transfer/burn any holder's tokens |
| Default account state frozen | HIGH | New accounts cannot transfer until thawed |
| Non-transferable | HIGH | Normal sale is impossible |
| Transfer hook with a program | MEDIUM | Custom transfer rejection/restriction risk |
| Pausable | HIGH | Global transfer/mint pause capability |
| Mint close authority | MEDIUM | Privileged mint lifecycle capability |
| Transfer fee >10% / >25% / >50% | MEDIUM / HIGH / CRITICAL | Measured configured basis points |
| Confidential transfer | LOW | Holder/amount transparency loss |
| Unknown extension | limitation | Not silently treated as safe |

Authority accounts are classified by direct account reads, not only by address:
SPL Token multisig accounts are recognized from parsed multisig data; off-curve or executable
authorities are classified as program-controlled. USDC, for example, has 2-of-4 SPL multisig mint
and freeze authorities and a multisig metadata authority, so its capability findings are MEDIUM/
LOW rather than HIGH by construction.

### 3.2 Creator and holder concentration

Industry screening commonly treats creator/dev holdings >10% as a warning and >20% as danger,
single-holder >10%/>20%, and top-10 >30%/>50% as escalating alerts. RugLens defaults to:

| Condition | Severity |
| --- | --- |
| Creator ≥10% | MEDIUM |
| Creator ≥20% | HIGH |
| Largest retail holder ≥10% | MEDIUM |
| Largest retail holder ≥20% | HIGH |
| Top-10 retail holders ≥30% | MEDIUM |
| Top-10 retail holders ≥50% | HIGH |

Creator holdings are queried from all creator token accounts, so a creator with many small
accounts is not missed. Program-controlled accounts (PDAs, pool vaults, executable owners) and
burn addresses are excluded from retail concentration and from circulating supply. Top-10
aggregation is by wallet owner, not by token account.

### 3.3 Funding-linked clusters

Clustering follows the standard "common funding source" method used by wallet-cluster tools:
trace back each top-holder wallet to an early native SOL inflow and group wallets with the same
funder. V1 uses the earliest transaction in a bounded signature window.

- Campaign threshold: at least **3 wallets** sharing a funder.
- HIGH: cluster ≥3 wallets and ≥30% of circulating supply.
- MEDIUM: cluster ≥3 wallets and ≥10%, or a creator-linked pair with ≥5%, or any 2-wallet group
  with ≥30%.
- `cluster_probability` is a transparent heuristic:
  `min(0.95, 0.20 + 0.15 × (members − 1) + 0.60 × cluster_share + (0.10 if creator_linked))`,
  and `0.05` when no group exists.
- Funder accounts that are off-curve, executable, non-System-owned, burn, or known programs are
  excluded.
- Truncated signature windows and failed traces lower cluster coverage. If fewer than half of
  candidate wallets can be traced, the detector FAILS and data coverage drops.

This is correlation, not proof of common control. Exchange hot wallets, custodial withdrawal
wallets, and launchpad service wallets can fund many unrelated users; the finding text and
limitations state this explicitly.

### 3.4 Liquidity/custody

V1 does not parse every Solana AMM pool layout. Instead it detects **program-controlled token
custody** from the top-20 accounts:

- If ≥0.5% of supply is held by off-curve/program-controlled accounts, RugLens emits an INFO
  "program-controlled custody detected" finding and records `liquidity_custody_pct`. This is
  consistent with a DEX/launchpad pool but may also be a vesting/treasury program.
- If no such custody is visible, it emits MEDIUM `SOL-LIQUIDITY-UNVERIFIED-001`. The token may be
  pre-launch or using an undiscovered venue; the result is not labeled safe.
- `liquidity_depth_verified` and `lp_lock_verified` are always `false` in V1. RugLens does not
  claim to know exact SOL depth or whether LP tokens are burned/locked on Solana.
- The Solana coverage profile therefore gives liquidity only 0.15 weight and always records the
  depth limitation, unlike the EVM profile where simulation and LP balances are measured.

### 3.5 Solana coverage profile

| Area | Weight |
| --- | ---: |
| Authorities, Token-2022, metadata | 0.30 |
| Creator/top-holder concentration | 0.30 |
| Funding clusters | 0.25 |
| Liquidity custody | 0.15 |
| **Total** | **1.00** |

The same global gates apply: LOW requires coverage ≥0.80 and no CRITICAL/HIGH/MEDIUM findings;
coverage <0.65 cannot be LOW. A failed holder, authority, or cluster detector drops coverage
below 0.80; a failed cluster detector alone leaves coverage at 0.75, so a clean-but-unclustered
token resolves UNKNOWN rather than LOW.

## 4. What RugLens does not do on Solana (V1)

- No buy/sell or honeypot simulation. There is no canonical Uniswap-V2-style swap to call, and
  routing through arbitrary DEX programs would require a venue-specific executable adapter.
- No exact DEX pool discovery across Raydium/Orca/Meteora/PumpSwap variants.
- No LP burn/lock verification.
- No full holder census; only the largest 20 token accounts.
- No historical account pinning with standard JSON-RPC.
- No calibrated probability model. `cluster_probability` is an explainable heuristic.

These gaps are reflected in coverage and limitations. They are not filled with third-party API
data or fabricated evidence.

## 5. Research basis

The defaults are grounded in public Solana security guidance and measurements:

- SolanaTracker risk documentation: developer holdings >10%/>20%, holder concentration thresholds,
  freeze/mint authority and LP lock factors — <https://docs.solanatracker.io/data-api/risk>
- Birdeye rug-checker guidance: creator percentage, top-10 holder percentage, mutable metadata,
  mint/freeze authorities, Token-2022 — <https://data.birdeye.so/docs/use-cases/risk-and-integrity/rug-checker>
- SolanaTracker holder guide: common 30%/50% top-10 alert levels and single-holder >20% checks —
  <https://docs.solanatracker.io/guides/token-holders>
- RugCheck and public token-verification guidance: authority, holder, liquidity, insider signals —
  <https://rugcheck.xyz/> and <https://solana.com/docs/tokens/how-to-verify-a-token>
- Neodyme Token-2022 security pitfalls: permanent delegate, transfer hook, transfer fee, mint close
  authority — <https://neodyme.io/en/blog/token-2022/>
- Raydium Token-2022 integration caveats — <https://docs.raydium.io/solana-fundamentals/spl-token-and-token-2022>
- Funding-cluster methodology / campaign definition (≥3 wallets from one funder) —
  <https://github.com/karidasd/find-the-insiders>
- Bubblemaps cluster concepts (shared funding/transfer patterns) —
  <https://blog.bubblemaps.io/how-to-spot-a-rug-pull-using-bubblemaps-before-it-happens/>
- Solana rug-pull research including early-buyer/fast-wallet groups and liquidity manipulation —
  <https://arxiv.org/html/2608.20271v1> and <https://arxiv.org/html/2610.39458v1>

Thresholds are heuristics, not ground truth. Any benchmark claim must come from an executed,
family-deduplicated run over labeled data.
