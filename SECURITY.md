# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.2.x | Yes |
| 0.1.x | No (superseded by the Solana-capable schema) |

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Use GitHub's private vulnerability
reporting / security advisory flow for the repository:

1. Go to the repository **Security** tab.
2. Choose **Report a vulnerability**.
3. Include affected version, component, reproduction steps, impact, and any suggested fix.

You should receive an acknowledgement within a few business days. There is no bug bounty
program at this time. We will coordinate disclosure and credit with you.

## In scope

- RPC parsing/decoding bugs, response-size bypasses, SSRF bypasses, and request smuggling.
- Detector crashes, hangs, resource exhaustion, or unsafe coverage inflation.
- False `LOW` outcomes under missing/failed data.
- Anvil/Slither subprocess leaks, command injection, path traversal, or timeout bypasses.
- Metadata sanitization bypasses (ANSI/control/HTML injection).
- Plugin loader boundary violations (coverage claim or duplicate ID bypass).
- Report persistence or API contract violations.

## Out of scope

- The accuracy of a particular third-party RPC endpoint or public chain state.
- Economic losses caused by relying on a heuristic risk label without independent verification.
- Findings that require wallet keys, live approvals, or attacks on unrelated systems.
- Issues in optional third-party tools (Foundry, Slither, RPC providers) that are not reachable
  through RugLens' documented boundary. Report those upstream as well.
- Do not test against live third-party infrastructure you do not own. Use local forks and test
  networks.

## Design assumptions and safeguards

- RugLens **never** asks for wallet connections, private keys, seed phrases, signatures, or
  transaction approvals. It does not broadcast transactions.
- Simulation runs on local, ephemeral Anvil forks. Forks are semaphore-limited (default 2),
  deadline-bound, and terminated in `finally`.
- Custom RPC URLs are disabled in API mode by default. When enabled, schemes, credentials,
  fragments, DNS results, and private/loopback/link-local/CGNAT ranges are checked. DNS rebinding
  remains a residual risk; defense-in-depth should pin egress with network policy.
- RPC bodies are streamed with a 5 MB cap; bytecode is capped at 50 KB; requests have separate
  connect and total timeouts. HTTP redirects are disabled at the RPC transport.
- Token metadata is untrusted and sanitized (ANSI/control characters, angle brackets, length).
- Slither is optional, external, AGPL-isolated, and invoked with a 15 s timeout, 5 MB output cap,
  2 MB source cap, path normalization, and best-effort process-tree termination.
- Solana reads are direct JSON-RPC only. The client caps response bodies, disables redirects,
  rate-limits requests, and separates connect/total timeouts. No Solana sell simulation or live
  transaction is performed.
- Solana holder analysis uses at most the 20 largest token accounts. Off-curve/program-controlled
  accounts are excluded from retail circulating supply but may include lockers, treasuries, or
  launchpad curves; this is disclosed. Cluster tracing uses a bounded signature window and common
  funding is correlational, not proof of common control. Exchange-funded wallets can create false
  correlations.
- Standard Solana JSON-RPC does not support historical account pinning. Reports record the
  observed slot, and `--block` is rejected for Solana rather than claiming a reproducible
  historical snapshot.
- Plugins are trusted local code. They cannot claim coverage, but can read the supplied context
  and emit findings. Do not point `RUGLENS_PLUGIN_DIR` at untrusted code.
- Persistence stores public on-chain evidence and assessment data only. The open-source core has
  no auth, tenant, billing, or telemetry state.

## Secure deployment checklist

1. Run the API behind TLS and an authenticated reverse proxy if exposed beyond localhost.
2. Leave `RUGLENS_API_ALLOW_CUSTOM_RPC=false` unless you require it and enforce egress policy.
3. Use a private/paid archive RPC for historical assessments; do not expose credentials in URLs
   committed to source control.
4. Run as a non-root user (the Docker image uses UID 10001), with a read-only source tree and a
   writable data volume only.
5. Keep `simulation_concurrency` and API concurrency low enough for available memory.
6. Keep dependencies patched; the `security` workflow runs `pip-audit`.
7. Treat reports as decision support, not financial advice. Verify high-value decisions with an
   independent audit and block-pinned reproduction.
