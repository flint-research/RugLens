# 0005 — Stream and cap RPC responses

- **Status:** Accepted
- **Date:** 2026-11-24
- **Context:** A compromised or malicious RPC can return oversized JSON or hex blobs to trigger
  memory exhaustion. Web3's stock HTTP provider buffers the full response before parsing.
- **Decision:** Subclass AsyncWeb3's HTTP provider. Use a bounded aiohttp session, reject
  declared `Content-Length` above the cap, read chunks, and abort as soon as the received body
  exceeds `rpc_max_response_bytes` (default 5 MB). Keep a secondary post-decode size check and a
  50 KB bytecode cap. Normalize transport failures, retry/failover at the `EvmClient` layer, and
  never retry a response-size violation.
- **Consequences:**
  - Oversized payloads cannot be fully buffered or parsed.
  - The provider remains a genuine AsyncWeb3 provider; JSON-RPC encoding/decoding stays native.
  - Anvil's local RPC client still uses web3's stock provider because it is loopback-only and
    short-lived.
  - Tests must verify the cap at the transport layer.
