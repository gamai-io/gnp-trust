[![CI](https://github.com/gamai-io/gnp-trust/actions/workflows/ci.yml/badge.svg)](https://github.com/gamai-io/gnp-trust/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

# gnp-trust

Minimal **GNP/1** trust plane for machine nodes: one node = one port = one token.

## Components

| File | Purpose |
|---|---|
| `gnp_node.py` | Node daemon: token-gated API, action tiers (`view`/`interact`/`admin`), leases with **fencing tokens**, secret deny-list, Ed25519-signed nonces, append-only JSONL audit |
| `gnp_mtls.py` | mTLS PKI helper: generates CA, node and client certs (localhost SANs, add IPs manually) |
| `gnp_hc_job.py` | Idempotent "human-compute" job runner: `task_id` de-dup, retries, before/after screenshot hashes as evidence |

## Why

Agents that act on real machines need more than a prompt: a gate that (a) checks *who* can act, (b) serializes conflicting actions with leases, (c) records tamper-evident evidence, and (d) refuses when uncertain (fail-closed). GNP/1 is that small layer — no framework, stdlib only.

## Quick start

```bash
python3 gnp_node.py --port 7140 --bind 127.0.0.1
# token: GNP_TOKEN or ~/.gnp/token
curl -s -H "X-Token: $GNP_TOKEN" http://127.0.0.1:7140/status

python3 gnp_mtls.py --dir ~/.gnp/pki        # CA + node/client certs
python3 -c "import gnp_hc_job"
```

## Guarantees

- Every request requires `X-Token` (loopback optionally exempt with `GNP_NODE_TRUST_LOOPBACK=1`).
- `input:` actions take a **lease** (holder + fencing token) before touching the machine.
- Secrets (`.env`, `.ssh`, keys, `api_keys.env`, …) are denied for read/write/exec.
- Children run with a sanitized environment and a hard timeout.
- Audit is append-only JSONL; evidence can be hash-chained.

## Configuration (env)

`GNP_NODE_BASE` (default `~/.gnp`), `GNP_NODE_PORT`, `GNP_NODE_BIND`, `GNP_HC_HOST`, `GNP_HC_PORT`,
`GNP_HARNESS_URL`, `GNP_JOBS_URL`, `GNP_FLEET_URL`, `GNP_TOKEN_FILE`, `GNP_JOBS_DB`, `GNP_EVIDENCE_MODULE`.

## Limitations

- Token auth is bearer-style; put it behind TLS or a private network.
- Lease store is SQLite (single node); distributed leases need an external store.
- `interact` allows only an allowlist of programs; anything else requires `admin`.

## License

Apache-2.0.
