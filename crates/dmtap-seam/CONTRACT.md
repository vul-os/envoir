# The DMTAP Operator Seam — Contract

The seam is the boundary between the **open-source** DMTAP node/gateway and an **operator** that
hosts them. It exists so a commercial control-plane (e.g. `envoir-cloud`) can add billing,
quotas, and multi-tenant management **without forking the OSS or gating any protocol/privacy
feature**.

There are two ways to implement the contract:

1. **In-process (Rust traits)** — a self-host binary embeds `dmtap-seam` and uses the default
   impls (or its own). This is the `Metering`, `Provisioning`, `Policy`, `GatewayAuthz` traits.
2. **Out-of-process (HTTP + events)** — a hosted operator, possibly in another language,
   implements the same four capabilities behind an HTTP API. The OSS ships a thin adapter that
   turns trait calls into HTTP calls.

Both expose the **same four capabilities** and obey the **same invariants**.

## Invariants (MUST)

- **Privacy/crypto are never gated.** No seam call can disable encryption, weaken the mixnet,
  reduce metadata privacy, or deny a user access to their own keys/mailbox. The seam meters and
  limits *operations* (gateway egress, storage, relay bandwidth) and *organizational* concerns
  (accounts, quotas) only.
- **Self-host defaults are fully functional.** With no operator, the OSS runs unrestricted:
  `NullMetering` (no billing), `SelfHostProvisioning` (single owner), `UnlimitedPolicy` (no
  limits), `OpenGatewayAuthz` (you are your own gateway).
- **Fail-open to function, fail-safe on billing.** If the operator endpoint is unreachable, the
  OSS MUST NOT break user-facing mail/chat/files. Metering events queue locally and retry
  (usage may be under-counted during an outage — an accepted operator risk, documented, never a
  reason to drop a user's message). Policy/authz checks fall back to a **configured** default
  (an operator chooses `allow` for graceful degradation or `deny` for hard quota enforcement;
  the OSS default is `allow`).
- **Sealed sender preserved.** `GatewayAuthz` attributes accountability to an anonymous token /
  postage / account — never requires the sender's identity in clear (spec §6.2, §9).

## Capability 1 — Metering

The OSS emits usage events at cost centers. Out-of-process shape:

```
POST /v1/metering/events
{ "events": [
    { "account": "acct_123", "kind": "gateway_send", "amount": 1, "ts_ms": 1737000000000 },
    { "account": "acct_123", "kind": "storage_bytes", "amount": 5242880, "ts_ms": ... }
] }
→ 202 Accepted   (operator enqueues; OSS retries on non-2xx)
```

`kind` ∈ `gateway_send | inbound_legacy | storage_bytes | relay_bytes | messages_sent |
vanity_domain`. Events are idempotent by `(account, kind, ts_ms, amount)` best-effort; the
operator dedups.

## Capability 2 — Provisioning

```
POST /v1/provision
{ "ik": "<base64url identity key>", "desired_name": "alice", "tier": "gateway_domain" }
→ 200 { "provisioned": { "id": "acct_123", "address": "alice@gw.example",
                          "tier": "gateway_domain", "suspended": false } }
→ 200 { "unavailable": { "reason": "name taken" } }
→ 200 { "pending_domain_setup": { "account": {...},
          "instructions": "Approve DNS via Domain Connect at <url>" } }   // tier C

GET  /v1/account/{id}          → 200 Account | 404
POST /v1/account/{id}/suspend  → 204
POST /v1/account/{id}/resume   → 204
```

`tier` ∈ `key_only | gateway_domain | vanity_domain` (spec §3.8 A/B/C).

## Capability 3 — Policy / entitlements

```
POST /v1/policy/check
{ "account": "acct_123", "quota": { "storage_bytes": 6000000000 } }
→ 200 { "allow": true }
→ 200 { "allow_with_remaining": 1200000000 }
→ 200 { "deny": { "reason": "storage limit reached — upgrade plan" } }
```

`quota` is one of `storage_bytes | gateway_sends | domains | send_rate`. There is deliberately
**no** quota for any privacy/crypto capability.

## Capability 4 — Gateway authorization

```
POST /v1/gateway/authorize
{ "cred": { "account": "acct_123", "token": null, "postage": 0, "pow_bits": 0 } }
→ 200 { "allow": true }
→ 200 { "deny": { "reason": "monthly send cap reached" } }
```

For anonymous senders, `account` is null and accountability rides on `token` (ARC),
`postage`, or `pow_bits` (spec §9). The operator rate-limits/blocks per token without learning
identity.

## Versioning

The HTTP contract is versioned under `/v1`. Unknown fields are ignored (forward-compatible);
the OSS and operator negotiate capabilities via `GET /v1/capabilities`. The in-process trait
API is versioned by the `dmtap-seam` crate semver.
