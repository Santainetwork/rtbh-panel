# STRIDE threat model

## Scope and trust boundaries

```text
Policy producer --authenticated policy-sync RPC--> rtbh-panel policy boundary
BGP peers --TCP/179, peer-initiated--> native in-process BGP listener
Dashboard users --authenticated UI--> read/status surface
rtbh-panel --> policy store and mock/live route adapter
```

The policy-sync RPC is the only control-plane RPC. The dashboard does not expose per-neighbor forms and cannot bypass policy validation. Production BGP is native and in-process on TCP/179. Dynamic passive neighbors require peer initiation.

## STRIDE analysis

| Threat | Asset / abuse | Mitigation | Residual check |
|---|---|---|---|
| Spoofing | Fake policy producer or BGP peer | Mutual auth for RPC; peer IP allowlist; optional allowed ASN; reject unknown identities | Rotate credentials; test unauthorized producer and ASN mismatch |
| Tampering | Altered policy or replayed generation | Length-framed authenticated transport; request IDs; monotonic generations; atomic replace | Audit duplicate, stale, and altered retries |
| Repudiation | Deny a policy decision or advertisement | Audit actor, request ID, generation, decision, reason, timestamp | Forward logs to protected storage |
| Information disclosure | Reveal policy, peer, or credentials | Least-privilege socket; no secrets in logs; TLS for TCP RPC; restricted dashboard data | Review permissions and log redaction |
| Denial of service | Exhaust sessions, memory, parser, or TCP/179 | `max_sessions`; allowlisted listen ranges; 1 MiB message cap; deadlines; bounded policy count; reject by default | Load test loopback harness and monitor resource limits |
| Elevation of privilege | Turn policy sync into BGP control or bind broad network | RPC operation allowlist; no arbitrary route/session methods; `CAP_NET_BIND_SERVICE` only; `NoNewPrivileges` | Review exported control surface and service unit |

## Safety invariants

- Safe default is reject. No invalid, unauthorized, stale, or partially applied policy advertises a route.
- `dry_run` defaults to true. Live mode requires explicit configuration and operational review.
- `listen_ranges` is an allowlist, not a denylist. Empty or malformed ranges fail closed.
- `allowed_asn` is optional, never an implicit wildcard override for other checks.
- `max_sessions` bounds accepted sessions. Dynamic passive mode never causes outbound dialing.
- Native BGP remains in-process and listens on TCP/179 in production. Packaging examples do not change that boundary.

## Verification cases

The self-contained contract harness in `../integration/` checks loopback-only peer initiation, allowlist rejection, optional ASN behavior, session capacity, dry-run default, policy-sync idempotency, and reject-on-invalid input. It uses a mock adapter and no not-yet-known project package APIs.
