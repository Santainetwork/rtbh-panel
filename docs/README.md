# rtbh-panel integration guide

`github.com/arcelo/rtbh-panel` is a control-plane dashboard for remotely triggered blackholing (RTBH). This repository documentation describes the intended integration boundaries without requiring an implementation package API.

## Runtime contract

- Production BGP is a native, in-process listener on **TCP/179**. It is not a sidecar or a shell command.
- Dynamic passive neighbors require the peer to initiate the BGP session. The listener does not actively dial arbitrary neighbors.
- The dashboard shows aggregate peer/session state and policy status. It avoids per-neighbor configuration forms.
- RPC is reserved for policy synchronization. It is not a general BGP control or dashboard API.
- The safe default is **reject**: an unrecognized neighbor, invalid policy, or failed authorization produces no route advertisement.
- BGP listen ranges are allowlisted. An empty or malformed range is rejected during configuration validation.
- Allowed ASN is optional. When configured, the peer ASN must match. When unset, other allowlist checks still apply.
- `max_sessions` is mandatory operational capacity protection. New sessions are rejected after the limit.
- `dry_run` defaults to **true**. Production activation requires an explicit `dry_run: false` decision.

## Quick start

1. Copy `examples/config.yaml` and replace placeholders.
2. Keep `dry_run: true` while validating policy synchronization and peer behavior.
3. Restrict `listen_ranges` to loopback or approved management networks during testing.
4. Run the contract harness:

```sh
go test -tags integration ./integration
```

The harness uses loopback TCP and an in-memory dashboard adapter only. It never contacts an external service or router.

## Configuration

See [`../examples/config.yaml`](../examples/config.yaml). The example intentionally binds BGP to `127.0.0.1:179` for local validation and documents the privileged port requirement. Do not expose TCP/179 broadly without an allowlist and host firewall policy.

## Deployment examples

[`../examples/Dockerfile`](../examples/Dockerfile) and [`../examples/rtbh-panel.service`](../examples/rtbh-panel.service) are reference artifacts only. They are not deployment scripts and are not executed by the integration tests.

## Protocol

See [`policy-sync.md`](policy-sync.md) for the RPC policy-sync contract, framing, idempotency, dry-run behavior, and failure handling.

## Security model

See [`threat-model.md`](threat-model.md) for STRIDE analysis, trust boundaries, mitigations, and operational checks.

## Scope

Implemented packages live under `internal/bgpengine`, `internal/policystore`, `internal/agentrpc`, and `internal/dashboard`. These examples perform no deployment actions.
