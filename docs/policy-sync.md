# Policy-sync protocol

Status: proposed contract. This document defines the narrow RPC boundary between a policy producer and rtbh-panel. RPC carries policy synchronization only. It cannot start, stop, or reconfigure BGP sessions and cannot issue arbitrary route commands.

## Transport and framing

- Use a mutually authenticated local transport, preferably a Unix socket with owner/group permissions. A deployment using TCP must use TLS with client authentication.
- Each message is one UTF-8 JSON object prefixed by a 32-bit unsigned big-endian length, matching `internal/agentrpc`.
- Maximum encoded message size: 1 MiB. Receivers reject zero-length, oversized, truncated, or invalid JSON messages.
- Every policy has a monotonically increasing sequence. Retries reuse the same sequence and payload.

## Request

```json
{
  "type": "policy",
  "sequence": 42,
  "policy": {
    "id": "edge-a-blackhole",
    "idempotency_key": "request-42",
    "operation": "add",
    "list": "blocklist",
    "prefix": "203.0.113.0/24"
  }
}
```

`operation` is `add`, `remove`, `replace`, or `delete`. `list` is `blocklist` or `whitelist`. `sequence` is monotonically increasing per connection identity. A gap is rejected. Dashboard `dry_run` defaults to `true`; only applied mutations enter this stream.

## Response

```json
{
  "type": "ack",
  "cursor": 42
}
```

The ACK cursor is the highest contiguously applied sequence. Reconnect supplies the durable applied/peer cursors to `agentrpc.NewSession`. An already-applied sequence is ACKed again without redelivery.

## Processing rules

1. Authenticate the caller before parsing policy effects.
2. Validate every operation, target list, canonical prefix, sequence, and message size.
3. Evaluate safe defaults. Any validation, authorization, or adapter failure is reject/no advertisement.
4. Persist policy effects and the applied cursor atomically before sending ACK.
5. Record sequence, decision, reason, and actor identity in an audit log without storing secrets.
6. Bound unacknowledged messages using `MaxInFlight`; stop sending when the limit is reached.

## BGP boundary

The native in-process BGP listener owns TCP/179 and session lifecycle. Dynamic passive neighbors must initiate sessions. Policy-sync RPC only updates the validated desired policy set consumed by that listener. Dashboard actions display status and do not create per-neighbor forms or bypass this protocol.

## Failure and recovery

On restart, recover only the last committed cursor from the policy store. If recovery is incomplete, stay in reject mode. Do not advertise from uncommitted or stale state. A producer resumes after the peer ACK cursor and may replay unacknowledged sequences.
