# rtbh-panel

Local Go control plane for remotely triggered blackholing (RTBH). One `rtbh-server` binary runs an embedded GoBGP passive listener, persistent CIDR policy storage, bounded policy-sync streaming to remote agents, and the React dashboard plus JSON API.

## What it does

- Learns dynamic passive BGP neighbors from allowlisted listen ranges.
- Advertises effective blocklist prefixes with RFC 7999 blackhole community `65535:666`.
- Withdraws routes on policy removal, allowlist overlap, or prefix expiry.
- Whitelist prefixes are never advertised; an overlap suppresses the deny route.
- Dry-run is the default. Apply mode requires an explicit decision and a policy file.
- Serves the built dashboard and `/api/v1/*` (with legacy `/api/*` aliases) from one binary.
- Streams applied policy changes to remote agents over loopback policy-sync.

## Safety defaults

- BGP, HTTP, and sync listeners bind loopback only.
- BGP default port `4179`; dry-run defaults to `true`.
- Import and export policies default to reject.
- Apply is explicit and audited; no shell, BIRD, or FRR adapter.

## Build

```sh
make build
```

`make build` builds the frontend and produces `bin/rtbh-server` and `bin/rtbh-agent`.

## Run locally

```sh
./bin/rtbh-server \
  --bgp-listen=127.0.0.1:4179 \
  --http-listen=127.0.0.1:8080 \
  --sync-listen=127.0.0.1:17900 \
  --listen-ranges=127.0.0.0/24 \
  --allowed-asns=64513 \
  --dry-run=true
```

Open `http://127.0.0.1:8080`.

Apply mode (explicit):

```sh
./bin/rtbh-server \
  --bgp-listen=127.0.0.1:4179 \
  --http-listen=127.0.0.1:8080 \
  --sync-listen=127.0.0.1:17900 \
  --listen-ranges=127.0.0.0/24 \
  --allowed-asns=64513 \
  --policy-file=policy.json \
  --dry-run=false
```

## API

Versioned endpoints are the primary interface; legacy paths remain aliases.

| Method | Path | Purpose |
| ------ | ---- | ------- |
| GET | `/api/v1/config` | Runtime config and dry-run state |
| GET | `/api/v1/peers` | Established peer status |
| POST | `/api/v1/block` | Add/remove deny prefix (`apply` explicit) |
| POST | `/api/v1/whitelist` | Add/remove allow prefix (`apply` explicit) |

Blocklist add accepts optional future `expires_at` (RFC 3339).

## Tests

```sh
go test ./...
go test -tags=integration ./...
go test -race ./...
go vet ./...
make web-test
make web-build
```

Integration tests exercise real loopback GoBGP sessions and the route lifecycle without contacting external services or routers.

See [`docs/README.md`](docs/README.md), [`docs/policy-sync.md`](docs/policy-sync.md), and [`docs/threat-model.md`](docs/threat-model.md) for configuration, protocol, security, and packaging details.
