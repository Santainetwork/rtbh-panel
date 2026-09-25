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

- BGP, HTTP, and sync listeners bind loopback only by default. Non-loopback listen without TLS requires explicit `--insecure-listen=true`.
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

### Text Feeds (Pastebin / URL / Local File)

You can sync blocklist and whitelist from plain text files or raw pastebin URLs (one IP/CIDR per line, `#` comments ignored):

```sh
./bin/rtbh-server \
  --blocklist-feed="https://pastebin.com/raw/xxxxxx" \
  --whitelist-feed="/etc/rtbh/whitelist.txt" \
  --feed-interval=10m \
  --whitelist-expand-slash24=true
```

* `--whitelist-expand-slash24=true` (or `--whitelist-expand-subnets=true`, default `true`): If an IPv4 subnet between `/16` and `/31` (such as `/19`, `/22`, `/23`, `/24`) is listed in the whitelist feed, it automatically expands into all individual `/32` host entries (e.g. 256 hosts for `/24`, 1,024 for `/22`, 8,192 for `/19`) into the whitelist.

### Web Dashboard Policy Management

You can add and remove blocklist and whitelist prefixes directly via the Web Dashboard:
1. Open the dashboard at `http://<IP>:8080`.
2. Scroll to **Policy inventory** (`Blocklist` or `Whitelist` tab).
3. Click **+ Add prefix** to input a CIDR (or **Remove** on an existing row).
4. Run preview (dry-run), check the confirmation checkbox, and click **Apply mutation**.
*Note: To allow permanent changes to be applied from the web interface, run `rtbh-server` with `--dry-run=false --policy-file=policy.json`.*

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
| GET | `/api/v1/config` | Runtime config, stats, and dry-run state |
| GET | `/api/v1/policies` | Server-side paginated & filtered policy search |
| POST | `/api/v1/policies/bulk-delete` | Bulk deletion of multiple prefixes in one atomic transaction |
| GET | `/api/v1/peers` | Established peer status |
| GET | `/api/v1/feeds` | List configured threat intelligence feed sources |
| POST | `/api/v1/feeds` | Add or update feed source with auto-sync interval |
| POST | `/api/v1/feeds/delete` | Delete feed source and automatically cascade-remove its IPs |
| POST | `/api/v1/feeds/sync` | Trigger instant on-demand sync of a specific feed |
| POST | `/api/v1/block` | Add/remove deny prefix (`apply` explicit) |
| POST | `/api/v1/whitelist` | Add/remove allow prefix (`apply` explicit) |

## Database Backends (SQL)

By default, `rtbh-server` runs with an embedded, zero-dependency pure-Go **SQLite** engine with Write-Ahead Logging (WAL) enabled, handling feeds with hundreds of thousands of IPs without high CPU or freezing.

You can also connect to external SQL databases via CLI flags or ENV:
* **SQLite:** `--db-driver=sqlite --db-dsn=policy.db` (Default)
* **PostgreSQL:** `--db-driver=postgres --db-dsn="postgres://user:pass@127.0.0.1:5432/rtbh?sslmode=disable"`
* **MySQL / MariaDB:** `--db-driver=mysql --db-dsn="user:pass@tcp(127.0.0.1:3306)/rtbh?parseTime=true"`

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
