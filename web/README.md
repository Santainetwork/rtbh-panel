# RTBH Dashboard

Local-only React, Vite, TypeScript, and shadcn/ui dashboard for the RTBH control plane.

## Safety model

- Mock API is the default. It never contacts a router or production service.
- Policy mutations run as dry-run first.
- Apply requires an explicit second confirmation.
- The UI configures dynamic listen ranges and allowed ASNs, never individual neighbors.
- The default route policy is displayed as `REJECT`.

## Run locally

```bash
pnpm install
pnpm dev
```

## Checks

```bash
pnpm test --run
pnpm lint
pnpm build
```

`pnpm lint` currently reports five non-failing warnings in CLI-generated shadcn sources: four `react/only-export-components` warnings and one `react/set-state-in-effect` warning in `use-mobile.ts`. Application code is warning-free.

## Optional local API mode

The dashboard uses in-memory mock data unless explicitly configured:

```bash
VITE_API_MODE=http VITE_API_PROXY=http://127.0.0.1:8080 pnpm dev
```

`VITE_API_MODE=http` switches to same-origin `/api` calls. `VITE_API_PROXY` is read only by the Vite development server. Keep it loopback-only. No production endpoint is embedded.
