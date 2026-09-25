export type PeerState = "ESTABLISHED" | "ACTIVE" | "IDLE"
export type PolicyList = "blocklist" | "whitelist"
export type PolicyAction = "add" | "remove"

export interface DashboardConfig {
  localAsn: number
  routerId: string
  listenRanges: string[]
  peerGroup: string
  allowedAsns: number[]
  maxSessions: number
  defaultPolicy: "reject"
  dryRun: boolean
}

export interface Peer {
  address: string
  asn: number
  state: PeerState
  uptime: string
  received: number
}

export interface AuditEntry {
  id: string
  timestamp: string
  actor: string
  action: string
  target: string
  mode: "DRY RUN" | "APPLIED"
  result: "allowed" | "rejected"
}

export interface DashboardSnapshot {
  source: "mock" | "http"
  config: DashboardConfig
  peers: Peer[]
  blocklist: string[]
  whitelist: string[]
  audit: AuditEntry[]
}

export interface Mutation {
  list: PolicyList
  action: PolicyAction
  prefix: string
  apply?: boolean
}

export interface MutationResult {
  applied: boolean
  dryRun: boolean
  mutation: Omit<Mutation, "apply">
}

export interface FeedImportRequest {
  list: PolicyList
  source: string
  expandSubnets?: boolean
  apply?: boolean
}

export interface FeedImportResult {
  applied: boolean
  dryRun: boolean
  count: number
  prefixes?: string[]
}

export interface DashboardApi {
  snapshot(): Promise<DashboardSnapshot>
  mutate(mutation: Mutation): Promise<MutationResult>
  importFeed?(req: FeedImportRequest): Promise<FeedImportResult>
}

const initialSnapshot: DashboardSnapshot = {
  source: "mock",
  config: {
    localAsn: 65000,
    routerId: "192.0.2.1",
    listenRanges: ["198.51.100.0/24", "2001:db8:100::/48"],
    peerGroup: "rtbh-dynamic",
    allowedAsns: [64512, 64513, 64514],
    maxSessions: 8,
    defaultPolicy: "reject",
    dryRun: true,
  },
  peers: [
    { address: "198.51.100.11", asn: 64512, state: "ESTABLISHED", uptime: "14d 08h", received: 0 },
    { address: "198.51.100.27", asn: 64513, state: "ESTABLISHED", uptime: "06d 21h", received: 0 },
    { address: "198.51.100.42", asn: 64514, state: "ACTIVE", uptime: "—", received: 0 },
  ],
  blocklist: ["203.0.113.91/32", "2001:db8:dead::/48"],
  whitelist: ["203.0.113.0/28", "2001:db8:cafe::/48"],
  audit: [
    { id: "evt-004", timestamp: "10:41:08 UTC", actor: "ops@noc", action: "add block", target: "203.0.113.91/32", mode: "DRY RUN", result: "allowed" },
    { id: "evt-003", timestamp: "10:36:42 UTC", actor: "policy-sync", action: "sync whitelist", target: "2 prefixes", mode: "APPLIED", result: "allowed" },
    { id: "evt-002", timestamp: "10:21:17 UTC", actor: "peer-guard", action: "admit ASN", target: "AS64514", mode: "APPLIED", result: "allowed" },
    { id: "evt-001", timestamp: "09:58:03 UTC", actor: "peer-guard", action: "admit ASN", target: "AS64496", mode: "APPLIED", result: "rejected" },
  ],
}

const clone = <T,>(value: T): T => structuredClone(value)

export function createMockApi(): DashboardApi {
  let state = clone(initialSnapshot)

  return {
    async snapshot() {
      return clone(state)
    },
    async mutate(request) {
      const mutation = { list: request.list, action: request.action, prefix: request.prefix }
      if (request.apply) {
        const entries = state[request.list]
        if (request.action === "add" && !entries.includes(request.prefix)) entries.unshift(request.prefix)
        if (request.action === "remove") state[request.list] = entries.filter((prefix) => prefix !== request.prefix)
        state.audit.unshift({
          id: `evt-${Date.now()}`,
          timestamp: "just now",
          actor: "local operator",
          action: `${request.action} ${request.list === "blocklist" ? "block" : "allow"}`,
          target: request.prefix,
          mode: "APPLIED",
          result: "allowed",
        })
      }
      return { applied: request.apply === true, dryRun: request.apply !== true, mutation }
    },
    async importFeed(req) {
      if (req.apply) {
        state.audit.unshift({
          id: `evt-${Date.now()}`,
          timestamp: "just now",
          actor: "local operator",
          action: `import ${req.list}`,
          target: req.source,
          mode: "APPLIED",
          result: "allowed",
        })
      }
      return { applied: req.apply === true, dryRun: req.apply !== true, count: 1 }
    },
  }
}

export function createHttpApi(fetcher: typeof fetch = fetch): DashboardApi {
  const request = async <T,>(path: string, init?: RequestInit): Promise<T> => {
    const response = await fetcher(path, {
      ...init,
      headers: { "Content-Type": "application/json", ...init?.headers },
    })
    if (!response.ok) throw new Error(`API request failed (${response.status})`)
    return response.json() as Promise<T>
  }

  return {
    async snapshot() {
      const [config, peers] = await Promise.all([
        request<{ local_asn: number; router_id: string; listen_ranges: string[]; peer_group: string; allowed_asns?: number[]; max_sessions: number; default_policy: "reject"; dry_run?: boolean; blocklist?: string[]; whitelist?: string[] }>("/api/v1/config"),
        request<Array<{ address: string; asn: number; state: PeerState }>>("/api/v1/peers"),
      ])
      return {
        source: "http",
        config: { localAsn: config.local_asn, routerId: config.router_id, listenRanges: config.listen_ranges, peerGroup: config.peer_group, allowedAsns: config.allowed_asns ?? [], maxSessions: config.max_sessions, defaultPolicy: config.default_policy, dryRun: config.dry_run !== false },
        peers: peers.map((peer) => ({ ...peer, uptime: "—", received: 0 })),
        blocklist: config.blocklist ?? [],
        whitelist: config.whitelist ?? [],
        audit: [],
      }
    },
    mutate(mutation) {
      const path = mutation.list === "blocklist" ? "/api/v1/block" : "/api/v1/whitelist"
      return request<MutationResult>(path, {
        method: "POST",
        body: JSON.stringify({ action: mutation.action, prefix: mutation.prefix, apply: mutation.apply === true }),
      })
    },
    importFeed(req) {
      return request<FeedImportResult>("/api/v1/feed", {
        method: "POST",
        body: JSON.stringify({
          list: req.list,
          source: req.source,
          expand_subnets: req.expandSubnets ?? true,
          apply: req.apply === true,
        }),
      })
    },
  }
}

export const dashboardApi = import.meta.env.PROD || import.meta.env.VITE_API_MODE === "http" ? createHttpApi() : createMockApi()
