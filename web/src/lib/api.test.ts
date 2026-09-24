import { describe, expect, it } from "vitest"

import { createHttpApi, createMockApi } from "./api"

describe("mock dashboard API", () => {
  it("returns deterministic operational snapshot", async () => {
    const snapshot = await createMockApi().snapshot()

    expect(snapshot.config.defaultPolicy).toBe("reject")
    expect(snapshot.config.dryRun).toBe(true)
    expect(snapshot.peers.some((peer) => peer.state === "ESTABLISHED")).toBe(true)
    expect(snapshot.blocklist.length).toBeGreaterThan(0)
    expect(snapshot.whitelist.length).toBeGreaterThan(0)
  })

  it("previews without mutation and applies only explicitly", async () => {
    const api = createMockApi()
    const mutation = { list: "blocklist" as const, action: "add" as const, prefix: "203.0.113.77/32" }

    const preview = await api.mutate(mutation)
    expect(preview.dryRun).toBe(true)
    expect((await api.snapshot()).blocklist).not.toContain("203.0.113.77/32")

    const applied = await api.mutate({ ...mutation, apply: true })
    expect(applied.applied).toBe(true)
    expect((await api.snapshot()).blocklist).toContain("203.0.113.77/32")
  })
})

describe("HTTP dashboard API", () => {
  it("reports live source and backend apply mode", async () => {
    const fetcher = async (input: RequestInfo | URL) => {
      const path = String(input)
      if (path === "/api/config") return new Response(JSON.stringify({
        local_asn: 65000,
        router_id: "192.0.2.1",
        listen_ranges: ["127.0.0.0/24"],
        peer_group: "rtbh-dynamic",
        allowed_asns: [64513],
        max_sessions: 8,
        default_policy: "reject",
        dry_run: false,
      }))
      if (path === "/api/peers") return new Response("[]")
      return new Response(null, { status: 404 })
    }

    const snapshot = await createHttpApi(fetcher as typeof fetch).snapshot()

    expect(snapshot.source).toBe("http")
    expect(snapshot.config.dryRun).toBe(false)
  })
})
