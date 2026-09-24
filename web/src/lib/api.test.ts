import { describe, expect, it } from "vitest"

import { createMockApi } from "./api"

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
