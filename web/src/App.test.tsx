import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, it, vi } from "vitest"

import App from "./App"
import { createMockApi, type DashboardApi, type Mutation } from "./lib/api"
import { isCanonicalCIDR } from "./lib/cidr"

describe("RTBH dashboard", () => {
  it("renders BGP peers and dynamic admission controls without a neighbor form", async () => {
    render(<App api={createMockApi()} />)

    expect(await screen.findByRole("heading", { name: /routing control/i })).toBeInTheDocument()
    expect(screen.getAllByText("198.51.100.11").length).toBeGreaterThan(0)
    expect(screen.getByText("198.51.100.0/24")).toBeInTheDocument()
    expect(screen.getAllByText("AS64512").length).toBeGreaterThan(0)
    expect(screen.getAllByText("DRY RUN").length).toBeGreaterThan(0)
    expect(screen.getByText("LOCAL MOCK")).toBeInTheDocument()
    expect(screen.queryByLabelText(/neighbor address/i)).not.toBeInTheDocument()
  })

  it("shows live API and apply-enabled status from the snapshot", async () => {
    const backing = createMockApi()
    const snapshot = await backing.snapshot()
    const api: DashboardApi = {
      snapshot: async () => ({ ...snapshot, source: "http", config: { ...snapshot.config, dryRun: false } }),
      mutate: (mutation) => backing.mutate(mutation),
    }

    render(<App api={api} />)

    expect(await screen.findByText("LOCAL API")).toBeInTheDocument()
    expect(screen.getByText("APPLY ENABLED")).toBeInTheDocument()
    expect(screen.queryByText("LOCAL MOCK")).not.toBeInTheDocument()
  })

  it("keeps apply disabled when live backend remains in dry-run mode", async () => {
    const backing = createMockApi()
    const api: DashboardApi = { snapshot: () => backing.snapshot(), mutate: vi.fn((mutation) => backing.mutate(mutation)) }
    const user = userEvent.setup()
    render(<App api={api} />)

    await user.click(await screen.findByRole("button", { name: "Add prefix" }))
    await user.type(screen.getByLabelText("Canonical CIDR"), "203.0.113.80/32")
    await user.click(screen.getByRole("button", { name: "Run dry-run" }))
    await screen.findByText("Dry-run approved")
    await user.click(screen.getByText(/authorize apply/i))

    expect(screen.getByRole("button", { name: "Apply mutation" })).toBeDisabled()
    expect(api.mutate).toHaveBeenCalledTimes(1)
  })

  it("previews first and applies only after explicit confirmation", async () => {
    const backing = createMockApi()
    const mutate = vi.fn((mutation: Mutation) => backing.mutate(mutation))
    const api: DashboardApi = {
      snapshot: async () => {
        const snapshot = await backing.snapshot()
        return { ...snapshot, config: { ...snapshot.config, dryRun: false } }
      },
      mutate,
    }
    const user = userEvent.setup()
    render(<App api={api} />)

    expect((await screen.findAllByText("203.0.113.91/32")).length).toBeGreaterThan(0)
    await user.click(screen.getByRole("button", { name: "Add prefix" }))
    await user.type(screen.getByLabelText("Canonical CIDR"), "203.0.113.77/32")
    await user.click(screen.getByRole("button", { name: "Run dry-run" }))

    await screen.findByText("Dry-run approved")
    expect(mutate).toHaveBeenCalledWith({ list: "blocklist", action: "add", prefix: "203.0.113.77/32" })
    expect(screen.getByRole("button", { name: "Apply mutation" })).toBeDisabled()
    expect((await backing.snapshot()).blocklist).not.toContain("203.0.113.77/32")

    await user.click(screen.getByText(/authorize apply/i))
    await user.click(screen.getByRole("button", { name: "Apply mutation" }))

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    expect(mutate).toHaveBeenLastCalledWith({ list: "blocklist", action: "add", prefix: "203.0.113.77/32", apply: true })
    expect((await backing.snapshot()).blocklist).toContain("203.0.113.77/32")
  })
})

describe("canonical CIDR validation", () => {
  it.each([
    ["203.0.113.0/24", true],
    ["203.0.113.7/24", false],
    ["2001:db8::/32", true],
    ["2001:db8::1/32", false],
    ["2001:::1/64", false],
    ["not-a-prefix", false],
  ])("validates %s", (prefix, expected) => {
    expect(isCanonicalCIDR(prefix)).toBe(expected)
  })
})
