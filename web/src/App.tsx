import { useEffect, useMemo, useState } from "react"
import {
  Activity,
  AlertTriangle,
  Blocks,
  Braces,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  CircleDot,
  Clock3,
  Download,
  FileClock,
  Fingerprint,
  Gauge,
  ListFilter,
  LockKeyhole,
  Network,
  Plus,
  RadioTower,
  RefreshCw,
  Route,
  ShieldCheck,
  ShieldX,
  TerminalSquare,
  Trash2,
} from "lucide-react"
import { toast } from "sonner"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarTrigger,
} from "@/components/ui/sidebar"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import { isCanonicalCIDR } from "@/lib/cidr"
import {
  dashboardApi,
  type DashboardApi,
  type DashboardSnapshot,
  type Mutation,
  type PolicyAction,
  type PolicyItem,
  type PolicyList,
  type SourceFeed,
} from "@/lib/api"

const nav = [
  { label: "Overview", href: "#overview", icon: Gauge },
  { label: "BGP sessions", href: "#sessions", icon: RadioTower },
  { label: "Sources", href: "#sources", icon: Download },
  { label: "Policies", href: "#policies", icon: ListFilter },
  { label: "Activity", href: "#activity", icon: FileClock },
]

function MetricCard({ label, value, detail, icon: Icon, tone = "normal" }: { label: string; value: string; detail: string; icon: typeof Gauge; tone?: "normal" | "safe" | "warning" }) {
  return (
    <Card className="metric-card">
      <CardHeader>
        <CardDescription className="eyebrow">{label}</CardDescription>
        <CardAction><span className={`icon-well ${tone}`}><Icon /></span></CardAction>
        <CardTitle className="metric-value">{value}</CardTitle>
      </CardHeader>
      <CardContent><p className="metric-detail">{detail}</p></CardContent>
    </Card>
  )
}

function PolicyTable({ entries, policyItems = [], list, api, totalCount, onMutate, onImportFeed, onBulkDelete, refreshTrigger }: {
  entries: string[]
  policyItems?: PolicyItem[]
  list: PolicyList
  api?: DashboardApi
  totalCount?: number
  onMutate: (list: PolicyList, action: PolicyAction, prefix?: string) => void
  onImportFeed: (list: PolicyList) => void
  onBulkDelete?: (list: PolicyList, prefixes: string[]) => Promise<void>
  refreshTrigger?: number
}) {
  const isBlock = list === "blocklist"
  const [search, setSearch] = useState("")
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [deleting, setDeleting] = useState(false)
  const [serverData, setServerData] = useState<{ items: PolicyItem[]; total: number; totalPages: number } | null>(null)

  useEffect(() => {
    const fetchFn = api?.getPolicies
    if (!fetchFn) return
    let active = true
    const fetchPage = async () => {
      try {
        const res = await fetchFn(list, page, pageSize, search)
        if (active) {
          setServerData({ items: res.items, total: res.total, totalPages: res.total_pages })
        }
      } catch {
        // fallback to memory
      }
    }
    fetchPage()
    return () => { active = false }
  }, [api, list, page, pageSize, search, refreshTrigger])

  const sourceMap = useMemo(() => {
    const map = new Map<string, string>()
    for (const item of policyItems) {
      if (item.list === list && item.source) {
        map.set(item.prefix, item.source)
      }
    }
    return map
  }, [policyItems, list])

  const filtered = useMemo(() => {
    if (serverData) return []
    if (!search.trim()) return entries
    const q = search.trim().toLowerCase()
    return entries.filter((p) => {
      const src = (sourceMap.get(p) || "manual").toLowerCase()
      return p.toLowerCase().includes(q) || src.includes(q)
    })
  }, [serverData, entries, search, sourceMap])

  const totalPages = serverData ? serverData.totalPages : Math.max(1, Math.ceil(filtered.length / pageSize))
  const currentPage = Math.min(page, totalPages)
  const effectiveTotal = serverData ? serverData.total : (totalCount ?? entries.length)

  const pageEntries = useMemo(() => {
    if (serverData) return serverData.items.map(it => it.prefix)
    const start = (currentPage - 1) * pageSize
    return filtered.slice(start, start + pageSize)
  }, [serverData, filtered, currentPage, pageSize])

  const allVisibleSelected = pageEntries.length > 0 && pageEntries.every((p) => selected.has(p))
  const toggleSelectAll = () => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (allVisibleSelected) {
        for (const p of pageEntries) next.delete(p)
      } else {
        for (const p of pageEntries) next.add(p)
      }
      return next
    })
  }

  const toggleSelect = (p: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(p)) next.delete(p)
      else next.add(p)
      return next
    })
  }

  const handleBulkDelete = async () => {
    if (selected.size === 0 || !onBulkDelete) return
    if (!confirm(`Are you sure you want to remove ${selected.size} prefixes from ${list}?`)) return
    setDeleting(true)
    try {
      const toDelete = Array.from(selected)
      await onBulkDelete(list, toDelete)
      setSelected(new Set())
      toast.success(`Removed ${toDelete.length} prefixes from ${list}`)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to bulk delete")
    } finally {
      setDeleting(false)
    }
  }

  return (
    <div className="policy-table-wrap">
      <div className="section-toolbar flex-wrap gap-3">
        <div>
          <p className="section-kicker">{effectiveTotal.toLocaleString()} total prefixes</p>
          <p className="section-note">{isBlock ? "Advertised with RTBH community after approval." : "Whitelist wins over every block decision."}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {selected.size > 0 && (
            <Button variant="destructive" size="sm" onClick={handleBulkDelete} disabled={deleting}>
              <Trash2 className="h-4 w-4" /> Delete Selected ({selected.size})
            </Button>
          )}
          <Button onClick={() => onImportFeed(list)} variant="outline" size="sm"><Download /> Import Feed</Button>
          <Button onClick={() => onMutate(list, "add")} size="sm"><Plus /> Add prefix</Button>
        </div>
      </div>

      <div className="flex items-center justify-between gap-3 my-3">
        <div className="relative flex-1 max-w-sm">
          <Input
            placeholder="Search prefix or source..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1) }}
            className="h-8 text-xs"
          />
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <span>Rows per page:</span>
          <Select value={pageSize.toString()} onValueChange={(v) => { setPageSize(parseInt(v, 10)); setPage(1) }}>
            <SelectTrigger className="h-7 w-[70px] text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="15">15</SelectItem>
              <SelectItem value="25">25</SelectItem>
              <SelectItem value="50">50</SelectItem>
              <SelectItem value="100">100</SelectItem>
              <SelectItem value="250">250</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[40px]">
              <Checkbox checked={allVisibleSelected} onCheckedChange={toggleSelectAll} aria-label="Select all on page" />
            </TableHead>
            <TableHead>Prefix</TableHead>
            <TableHead>Source</TableHead>
            <TableHead>Family</TableHead>
            <TableHead>Decision</TableHead>
            <TableHead className="text-right">Control</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {pageEntries.length === 0 ? (
            <TableRow>
              <TableCell colSpan={6} className="text-center text-muted-foreground py-6">
                No prefixes found.
              </TableCell>
            </TableRow>
          ) : (
            pageEntries.map((prefix) => {
              const it = serverData?.items.find(i => i.prefix === prefix)
              const src = it?.source || sourceMap.get(prefix) || "Manual"
              const isSelected = selected.has(prefix)
              return (
                <TableRow key={prefix} data-state={isSelected ? "selected" : undefined}>
                  <TableCell>
                    <Checkbox checked={isSelected} onCheckedChange={() => toggleSelect(prefix)} aria-label={`Select ${prefix}`} />
                  </TableCell>
                  <TableCell className="font-mono text-foreground font-medium">{prefix}</TableCell>
                  <TableCell>
                    <Badge variant={src === "Manual" ? "outline" : "secondary"} className="text-xs">
                      {src}
                    </Badge>
                  </TableCell>
                  <TableCell><Badge variant="outline">{prefix.includes(":") ? "IPv6" : "IPv4"}</Badge></TableCell>
                  <TableCell><Badge variant={isBlock ? "destructive" : "secondary"}>{isBlock ? "BLACKHOLE" : "ALLOW"}</Badge></TableCell>
                  <TableCell className="text-right">
                    <Button aria-label={`Remove ${prefix}`} onClick={() => onMutate(list, "remove", prefix)} variant="ghost" size="sm">Remove</Button>
                  </TableCell>
                </TableRow>
              )
            })
          )}
        </TableBody>
      </Table>

      <div className="flex items-center justify-between border-t pt-3 mt-2 text-xs text-muted-foreground">
        <div>
          Showing {pageEntries.length > 0 ? (currentPage - 1) * pageSize + 1 : 0} - {Math.min(currentPage * pageSize, effectiveTotal)} of {effectiveTotal.toLocaleString()} prefixes
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" disabled={currentPage <= 1} onClick={() => setPage(p => p - 1)}>
            <ChevronLeft className="h-3 w-3" /> Prev
          </Button>
          <span>Page {currentPage} of {totalPages}</span>
          <Button variant="outline" size="sm" disabled={currentPage >= totalPages} onClick={() => setPage(p => p + 1)}>
            Next <ChevronRight className="h-3 w-3" />
          </Button>
        </div>
      </div>
    </div>
  )
}

function MutationDialog({ open, initial, onOpenChange, onComplete, api, dryRun }: { open: boolean; initial: Omit<Mutation, "apply">; onOpenChange: (open: boolean) => void; onComplete: () => Promise<void>; api: DashboardApi; dryRun: boolean }) {
  const [list, setList] = useState<PolicyList>(initial.list)
  const [action, setAction] = useState<PolicyAction>(initial.action)
  const [prefix, setPrefix] = useState(initial.prefix)
  const [previewed, setPreviewed] = useState(false)
  const [confirmed, setConfirmed] = useState(false)
  const [busy, setBusy] = useState(false)
  const valid = isCanonicalCIDR(prefix)

  const preview = async () => {
    if (!valid) return
    setBusy(true)
    try {
      await api.mutate({ list, action, prefix: prefix.trim() })
      setPreviewed(true)
      toast.info("Dry-run complete", { description: "No policy state changed." })
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Dry-run failed")
    } finally { setBusy(false) }
  }

  const apply = async () => {
    if (!valid || !previewed || !confirmed) return
    setBusy(true)
    try {
      await api.mutate({ list, action, prefix: prefix.trim(), apply: true })
      await onComplete()
      onOpenChange(false)
      toast.success("Policy applied", { description: `${prefix.trim()} ${action === "add" ? "added to" : "removed from"} ${list}.` })
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Policy mutation failed")
    } finally { setBusy(false) }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <div className="dialog-symbol"><TerminalSquare /></div>
          <DialogTitle>Policy mutation</DialogTitle>
          <DialogDescription>Preview first. Applying requires a separate, explicit confirmation.</DialogDescription>
        </DialogHeader>
        <div className="dialog-grid">
          <div className="field-stack"><Label htmlFor="policy-list">Policy list</Label><Select value={list} onValueChange={(value) => { setList(value as PolicyList); setPreviewed(false) }}><SelectTrigger id="policy-list" className="w-full"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="blocklist">Blocklist</SelectItem><SelectItem value="whitelist">Whitelist</SelectItem></SelectContent></Select></div>
          <div className="field-stack"><Label htmlFor="policy-action">Action</Label><Select value={action} onValueChange={(value) => { setAction(value as PolicyAction); setPreviewed(false) }}><SelectTrigger id="policy-action" className="w-full"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="add">Add prefix</SelectItem><SelectItem value="remove">Remove prefix</SelectItem></SelectContent></Select></div>
          <div className="field-stack field-wide"><Label htmlFor="prefix">Canonical CIDR</Label><Input id="prefix" placeholder="203.0.113.77/32" value={prefix} aria-invalid={prefix.length > 0 && !valid} onChange={(event) => { setPrefix(event.target.value); setPreviewed(false); setConfirmed(false) }} /><p className={prefix && !valid ? "validation-error" : "field-help"}>{prefix && !valid ? "Enter a canonical IPv4 or IPv6 CIDR." : "Host bits must be zero for network prefixes."}</p></div>
        </div>
        {previewed && <Alert className="safety-alert"><ShieldCheck /><AlertTitle>Dry-run approved</AlertTitle><AlertDescription><strong>{action.toUpperCase()}</strong> {prefix} in {list}. This preview changed nothing.</AlertDescription></Alert>}
        {previewed && <label className="confirm-row"><Checkbox checked={confirmed} onCheckedChange={(value) => setConfirmed(value === true)} /><span>I reviewed this exact mutation and authorize apply.</span></label>}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          {!previewed ? <Button disabled={!valid || busy} onClick={preview}>Run dry-run</Button> : <Button variant="destructive" disabled={dryRun || !confirmed || busy} onClick={apply}>Apply mutation</Button>}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function ImportFeedDialog({ open, initialList, onOpenChange, onComplete, api, dryRun }: {
  open: boolean
  initialList: PolicyList
  onOpenChange: (open: boolean) => void
  onComplete: () => Promise<void>
  api: DashboardApi
  dryRun: boolean
}) {
  const [list, setList] = useState<PolicyList>(initialList)
  const [source, setSource] = useState("")
  const [expandSubnets, setExpandSubnets] = useState(true)
  const [previewed, setPreviewed] = useState(false)
  const [foundCount, setFoundCount] = useState<number | null>(null)
  const [confirmed, setConfirmed] = useState(false)
  const [busy, setBusy] = useState(false)

  const preview = async () => {
    if (!source.trim() || !api.importFeed) return
    setBusy(true)
    try {
      const res = await api.importFeed({ list, source: source.trim(), expandSubnets, apply: false })
      setFoundCount(res.count)
      setPreviewed(true)
      toast.info("Feed parsed successfully", { description: `Found ${res.count} valid prefixes.` })
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to fetch feed")
    } finally {
      setBusy(false)
    }
  }

  const apply = async () => {
    if (!source.trim() || !previewed || !confirmed || !api.importFeed) return
    setBusy(true)
    try {
      const res = await api.importFeed({ list, source: source.trim(), expandSubnets, apply: true })
      await onComplete()
      onOpenChange(false)
      toast.success("Feed imported", { description: `${res.count} prefixes applied to ${list}.` })
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Feed import failed")
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <div className="dialog-symbol"><Download /></div>
          <DialogTitle>Import External Feed / URL</DialogTitle>
          <DialogDescription>Download list of IPs/CIDRs from an external URL (e.g. Feodo Tracker, Pastebin) or local file.</DialogDescription>
        </DialogHeader>
        <div className="dialog-grid">
          <div className="field-stack"><Label htmlFor="feed-list">Target list</Label><Select value={list} onValueChange={(value) => { setList(value as PolicyList); setPreviewed(false) }}><SelectTrigger id="feed-list" className="w-full"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="blocklist">Blocklist</SelectItem><SelectItem value="whitelist">Whitelist</SelectItem></SelectContent></Select></div>
          <div className="field-stack field-wide"><Label htmlFor="feed-url">Feed URL or File Path</Label><Input id="feed-url" placeholder="https://feodotracker.abuse.ch/downloads/ipblocklist.txt" value={source} onChange={(e) => { setSource(e.target.value); setPreviewed(false); setConfirmed(false) }} /><p className="field-help">Accepts HTTP/HTTPS URL or local path. Ignores # comments and empty lines.</p></div>
          {list === "whitelist" && (
            <label className="confirm-row col-span-2"><Checkbox checked={expandSubnets} onCheckedChange={(v) => { setExpandSubnets(v === true); setPreviewed(false) }} /><span>Expand subnets (/16 to /31) into individual /32 host entries</span></label>
          )}
        </div>
        {previewed && foundCount !== null && (
          <Alert className="safety-alert"><ShieldCheck /><AlertTitle>Feed parsed: {foundCount} prefixes</AlertTitle><AlertDescription>Ready to import into {list}.</AlertDescription></Alert>
        )}
        {previewed && (
          <label className="confirm-row"><Checkbox checked={confirmed} onCheckedChange={(v) => setConfirmed(v === true)} /><span>I reviewed this feed source and authorize import into {list}.</span></label>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          {!previewed ? (
            <Button disabled={!source.trim() || busy} onClick={preview}>Preview feed</Button>
          ) : (
            <Button variant="destructive" disabled={dryRun || !confirmed || busy} onClick={apply}>Apply feed</Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function SourcesSection({ feeds, onAddFeed, onDeleteFeed, onSyncFeed }: {
  feeds: SourceFeed[]
  onAddFeed: (feed: SourceFeed) => Promise<void>
  onDeleteFeed: (id: string) => Promise<void>
  onSyncFeed: (id: string) => Promise<void>
}) {
  const [name, setName] = useState("")
  const [url, setUrl] = useState("")
  const [list, setList] = useState<PolicyList>("blocklist")
  const [interval, setInterval] = useState("3600")
  const [busy, setBusy] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim() || !url.trim()) return
    setBusy(true)
    try {
      await onAddFeed({
        id: "",
        name: name.trim(),
        url: url.trim(),
        list,
        interval: parseInt(interval, 10),
        enabled: true,
        prefix_count: 0,
        expand_subnets: true,
      })
      setName("")
      setUrl("")
      toast.success("Feed source added")
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to add source")
    } finally {
      setBusy(false)
    }
  }

  const formatInterval = (sec: number) => {
    if (sec <= 0) return "Manual"
    if (sec < 3600) return `${Math.round(sec / 60)}m`
    if (sec < 86400) return `${Math.round(sec / 3600)}h`
    return `${Math.round(sec / 86400)}d`
  }

  return (
    <section id="sources" className="content-grid">
      <Card className="span-two">
        <CardHeader>
          <CardTitle>Threat Intelligence & Sources</CardTitle>
          <CardDescription>Automated sources scheduled for periodic download into blocklist or whitelist.</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="mb-6 p-4 rounded-lg border bg-card/50 flex flex-wrap gap-3 items-end">
            <div className="flex-1 min-w-[160px]">
              <Label className="text-xs">Source Name</Label>
              <Input placeholder="e.g. Feodo Tracker" value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <div className="flex-[2] min-w-[240px]">
              <Label className="text-xs">Feed URL / Path</Label>
              <Input placeholder="https://feodotracker.abuse.ch/downloads/ipblocklist.txt" value={url} onChange={(e) => setUrl(e.target.value)} required />
            </div>
            <div className="w-[120px]">
              <Label className="text-xs">Target</Label>
              <Select value={list} onValueChange={(v) => setList(v as PolicyList)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="blocklist">Blocklist</SelectItem>
                  <SelectItem value="whitelist">Whitelist</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="w-[130px]">
              <Label className="text-xs">Auto Update</Label>
              <Select value={interval} onValueChange={setInterval}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="300">Every 5 mins</SelectItem>
                  <SelectItem value="900">Every 15 mins</SelectItem>
                  <SelectItem value="1800">Every 30 mins</SelectItem>
                  <SelectItem value="3600">Every 1 hour</SelectItem>
                  <SelectItem value="21600">Every 6 hours</SelectItem>
                  <SelectItem value="43200">Every 12 hours</SelectItem>
                  <SelectItem value="86400">Every 24 hours</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button type="submit" disabled={busy || !name.trim() || !url.trim()}><Plus /> Add Source</Button>
          </form>

          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Source</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>URL</TableHead>
                <TableHead>Interval</TableHead>
                <TableHead>Prefixes</TableHead>
                <TableHead>Last Sync</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {feeds.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground py-6">
                    No threat feeds configured yet.
                  </TableCell>
                </TableRow>
              ) : (
                feeds.map((f) => (
                  <TableRow key={f.id}>
                    <TableCell className="font-medium text-foreground">{f.name}</TableCell>
                    <TableCell>
                      <Badge variant={f.list === "blocklist" ? "destructive" : "secondary"}>
                        {f.list === "blocklist" ? "BLOCK" : "ALLOW"}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs max-w-[200px] truncate" title={f.url}>{f.url}</TableCell>
                    <TableCell><Badge variant="outline">{formatInterval(f.interval)}</Badge></TableCell>
                    <TableCell className="tabular-nums font-mono">{f.prefix_count} IPs</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{f.last_sync || "Never"}</TableCell>
                    <TableCell className="text-right space-x-1">
                      <Button aria-label={`Sync ${f.name}`} variant="ghost" size="sm" onClick={() => onSyncFeed(f.id)} title="Sync Now">
                        <RefreshCw className="h-4 w-4" />
                      </Button>
                      <Button aria-label={`Delete ${f.name}`} variant="ghost" size="sm" onClick={() => onDeleteFeed(f.id)} title="Delete">
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </section>
  )
}

function Dashboard({ snapshot, refresh, api }: { snapshot: DashboardSnapshot; refresh: () => Promise<void>; api: DashboardApi }) {
  const [dialogOpen, setDialogOpen] = useState(false)
  const [importDialogOpen, setImportDialogOpen] = useState(false)
  const [importList, setImportList] = useState<PolicyList>("blocklist")
  const [mutation, setMutation] = useState<Omit<Mutation, "apply">>({ list: "blocklist", action: "add", prefix: "" })
  const established = snapshot.peers.filter((peer) => peer.state === "ESTABLISHED").length
  const openMutation = (list: PolicyList, action: PolicyAction, prefix = "") => { setMutation({ list, action, prefix }); setDialogOpen(true) }
  const openImportFeed = (list: PolicyList) => { setImportList(list); setImportDialogOpen(true) }

  const handleAddFeed = async (f: SourceFeed) => {
    if (api.saveFeed) {
      await api.saveFeed(f)
      await refresh()
    }
  }

  const handleDeleteFeed = async (id: string) => {
    if (api.deleteFeed) {
      await api.deleteFeed(id)
      await refresh()
      toast.success("Feed source deleted")
    }
  }

  const handleSyncFeed = async (id: string) => {
    if (api.syncFeed) {
      try {
        toast.info("Syncing feed...")
        const res = await api.syncFeed(id)
        await refresh()
        toast.success("Feed synced", { description: `${res.count} prefixes loaded.` })
      } catch (err) {
        toast.error(err instanceof Error ? err.message : "Sync failed")
      }
    }
  }

  const handleBulkDelete = async (list: PolicyList, prefixes: string[]) => {
    if (api.bulkDelete) {
      await api.bulkDelete(list, prefixes)
    } else {
      for (const prefix of prefixes) {
        await api.mutate({ list, action: "remove", prefix, apply: true })
      }
    }
    await refresh()
  }

  return (
    <>
      <Sidebar collapsible="icon">
        <SidebarHeader className="brand-block">
          <div className="brand-mark"><Route /></div>
          <div className="brand-copy"><strong>NULLROUTE</strong><span>RTBH control plane</span></div>
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupLabel>Operations</SidebarGroupLabel>
            <SidebarGroupContent><SidebarMenu>{nav.map(({ label, href, icon: Icon }, index) => <SidebarMenuItem key={label}><SidebarMenuButton asChild isActive={index === 0} tooltip={label}><a href={href}><Icon /><span>{label}</span></a></SidebarMenuButton></SidebarMenuItem>)}</SidebarMenu></SidebarGroupContent>
          </SidebarGroup>
          <SidebarGroup>
            <SidebarGroupLabel>Guardrails</SidebarGroupLabel>
            <SidebarGroupContent className="guardrail-stack">
              <div><LockKeyhole /><span>Default reject</span></div>
              <div><Fingerprint /><span>ASN allowlist</span></div>
              <div><ShieldCheck /><span>Dry-run first</span></div>
            </SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>
        <SidebarFooter><div className="environment-chip"><CircleDot /><div><span>Environment</span><strong>{snapshot.source === "http" ? "LOCAL API" : "LOCAL MOCK"}</strong></div></div></SidebarFooter>
        <SidebarRail />
      </Sidebar>
      <SidebarInset>
        <header className="topbar"><SidebarTrigger /><Separator orientation="vertical" className="h-5" /><div className="breadcrumb"><span>Control plane</span><ChevronRight /><strong>Overview</strong></div><div className="topbar-actions"><Badge className="dry-run-badge" variant="outline"><AlertTriangle /> {snapshot.config.dryRun ? "DRY RUN" : "APPLY ENABLED"}</Badge><Button variant="outline" size="sm" onClick={refresh}><RefreshCw /> Refresh</Button></div></header>
        <main id="overview" className="dashboard-main">
          <section className="hero-row"><div><p className="eyebrow accent-text">NETWORK DEFENSE / LIVE POSTURE</p><h1>Routing control, without surprises.</h1><p>Observe dynamic BGP sessions. Stage prefix policy changes. Apply only after deliberate confirmation.</p></div><div className="system-pulse"><span></span><div><small>CONTROL PLANE</small><strong>Operational</strong></div></div></section>
          <Alert className="safety-banner"><ShieldCheck /><AlertTitle>{snapshot.config.dryRun ? "Safe operating mode" : "Apply mode enabled"}</AlertTitle><AlertDescription>All policy actions begin as dry-run. Routes remain unchanged until an operator confirms apply.</AlertDescription></Alert>
          <section className="metrics-grid">
            <MetricCard label="BGP sessions" value={`${established} / ${snapshot.config.maxSessions}`} detail="Established / session ceiling" icon={Network} tone="safe" />
            <MetricCard label="Local ASN" value={`AS${snapshot.config.localAsn}`} detail={`Router ID ${snapshot.config.routerId}`} icon={Braces} />
            <MetricCard label="Default policy" value="REJECT" detail="Unmatched routes are denied" icon={ShieldX} tone="warning" />
            <MetricCard label="Active policy" value={`${(snapshot.config.blocklistCount ?? snapshot.blocklist.length) + (snapshot.config.whitelistCount ?? snapshot.whitelist.length)}`} detail={`${(snapshot.config.blocklistCount ?? snapshot.blocklist.length).toLocaleString()} block · ${(snapshot.config.whitelistCount ?? snapshot.whitelist.length).toLocaleString()} allow`} icon={Blocks} />
          </section>
          <section id="sessions" className="content-grid">
            <Card className="span-two">
              <CardHeader><CardTitle>BGP peer status</CardTitle><CardDescription>Dynamic passive sessions from allowlisted ranges.</CardDescription><CardAction><Badge variant="secondary"><Activity /> {established} established</Badge></CardAction></CardHeader>
              <CardContent><Table><TableHeader><TableRow><TableHead>Peer address</TableHead><TableHead>Remote ASN</TableHead><TableHead>State</TableHead><TableHead>Uptime</TableHead><TableHead className="text-right">Prefixes</TableHead></TableRow></TableHeader><TableBody>{snapshot.peers.map((peer) => <TableRow key={peer.address}><TableCell className="font-mono text-foreground">{peer.address}</TableCell><TableCell>AS{peer.asn}</TableCell><TableCell><Badge className={peer.state === "ESTABLISHED" ? "state-up" : "state-wait"} variant="outline"><span className="status-dot" />{peer.state}</Badge></TableCell><TableCell>{peer.uptime}</TableCell><TableCell className="text-right tabular-nums">{peer.received}</TableCell></TableRow>)}</TableBody></Table></CardContent>
            </Card>
            <div className="config-stack">
              <Card><CardHeader><CardTitle>Dynamic listen ranges</CardTitle><CardDescription>Accepted TCP sources. Sessions are learned, not configured individually.</CardDescription></CardHeader><CardContent className="token-stack">{snapshot.config.listenRanges.map((range) => <div className="config-token" key={range}><RadioTower /><code>{range}</code></div>)}</CardContent></Card>
              <Card><CardHeader><CardTitle>Allowed remote ASN</CardTitle><CardDescription>Optional OPEN-stage admission policy.</CardDescription></CardHeader><CardContent className="asn-grid">{snapshot.config.allowedAsns.map((asn) => <Badge variant="outline" key={asn}>AS{asn}</Badge>)}</CardContent></Card>
            </div>
          </section>
          <SourcesSection feeds={snapshot.feeds ?? []} onAddFeed={handleAddFeed} onDeleteFeed={handleDeleteFeed} onSyncFeed={handleSyncFeed} />
          <section id="policies"><div className="section-heading"><div><p className="eyebrow">ROUTE DECISIONS</p><h2>Policy inventory</h2></div><Badge variant="outline"><LockKeyhole /> whitelist precedence</Badge></div><Card><CardContent className="pt-0"><Tabs defaultValue="blocklist"><TabsList variant="line"><TabsTrigger value="blocklist"><ShieldX /> Blocklist <Badge variant="secondary">{(snapshot.config.blocklistCount ?? snapshot.blocklist.length).toLocaleString()}</Badge></TabsTrigger><TabsTrigger value="whitelist"><ShieldCheck /> Whitelist <Badge variant="secondary">{(snapshot.config.whitelistCount ?? snapshot.whitelist.length).toLocaleString()}</Badge></TabsTrigger></TabsList><TabsContent value="blocklist"><PolicyTable entries={snapshot.blocklist} policyItems={snapshot.policies} list="blocklist" api={api} totalCount={snapshot.config.blocklistCount ?? snapshot.blocklist.length} onMutate={openMutation} onImportFeed={openImportFeed} onBulkDelete={handleBulkDelete} /></TabsContent><TabsContent value="whitelist"><PolicyTable entries={snapshot.whitelist} policyItems={snapshot.policies} list="whitelist" api={api} totalCount={snapshot.config.whitelistCount ?? snapshot.whitelist.length} onMutate={openMutation} onImportFeed={openImportFeed} onBulkDelete={handleBulkDelete} /></TabsContent></Tabs></CardContent></Card></section>
          <section id="activity"><div className="section-heading"><div><p className="eyebrow">IMMUTABLE TRAIL</p><h2>Recent activity</h2></div><Badge variant="secondary"><Clock3 /> newest first</Badge></div><Card><CardContent><div className="activity-list">{snapshot.audit.map((event) => <div className="activity-row" key={event.id}><div className={`activity-icon ${event.result}`} >{event.result === "allowed" ? <CheckCircle2 /> : <ShieldX />}</div><div className="activity-main"><strong>{event.action}</strong><code>{event.target}</code><span>by {event.actor}</span></div><div className="activity-meta"><Badge variant={event.mode === "DRY RUN" ? "outline" : "secondary"}>{event.mode}</Badge><time>{event.timestamp}</time></div></div>)}</div></CardContent></Card></section>
        </main>
      </SidebarInset>
      {dialogOpen && <MutationDialog open initial={mutation} onOpenChange={setDialogOpen} onComplete={refresh} api={api} dryRun={snapshot.config.dryRun} />}
      {importDialogOpen && <ImportFeedDialog open initialList={importList} onOpenChange={setImportDialogOpen} onComplete={refresh} api={api} dryRun={snapshot.config.dryRun} />}
    </>
  )
}

export default function App({ api = dashboardApi }: { api?: DashboardApi }) {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null)
  const [error, setError] = useState("")
  const refresh = useMemo(() => async () => {
    try { const next = await api.snapshot(); setError(""); setSnapshot(next) }
    catch (caught) { setError(caught instanceof Error ? caught.message : "Dashboard unavailable") }
  }, [api])
  useEffect(() => {
    let active = true
    api.snapshot().then(
      (next) => { if (active) setSnapshot(next) },
      (caught: unknown) => { if (active) setError(caught instanceof Error ? caught.message : "Dashboard unavailable") },
    )
    return () => { active = false }
  }, [api])

  if (error) return <main className="center-state"><Alert variant="destructive"><AlertTriangle /><AlertTitle>Dashboard unavailable</AlertTitle><AlertDescription>{error}</AlertDescription></Alert><Button onClick={refresh}>Retry</Button></main>
  if (!snapshot) return <main aria-label="Loading dashboard" className="loading-state"><Skeleton className="h-screen w-64" /><div><Skeleton className="h-16 w-2/3" /><div className="metrics-grid">{Array.from({ length: 4 }, (_, index) => <Skeleton className="h-36" key={index} />)}</div></div></main>
  return <TooltipProvider><SidebarProvider><Dashboard snapshot={snapshot} refresh={refresh} api={api} /><Toaster theme="dark" richColors /></SidebarProvider></TooltipProvider>
}
