import { useEffect, useMemo, useState } from "react"
import {
  Activity,
  AlertTriangle,
  Blocks,
  Braces,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Clock3,
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
  type PolicyList,
} from "@/lib/api"

const nav = [
  { label: "Overview", href: "#overview", icon: Gauge },
  { label: "BGP sessions", href: "#sessions", icon: RadioTower },
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

function PolicyTable({ entries, list, onMutate }: { entries: string[]; list: PolicyList; onMutate: (list: PolicyList, action: PolicyAction, prefix?: string) => void }) {
  const isBlock = list === "blocklist"
  return (
    <div className="policy-table-wrap">
      <div className="section-toolbar">
        <div>
          <p className="section-kicker">{entries.length} active prefixes</p>
          <p className="section-note">{isBlock ? "Advertised with RTBH community after approval." : "Whitelist wins over every block decision."}</p>
        </div>
        <Button onClick={() => onMutate(list, "add")} size="sm"><Plus /> Add prefix</Button>
      </div>
      <Table>
        <TableHeader><TableRow><TableHead>Prefix</TableHead><TableHead>Family</TableHead><TableHead>Decision</TableHead><TableHead className="text-right">Control</TableHead></TableRow></TableHeader>
        <TableBody>
          {entries.map((prefix) => (
            <TableRow key={prefix}>
              <TableCell className="font-mono text-foreground">{prefix}</TableCell>
              <TableCell><Badge variant="outline">{prefix.includes(":") ? "IPv6" : "IPv4"}</Badge></TableCell>
              <TableCell><Badge variant={isBlock ? "destructive" : "secondary"}>{isBlock ? "BLACKHOLE" : "ALLOW"}</Badge></TableCell>
              <TableCell className="text-right"><Button aria-label={`Remove ${prefix}`} onClick={() => onMutate(list, "remove", prefix)} variant="ghost" size="sm">Remove</Button></TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

function MutationDialog({ open, initial, onOpenChange, onComplete, api }: { open: boolean; initial: Omit<Mutation, "apply">; onOpenChange: (open: boolean) => void; onComplete: () => Promise<void>; api: DashboardApi }) {
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
          {!previewed ? <Button disabled={!valid || busy} onClick={preview}>Run dry-run</Button> : <Button variant="destructive" disabled={!confirmed || busy} onClick={apply}>Apply mutation</Button>}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function Dashboard({ snapshot, refresh, api }: { snapshot: DashboardSnapshot; refresh: () => Promise<void>; api: DashboardApi }) {
  const [dialogOpen, setDialogOpen] = useState(false)
  const [mutation, setMutation] = useState<Omit<Mutation, "apply">>({ list: "blocklist", action: "add", prefix: "" })
  const established = snapshot.peers.filter((peer) => peer.state === "ESTABLISHED").length
  const openMutation = (list: PolicyList, action: PolicyAction, prefix = "") => { setMutation({ list, action, prefix }); setDialogOpen(true) }

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
        <SidebarFooter><div className="environment-chip"><CircleDot /><div><span>Environment</span><strong>LOCAL MOCK</strong></div></div></SidebarFooter>
        <SidebarRail />
      </Sidebar>
      <SidebarInset>
        <header className="topbar"><SidebarTrigger /><Separator orientation="vertical" className="h-5" /><div className="breadcrumb"><span>Control plane</span><ChevronRight /><strong>Overview</strong></div><div className="topbar-actions"><Badge className="dry-run-badge" variant="outline"><AlertTriangle /> DRY RUN</Badge><Button variant="outline" size="sm" onClick={refresh}><RefreshCw /> Refresh</Button></div></header>
        <main id="overview" className="dashboard-main">
          <section className="hero-row"><div><p className="eyebrow accent-text">NETWORK DEFENSE / LIVE POSTURE</p><h1>Routing control, without surprises.</h1><p>Observe dynamic BGP sessions. Stage prefix policy changes. Apply only after deliberate confirmation.</p></div><div className="system-pulse"><span></span><div><small>CONTROL PLANE</small><strong>Operational</strong></div></div></section>
          <Alert className="safety-banner"><ShieldCheck /><AlertTitle>Safe operating mode</AlertTitle><AlertDescription>All policy actions begin as dry-run. Routes remain unchanged until an operator confirms apply.</AlertDescription></Alert>
          <section className="metrics-grid">
            <MetricCard label="BGP sessions" value={`${established} / ${snapshot.config.maxSessions}`} detail="Established / session ceiling" icon={Network} tone="safe" />
            <MetricCard label="Local ASN" value={`AS${snapshot.config.localAsn}`} detail={`Router ID ${snapshot.config.routerId}`} icon={Braces} />
            <MetricCard label="Default policy" value="REJECT" detail="Unmatched routes are denied" icon={ShieldX} tone="warning" />
            <MetricCard label="Active policy" value={`${snapshot.blocklist.length + snapshot.whitelist.length}`} detail={`${snapshot.blocklist.length} block · ${snapshot.whitelist.length} allow`} icon={Blocks} />
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
          <section id="policies"><div className="section-heading"><div><p className="eyebrow">ROUTE DECISIONS</p><h2>Policy inventory</h2></div><Badge variant="outline"><LockKeyhole /> whitelist precedence</Badge></div><Card><CardContent className="pt-0"><Tabs defaultValue="blocklist"><TabsList variant="line"><TabsTrigger value="blocklist"><ShieldX /> Blocklist <Badge variant="secondary">{snapshot.blocklist.length}</Badge></TabsTrigger><TabsTrigger value="whitelist"><ShieldCheck /> Whitelist <Badge variant="secondary">{snapshot.whitelist.length}</Badge></TabsTrigger></TabsList><TabsContent value="blocklist"><PolicyTable entries={snapshot.blocklist} list="blocklist" onMutate={openMutation} /></TabsContent><TabsContent value="whitelist"><PolicyTable entries={snapshot.whitelist} list="whitelist" onMutate={openMutation} /></TabsContent></Tabs></CardContent></Card></section>
          <section id="activity"><div className="section-heading"><div><p className="eyebrow">IMMUTABLE TRAIL</p><h2>Recent activity</h2></div><Badge variant="secondary"><Clock3 /> newest first</Badge></div><Card><CardContent><div className="activity-list">{snapshot.audit.map((event) => <div className="activity-row" key={event.id}><div className={`activity-icon ${event.result}`} >{event.result === "allowed" ? <CheckCircle2 /> : <ShieldX />}</div><div className="activity-main"><strong>{event.action}</strong><code>{event.target}</code><span>by {event.actor}</span></div><div className="activity-meta"><Badge variant={event.mode === "DRY RUN" ? "outline" : "secondary"}>{event.mode}</Badge><time>{event.timestamp}</time></div></div>)}</div></CardContent></Card></section>
        </main>
      </SidebarInset>
      {dialogOpen && <MutationDialog open initial={mutation} onOpenChange={setDialogOpen} onComplete={refresh} api={api} />}
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
