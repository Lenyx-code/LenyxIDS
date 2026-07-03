import { useState, useEffect, useRef, useCallback } from "react"
import {
  Monitor, Cpu, MemoryStick, HardDrive, Network,
  Activity, AlertTriangle, ChevronRight, ChevronLeft,
  RefreshCw, X, FileText, Skull, ExternalLink, ShieldAlert
} from "lucide-react"
import { API } from "../services/api"
import { MonitoringAlerts } from "./MonitoringAlerts"
import { FileChangesTab } from "./FileAlertStab"
import { useSSEStore } from "../store/sseStore"

const HISTORY_MAX = 60
const REFRESH_MS  = 5000

const thresholds = (cfg, key) => cfg?.[key] ?? { warn: 70, critical: 85 }

const levelColor = (pct, cfg, key) => {
  const t = thresholds(cfg, key)
  if (pct >= t.critical) return { bar: "bg-red-500",    text: "text-red-400",    ring: "ring-red-500/40"    }
  if (pct >= t.warn)     return { bar: "bg-yellow-500", text: "text-yellow-400", ring: "ring-yellow-500/40" }
  return                        { bar: "bg-emerald-500", text: "text-emerald-400", ring: "ring-emerald-500/40" }
}

const fmt = (iso) => {
  if (!iso) return "—"
  return new Date(iso).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" })
}

const fmtAgo = (iso) => {
  if (!iso) return "jamais"
  const s = Math.floor((Date.now() - new Date(iso)) / 1000)
  if (s < 60)   return `il y a ${s}s`
  if (s < 3600) return `il y a ${Math.floor(s / 60)}m`
  return `il y a ${Math.floor(s / 3600)}h`
}

// ── Sparkline ─────────────────────────────────────────────────────────────────

function Sparkline({ data, color = "#10b981", width = 120, height = 32 }) {
  if (!data || data.length < 2) return (
    <div style={{ width, height }} className="flex items-end">
      <div className="w-full h-px bg-slate-700/50" />
    </div>
  )
  const max  = 100
  const pts  = data.map((v, i) => {
    const x = (i / (data.length - 1)) * width
    const y = height - (v / max) * (height - 2) - 1
    return `${x},${y}`
  }).join(" ")
  const area = [
    `0,${height}`,
    ...data.map((v, i) => {
      const x = (i / (data.length - 1)) * width
      const y = height - (v / max) * (height - 2) - 1
      return `${x},${y}`
    }),
    `${width},${height}`,
  ].join(" ")
  return (
    <svg width={width} height={height} style={{ overflow: "visible" }}>
      <polygon points={area} fill={color} fillOpacity="0.12" />
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5"
        strokeLinecap="round" strokeLinejoin="round" />
      <circle
        cx={(data.length - 1) / (data.length - 1) * width}
        cy={height - (data[data.length - 1] / max) * (height - 2) - 1}
        r="2.5" fill={color}
      />
    </svg>
  )
}

// ── MetricBar ─────────────────────────────────────────────────────────────────

function MetricBar({ label, value, color, history, sparkColor }) {
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">{label}</span>
        <span className={`text-xs font-mono font-semibold ${color.text}`}>
          {value != null ? `${Number(value).toFixed(1)}%` : "—"}
        </span>
      </div>
      <div className="h-1 w-full bg-slate-700/40 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all duration-500 ${color.bar}`}
          style={{ width: `${Math.min(100, value ?? 0)}%` }} />
      </div>
      {history?.length > 1 && (
        <Sparkline data={history} color={sparkColor} width="100%" height={24} />
      )}
    </div>
  )
}

// ── Statut machine ────────────────────────────────────────────────────────────

function getHostStatus(host, cfg) {
  const cpuCrit = cfg?.cpu?.critical ?? 85
  const ramCrit = cfg?.ram?.critical ?? 85
  const cpuWarn = cfg?.cpu?.warn     ?? 70
  const ramWarn = cfg?.ram?.warn     ?? 70
  const hasOverloaded = (host.processes ?? []).some(p => p.overloaded)
  if (host.cpu_pct >= cpuCrit || host.ram_pct >= ramCrit) return "critical"
  if (hasOverloaded)                                        return "overloaded"
  if (host.cpu_pct >= cpuWarn || host.ram_pct >= ramWarn)  return "warn"
  return "ok"
}

// ── HostCard ──────────────────────────────────────────────────────────────────

function HostCard({ host, history, cfg, onClick, onViewAlerts }) {
  const cpu  = levelColor(host.cpu_pct,  cfg, "cpu")
  const ram  = levelColor(host.ram_pct,  cfg, "ram")
  const disk = levelColor(host.disk_pct, cfg, "disk")

  const status = getHostStatus(host, cfg)

  const statusDot = {
    ok:         "bg-emerald-400 shadow-emerald-400/60",
    warn:       "bg-yellow-400 shadow-yellow-400/60",
    overloaded: "bg-orange-400 shadow-orange-400/60 animate-pulse",
    critical:   "bg-red-400 shadow-red-400/60 animate-pulse",
  }[status]

  const statusLabel = {
    ok:         null,
    warn:       null,
    overloaded: { text: "Processus surchargé", cls: "text-orange-400 bg-orange-500/10 border-orange-500/30" },
    critical:   { text: "Critique",            cls: "text-red-400 bg-red-500/10 border-red-500/30"         },
  }[status]

  const osIcon = host.os === "Windows" ? "🪟" : host.os === "Darwin" ? "🍎" : "🐧"

  const topProc = (host.processes ?? [])
    .filter(p => p.cpu_pct > 0)
    .sort((a, b) => b.cpu_pct - a.cpu_pct)[0]

  return (
    <button onClick={onClick}
      className="flex flex-col gap-3 p-4 rounded-xl border border-slate-700/40 bg-slate-800/30
        hover:bg-slate-800/60 hover:border-slate-600/60 transition-all duration-200 text-left w-full">

      {/* En-tête */}
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-base leading-none">{osIcon}</span>
          <div className="min-w-0">
            <p className="text-xs font-mono font-semibold text-slate-200 truncate">{host.hostname}</p>
            <p className="text-[10px] font-mono text-cyan-500/70">
              {host.ip_main ?? "—"}
              <span className="text-slate-600 ml-1">· {fmtAgo(host.last_seen ?? host.timestamp)}</span>
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <div className={`w-2 h-2 rounded-full shadow-sm ${statusDot}`} />
          <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
        </div>
      </div>

      {/* Badge statut */}
      {statusLabel && (
        <div className={`flex items-center gap-1.5 px-2 py-1 rounded-lg border text-[10px] font-mono ${statusLabel.cls}`}>
          <span className="animate-pulse">⚠</span>
          {statusLabel.text}
          {status === "overloaded" && topProc && (
            <span className="ml-1 text-slate-500">— {topProc.name} {topProc.cpu_pct}%</span>
          )}
        </div>
      )}

      {/* Métriques */}
      <div className="flex flex-col gap-2">
        <MetricBar label="CPU"    value={host.cpu_pct}  color={cpu}  history={history?.cpu}  sparkColor="#3b82f6" />
        <MetricBar label="RAM"    value={host.ram_pct}  color={ram}  history={history?.ram}  sparkColor="#8b5cf6" />
        <MetricBar label="Disque" value={host.disk_pct} color={disk} history={history?.disk} sparkColor="#f59e0b" />
      </div>

      {/* Pied */}
      <div className="flex items-center justify-between text-[10px] font-mono text-slate-500">
        <span>{host.open_connections ?? 0} connexions · {host.process_count ?? "—"} processus</span>
        <button
          onClick={(e) => { e.stopPropagation(); onViewAlerts(host.hostname) }}
          className="flex items-center gap-1 px-2 py-0.5 rounded-md
            bg-slate-700/60 hover:bg-slate-600/60 text-slate-400 hover:text-slate-200
            border border-slate-600/40 transition-colors">
          <ExternalLink className="w-2.5 h-2.5" />
          alertes
        </button>
      </div>
    </button>
  )
}

// ── HostDetail ────────────────────────────────────────────────────────────────

function HostDetail({ host, history, cfg, onClose }) {
  const [tab, setTab] = useState("metrics")
  if (!host) return null

  const cpu  = levelColor(host.cpu_pct,  cfg, "cpu")
  const ram  = levelColor(host.ram_pct,  cfg, "ram")
  const disk = levelColor(host.disk_pct, cfg, "disk")

  const suspiciousProcs = (host.processes ?? []).filter(p => p.suspicious || p.unknown_root || p.overloaded)
  const normalProcs     = (host.processes ?? []).filter(p => !p.suspicious && !p.unknown_root && !p.overloaded)

  return (
    <div className="flex flex-col h-full overflow-hidden ml-5">
      <div className="flex items-center justify-between p-4 border-b border-slate-700/40 shrink-0">
        <div className="flex items-center gap-2">
          <Monitor className="w-4 h-4 text-slate-400" />
          <div>
            <p className="text-sm font-mono font-semibold text-slate-200">{host.hostname}</p>
            <p className="text-[10px] text-slate-500">
              {host.os} · {host.ip_main ?? "—"} · {host.os_version?.slice(0, 30)}
            </p>
          </div>
        </div>
        <button onClick={onClose}
          className="p-1.5 rounded-lg hover:bg-slate-700/50 text-slate-500 hover:text-slate-300 transition-colors">
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="flex gap-1 p-3 border-b border-slate-700/40 shrink-0">
        {[
          { id: "metrics",   label: "Métriques", icon: Activity },
          { id: "processes", label: "Processus", icon: Cpu, badge: suspiciousProcs.length || null },
          { id: "files",     label: "Fichiers",  icon: FileText },
        ].map(({ id, label, icon: Icon, badge }) => (
          <button key={id} onClick={() => setTab(id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-colors
              ${tab === id ? "bg-slate-700/60 text-slate-200" : "text-slate-500 hover:text-slate-300 hover:bg-slate-700/30"}`}>
            <Icon className="w-3 h-3" />
            {label}
            {badge ? (
              <span className="ml-1 px-1.5 py-0.5 rounded-full bg-red-500/20 text-red-400 text-[9px]">{badge}</span>
            ) : null}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto p-4">
        {tab === "metrics" && (
          <div className="flex flex-col gap-5">
            {[
              { label: "CPU",    key: "cpu",  value: host.cpu_pct,  color: cpu,  spark: "#3b82f6", icon: Cpu        },
              { label: "RAM",    key: "ram",  value: host.ram_pct,  color: ram,  spark: "#8b5cf6", icon: MemoryStick },
              { label: "Disque", key: "disk", value: host.disk_pct, color: disk, spark: "#f59e0b", icon: HardDrive  },
            ].map(({ label, key, value, color, spark, icon: Icon }) => (
              <div key={key} className="flex flex-col gap-2 p-3 rounded-xl bg-slate-800/40 border border-slate-700/30">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Icon className="w-3.5 h-3.5 text-slate-500" />
                    <span className="text-xs font-mono text-slate-400">{label}</span>
                  </div>
                  <span className={`text-lg font-mono font-semibold ${color.text}`}>
                    {value != null ? `${Number(value).toFixed(1)}%` : "—"}
                  </span>
                </div>
                <div className="h-1.5 w-full bg-slate-700/40 rounded-full overflow-hidden">
                  <div className={`h-full rounded-full transition-all duration-700 ${color.bar}`}
                    style={{ width: `${Math.min(100, value ?? 0)}%` }} />
                </div>
                {history?.[key]?.length > 1 && (
                  <div className="mt-1">
                    <Sparkline data={history[key]} color={spark} height={40} />
                    <div className="flex justify-between text-[9px] font-mono text-slate-600 mt-0.5">
                      <span>-{Math.round(history[key].length * REFRESH_MS / 60000)}min</span>
                      <span>maintenant</span>
                    </div>
                  </div>
                )}
              </div>
            ))}

            <div className="grid grid-cols-2 gap-3">
              {[
                { icon: Network,  label: "Connexions", val: host.open_connections ?? "—" },
                { icon: Activity, label: "Processus",  val: host.process_count    ?? "—" },
                { icon: Network,  label: "Envoyé",     val: host.net_sent_mb != null ? `${host.net_sent_mb} MB` : "—" },
                { icon: Network,  label: "Reçu",       val: host.net_recv_mb != null ? `${host.net_recv_mb} MB` : "—" },
              ].map(({ icon: Icon, label, val }) => (
                <div key={label} className="flex items-center gap-2 p-3 rounded-xl bg-slate-800/40 border border-slate-700/30">
                  <Icon className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                  <div>
                    <p className="text-[9px] font-mono text-slate-500 uppercase tracking-wider">{label}</p>
                    <p className="text-xs font-mono font-semibold text-slate-200">{val}</p>
                  </div>
                </div>
              ))}
            </div>

            {host.connections?.length > 0 && (
              <div className="flex flex-col gap-1.5">
                <p className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Connexions actives</p>
                <div className="rounded-xl border border-slate-700/30 overflow-hidden divide-y divide-slate-700/20">
                  {host.connections.slice(0, 8).map((c, i) => (
                    <div key={i} className="flex items-center justify-between px-3 py-1.5 text-[10px] font-mono">
                      <span className="text-slate-400 truncate">{c.laddr}</span>
                      <span className="text-slate-600 mx-2">→</span>
                      <span className="text-slate-300 truncate">{c.raddr || "—"}</span>
                      <span className={`ml-2 shrink-0 ${c.status === "ESTABLISHED" ? "text-emerald-400" : "text-slate-500"}`}>
                        {c.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {tab === "processes" && (
          <div className="flex flex-col gap-3">
            {suspiciousProcs.length > 0 && (
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center gap-2">
                  <Skull className="w-3.5 h-3.5 text-red-400" />
                  <span className="text-[10px] font-mono text-red-400 uppercase tracking-wider font-semibold">
                    Suspects / Surchargés ({suspiciousProcs.length})
                  </span>
                </div>
                {suspiciousProcs.map((p, i) => (
                  <ProcRow key={i} proc={p} suspect />
                ))}
              </div>
            )}
            <div className="flex flex-col gap-1">
              <p className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">
                Top processus ({normalProcs.length})
              </p>
              {normalProcs.slice(0, 30).map((p, i) => <ProcRow key={i} proc={p} />)}
            </div>
          </div>
        )}

        
        {tab === "files" && (
          <FileChangesTab hostname={host.hostname} />
        )}
      </div>
    </div>
  )
}

// ── ProcRow ───────────────────────────────────────────────────────────────────

function ProcRow({ proc, suspect = false }) {
  const [open, setOpen] = useState(false)
  const isOverloaded = proc.overloaded && !proc.suspicious

  return (
    <div className={`rounded-lg border overflow-hidden
      ${proc.suspicious || proc.unknown_root ? "border-red-500/30 bg-red-500/5"
        : isOverloaded ? "border-orange-500/30 bg-orange-500/5"
        : "border-slate-700/20 bg-slate-800/20"}`}>
      <button onClick={() => setOpen(o => !o)}
        className="flex items-center gap-3 w-full px-3 py-2 text-[11px] font-mono text-left">
        <span className={`font-semibold truncate flex-1
          ${proc.suspicious || proc.unknown_root ? "text-red-300"
            : isOverloaded ? "text-orange-300"
            : "text-slate-300"}`}>
          {proc.name}
        </span>
        <span className={`shrink-0 w-10 text-right ${proc.cpu_pct > 50 ? "text-orange-400" : "text-slate-500"}`}>
          {proc.cpu_pct}%
        </span>
        <span className="shrink-0 w-10 text-right text-slate-600">{proc.mem_pct?.toFixed(1)}%</span>
        <span className="shrink-0 text-slate-600 w-4 text-center">{open ? "▲" : "▼"}</span>
      </button>
      {open && (
        <div className="px-3 pb-2 border-t border-slate-700/20 flex flex-col gap-1 pt-1.5">
          <div className="flex gap-4 text-[10px] font-mono text-slate-500">
            <span>PID: <span className="text-slate-300">{proc.pid}</span></span>
            <span>User: <span className={proc.user === "root" || proc.user?.includes("SYSTEM") ? "text-red-400" : "text-slate-300"}>{proc.user}</span></span>
            <span>Status: <span className="text-slate-300">{proc.status}</span></span>
          </div>
          {proc.cmdline && (
            <p className="text-[10px] font-mono text-slate-500 break-all">
              <span className="text-slate-600">cmd: </span>{proc.cmdline.slice(0, 200)}
            </p>
          )}
          {suspect && (
            <div className="flex items-center gap-1.5 mt-0.5">
              <AlertTriangle className="w-3 h-3 text-red-400" />
              <span className="text-[10px] text-red-400">
                {proc.suspicious ? "Commande suspecte" : isOverloaded ? "CPU surchargé" : "Processus root inconnu"}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Monitoring (composant principal) ─────────────────────────────────────────

export function Monitoring() {
  const [selected,   setSelected]   = useState(null)
  const [loading,    setLoading]    = useState(true)
  const [cfgMap,     setCfgMap]     = useState({})
  const [globalCfg,  setGlobalCfg]  = useState({
    cpu:  { warn: 70, critical: 85 },
    ram:  { warn: 75, critical: 90 },
    disk: { warn: 80, critical: 95 },
  })
  const timerRef = useRef(null)

  const hosts       = useSSEStore((state) => state.hosts)
  const historyMap  = useSSEStore((state) => state.historyMap)
  const lastUpdate  = useSSEStore((state) => state.lastUpdate)
  const setHosts    = useSSEStore((state) => state.setHosts)

  // alertsHost : nom d'une machine précise, ou "__ALL__" pour la vue globale
  const [alertsHost, setAlertsHost] = useState(null)

  const getCfg = (hostname) => cfgMap[hostname] ?? globalCfg

  // Fetch REST : sert de filet de sécurité / chargement initial.
  // Le temps réel (SSE) est déjà branché globalement via Layout → initRealtime().
  const fetchHosts = useCallback(async () => {
    try {
      const r    = await API.getMonitoringHosts()
      const list = r.data?.hosts ?? []
      setHosts(list)
      setSelected(prev => {
        if (!prev) return null
        return list.find(h => (h.hostname ?? h._id) === (prev.hostname ?? prev._id)) ?? prev
      })
    } catch {}
    finally { setLoading(false) }
  }, [setHosts])

  useEffect(() => {
    fetchHosts()
    timerRef.current = setInterval(fetchHosts, REFRESH_MS)
    return () => clearInterval(timerRef.current)
  }, [fetchHosts])

  // ⚠️ Plus de useEffect avec `new EventSource(...)` ici : supprimé.
  // Cette connexion est désormais gérée une seule fois dans Layout via initRealtime().

  const onlineHosts   = hosts.length
  const criticalCount = hosts.filter(h => {
    const c = getCfg(h.hostname ?? h._id)
    return h.cpu_pct >= c.cpu.critical || h.ram_pct >= c.ram.critical
  }).length

  // ── Vue alertes (globale ou par machine) ──────────────────────────────────
  if (alertsHost) {
    const isGlobal = alertsHost === "__ALL__"
    return (
      <div className="flex flex-col h-full overflow-hidden gap-3">
        <div className="flex items-center gap-3 shrink-0">
          <button onClick={() => setAlertsHost(null)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700
              text-xs font-mono text-slate-400 hover:text-slate-200 hover:border-slate-600 transition-all">
            <ChevronLeft className="w-3.5 h-3.5" />
            Retour monitoring
          </button>
          <span className="text-xs font-mono text-slate-500">
            {isGlobal
              ? <span className="text-cyan-400 font-semibold">Toutes les machines</span>
              : <>Alertes de <span className="text-cyan-400 font-semibold">{alertsHost}</span></>
            }
          </span>
        </div>
        <MonitoringAlerts defaultHostname={isGlobal ? undefined : alertsHost} />
      </div>
    )
  }

  // ── Vue principale ────────────────────────────────────────────────────────
  return (
    <div className="flex h-full overflow-hidden gap-4">

      {/* Panneau gauche */}
      <div className={`flex flex-col gap-3 transition-all duration-300 ${selected ? "w-80 shrink-0" : "flex-1"}`}>

        {/* Header */}
        <div className="flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <Monitor className="w-4 h-4 text-slate-500" />
            <h1 className="text-sm font-mono font-semibold text-slate-200">Monitoring</h1>
            {criticalCount > 0 && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full
                bg-red-500/15 border border-red-500/30 text-red-400 animate-pulse">
                {criticalCount} critique{criticalCount > 1 ? "s" : ""}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {lastUpdate && (
              <span className="text-[10px] font-mono text-slate-600">{fmt(lastUpdate)}</span>
            )}
            <button
              onClick={() => setAlertsHost("__ALL__")}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700
                text-xs font-mono text-slate-400 hover:text-red-400 hover:border-red-500/30 transition-all"
              title="Voir toutes les alertes de monitoring"
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              Toutes les alertes
            </button>
            <button onClick={fetchHosts}
              className="p-1.5 rounded-lg hover:bg-slate-700/50 text-slate-500 hover:text-slate-300 transition-colors">
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            </button>
          </div>
        </div>

        {/* Résumé global */}
        {!selected && (
          <div className="grid grid-cols-3 gap-3 shrink-0">
            {[
              { label: "Machines",  val: onlineHosts,               color: "text-slate-300"  },
              { label: "Critiques", val: criticalCount,             color: criticalCount > 0 ? "text-red-400" : "text-slate-500" },
              { label: "Sains",     val: onlineHosts - criticalCount, color: "text-emerald-400" },
            ].map(({ label, val, color }) => (
              <div key={label} className="flex flex-col gap-0.5 p-3 rounded-xl bg-slate-800/40 border border-slate-700/30">
                <span className="text-[9px] font-mono text-slate-500 uppercase tracking-wider">{label}</span>
                <span className={`text-xl font-mono font-semibold ${color}`}>{val}</span>
              </div>
            ))}
          </div>
        )}

        {/* Grille des machines */}
        <div className={`flex-1 overflow-y-auto grid gap-3
          ${selected ? "grid-cols-1" : "grid-cols-1 md:grid-cols-2 xl:grid-cols-3"}`}>
          {loading ? (
            Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="h-48 rounded-xl bg-slate-800/40 animate-pulse" />
            ))
          ) : hosts.length === 0 ? (
            <div className="col-span-full flex flex-col items-center justify-center py-20 gap-3 text-slate-600">
              <Monitor className="w-8 h-8 opacity-30" />
              <div className="text-center">
                <p className="text-xs font-mono">Aucune machine connectée</p>
                <p className="text-[11px] mt-1 text-slate-700">
                  Lancez <code className="text-slate-500">agent.py</code> sur chaque machine à surveiller.
                </p>
              </div>
            </div>
          ) : (
            hosts.map((h) => {
  const key = h.hostname ?? h._id
  return (
    <div key={key} className="relative group">
      <HostCard
        host={h}
        history={historyMap[key]}
        cfg={getCfg(key)}
        onClick={() => setSelected(h)}
        onViewAlerts={setAlertsHost}
      />
      <button
        onClick={(e) => { 
          e.stopPropagation();
        }}
        className="absolute top-2 right-8 opacity-0 group-hover:opacity-100 transition-opacity
          text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-700/80 text-slate-400 hover:text-slate-200"
      >
        seuils
      </button>
    </div>
  )
})
          )}
        </div>
      </div>

      {/* Panneau droit — détail machine */}
      {selected && (
        <div className="flex-1 min-w-0 rounded-xl border border-slate-700/40 bg-slate-900/50 overflow-hidden">
          <HostDetail
            host={selected}
            history={historyMap[selected.hostname ?? selected._id]}
            cfg={getCfg(selected.hostname ?? selected._id)}
            onClose={() => setSelected(null)}
          />
        </div>
      )}
    </div>
  )
}