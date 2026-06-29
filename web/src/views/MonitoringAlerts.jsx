import { useEffect, useState, useCallback } from "react"
import {
  ShieldAlert, Cpu, HardDrive, MemoryStick, Terminal,
  Network, FileText, RefreshCw, ChevronLeft, ChevronRight,
  Filter, X, Eye, CheckCircle, XCircle
} from "lucide-react"
import { API } from "../services/api"

// ── Config ────────────────────────────────────────────────────────

const ANOMALY_CFG = {
  CPU_SPIKE:             { icon: Cpu,         label: "CPU Spike",            color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30" },
  RAM_EXHAUSTION:        { icon: MemoryStick, label: "RAM Exhaustion",       color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/30" },
  DISK_FULL:             { icon: HardDrive,   label: "Disque plein",         color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30" },
  SUSPICIOUS_COMMAND:    { icon: Terminal,    label: "Commande suspecte",    color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30"    },
  UNEXPECTED_ROOT_PROC:  { icon: Terminal,    label: "Processus root",       color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30"    },
  PROCESS_OVERLOAD:      { icon: Cpu,         label: "Processus surchargé",  color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30" },
  FILE_CHANGE:           { icon: FileText,    label: "Modification fichier", color: "text-cyan-400",   bg: "bg-cyan-500/10",   border: "border-cyan-500/30"   },
  SUSPICIOUS_CONNECTION: { icon: Network,     label: "Connexion suspecte",   color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30"    },
}

const SEVERITY_CFG = {
  critical: { text: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30",    dot: "bg-red-500"    },
  high:     { text: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", dot: "bg-orange-500" },
  medium:   { text: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", dot: "bg-yellow-500" },
  low:      { text: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/30",   dot: "bg-blue-500"   },
}

const sev = (s) => SEVERITY_CFG[(s ?? "low").toLowerCase()] ?? SEVERITY_CFG.low

const fmt = (iso) => {
  if (!iso) return "—"
  return new Date(iso).toLocaleString("fr-FR", {
    day: "2-digit", month: "2-digit", year: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  })
}

const ANOMALY_TYPES = Object.keys(ANOMALY_CFG)
const SEVERITIES    = ["critical", "high", "medium", "low"]

const specificFields = {
  PROCESS_OVERLOAD:      ["process_name", "process_pid", "process_user", "process_cpu", "process_mem", "overload_cycles"],
  SUSPICIOUS_COMMAND:    ["process_name", "process_pid", "process_user", "process_cmd"],
  UNEXPECTED_ROOT_PROC:  ["process_name", "process_pid", "process_user", "process_cpu"],
  FILE_CHANGE:           ["file_path", "change_type", "old_size", "new_size"],
  SUSPICIOUS_CONNECTION: ["remote_addr", "local_addr", "conn_pid", "conn_status"],
}

const fieldLabels = {
  process_name: "Processus", process_pid: "PID", process_user: "Utilisateur",
  process_cpu: "CPU %", process_mem: "RAM %", process_cmd: "Commande",
  overload_cycles: "Cycles en surcharge", file_path: "Fichier",
  change_type: "Type de changement", old_size: "Ancienne taille", new_size: "Nouvelle taille",
  remote_addr: "Adresse distante", local_addr: "Adresse locale",
  conn_pid: "PID connexion", conn_status: "Statut",
}

// ── AlertDetail ───────────────────────────────────────────────────

function AlertDetail({ alert, onClose, onStatusChange }) {
  if (!alert) return null
  const cfg    = ANOMALY_CFG[alert.anomaly_type] ?? { icon: ShieldAlert, label: alert.anomaly_type, color: "text-slate-400" }
  const Icon   = cfg.icon
  const sc     = sev(alert.severity)
  const fields = specificFields[alert.anomaly_type] ?? []

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
      onClick={onClose}>
      <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-lg mx-4 shadow-2xl"
        onClick={e => e.stopPropagation()}>

        <div className="flex items-center justify-between p-5 border-b border-slate-700">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${cfg.bg ?? "bg-slate-700/50"}`}>
              <Icon className={`w-4 h-4 ${cfg.color}`} />
            </div>
            <div>
              <p className="text-sm font-mono font-semibold text-slate-200">{cfg.label}</p>
              <p className="text-[10px] font-mono text-slate-500">{fmt(alert.detection_time)}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${sc.bg} ${sc.border} ${sc.text}`}>
              {(alert.severity ?? "—").toUpperCase()}
            </span>
            <button onClick={onClose} className="p-1 rounded-lg hover:bg-slate-700/50 text-slate-500 transition-colors">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="p-5 flex flex-col gap-4">
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: "Hôte",   val: alert.agent_hostname ?? alert.ip_src ?? "—" },
              { label: "Statut", val: alert.status ?? "open" },
            ].map(({ label, val }) => (
              <div key={label} className="p-3 rounded-lg bg-slate-800 border border-slate-700">
                <p className="text-[9px] font-mono text-slate-500 uppercase tracking-wider mb-1">{label}</p>
                <p className="text-xs font-mono font-semibold text-slate-200">{val}</p>
              </div>
            ))}
          </div>

          {alert.detail && (
            <div className={`p-3 rounded-lg border ${cfg.bg ?? "bg-slate-800/40"} ${cfg.border ?? "border-slate-700"}`}>
              <p className="text-[9px] font-mono text-slate-500 uppercase tracking-wider mb-1">Détail</p>
              <p className="text-xs font-mono text-slate-300 break-words">{alert.detail}</p>
            </div>
          )}

          {fields.length > 0 && (
            <div className="rounded-lg border border-slate-700 divide-y divide-slate-700/50 overflow-hidden">
              {fields.filter(f => alert[f] != null).map(f => (
                <div key={f} className="flex items-center justify-between px-3 py-2">
                  <span className="text-[10px] font-mono text-slate-500">{fieldLabels[f] ?? f}</span>
                  <span className="text-[10px] font-mono text-slate-200 font-semibold max-w-xs truncate text-right">{String(alert[f])}</span>
                </div>
              ))}
            </div>
          )}

          {alert.integrity_hash && (
            <div className="p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
              <p className="text-[9px] font-mono text-emerald-500 uppercase tracking-wider mb-1">Hash intégrité</p>
              <p className="text-[10px] font-mono text-slate-500 break-all">{alert.integrity_hash}</p>
            </div>
          )}
        </div>

        <div className="flex gap-2 p-4 border-t border-slate-700">
          {alert.status === "open" && (
            <button onClick={() => onStatusChange(alert._id, "reviewed")}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono
                bg-emerald-600/20 border border-emerald-600/30 text-emerald-400 hover:bg-emerald-600/30 transition-colors">
              <CheckCircle className="w-3.5 h-3.5" /> Marquer analysé
            </button>
          )}
          {alert.status !== "closed" && (
            <button onClick={() => onStatusChange(alert._id, "closed")}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono
                bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-colors">
              <XCircle className="w-3.5 h-3.5" /> Fermer
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

// ── AlertRow ──────────────────────────────────────────────────────

function AlertRow({ alert, index, onView, onStatusChange }) {
  const cfg   = ANOMALY_CFG[alert.anomaly_type] ?? { icon: ShieldAlert, label: alert.anomaly_type ?? "—", color: "text-slate-400" }
  const Icon  = cfg.icon
  const sc    = sev(alert.severity)
  const rowBg = index % 2 !== 0 ? "bg-slate-800/20" : ""

  return (
    <div className={`grid grid-cols-12 gap-2 px-4 py-2.5 border-b border-slate-800
      text-xs font-mono hover:bg-slate-800/40 transition-all ${rowBg}`}>

      <div className="col-span-3 flex items-center gap-2">
        <Icon className={`w-3.5 h-3.5 shrink-0 ${cfg.color}`} />
        <span className="text-slate-300 truncate">{cfg.label}</span>
      </div>

      <div className="col-span-1 flex items-center">
        <span className={`flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded-full border ${sc.bg} ${sc.border} ${sc.text}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${sc.dot}`} />
          {(alert.severity ?? "—").toUpperCase()}
        </span>
      </div>

      <div className="col-span-2 flex items-center text-cyan-400 truncate">
        {alert.agent_hostname ?? alert.ip_src ?? "—"}
      </div>

      <div className="col-span-4 flex items-center text-slate-500 truncate" title={alert.detail}>
        {alert.detail ?? "—"}
      </div>

      <div className="col-span-1 flex items-center text-slate-600 text-[10px]">
        {fmt(alert.detection_time)}
      </div>

      <div className="col-span-1 flex items-center gap-1">
        <button onClick={() => onView(alert)}
          className="p-1 rounded border border-slate-700 text-slate-500 hover:text-blue-400 hover:border-blue-700 transition-all" title="Voir">
          <Eye className="w-3 h-3" />
        </button>
        {alert.status === "open" && (
          <button onClick={() => onStatusChange(alert._id, "reviewed")}
            className="p-1 rounded border border-slate-700 text-slate-500 hover:text-emerald-400 hover:border-emerald-700 transition-all" title="Analysé">
            <CheckCircle className="w-3 h-3" />
          </button>
        )}
        {alert.status !== "closed" && (
          <button onClick={() => onStatusChange(alert._id, "closed")}
            className="p-1 rounded border border-slate-700 text-slate-500 hover:text-red-400 hover:border-red-700 transition-all" title="Fermer">
            <XCircle className="w-3 h-3" />
          </button>
        )}
      </div>
    </div>
  )
}

// ── Vue principale ────────────────────────────────────────────────

export function MonitoringAlerts({ defaultHostname = null }) {
  const [selected,    setSelected]    = useState(null)
  const [showFilters, setShowFilters] = useState(false)

  // State local — pas de store dédié pour les alertes
  const [alerts,          setAlerts]          = useState([])
  const [alertsTotal,     setAlertsTotal]     = useState(0)
  const [alertsPage,      setAlertsPage]      = useState(1)
  const [alertsTotalPages,setAlertsTotalPages]= useState(1)
  const [alertsLoading,   setAlertsLoading]   = useState(true)
  const [filters, setFilters] = useState({
    anomaly_type: "",
    severity:     "",
    hostname:     defaultHostname ?? "",
  })

  const fetchAlerts = useCallback(async (overrides = {}) => {
    setAlertsLoading(true)
    const f = { ...filters, ...overrides }
    try {
      const r = await API.getMonitoringAlerts({
        page:  alertsPage,
        limit: 15,
        ...(f.anomaly_type && { anomaly_type: f.anomaly_type }),
        ...(f.severity     && { severity:     f.severity     }),
        ...(f.hostname     && { hostname:     f.hostname     }),
      })
      setAlerts(r.data.data        ?? [])
      setAlertsTotal(r.data.total       ?? 0)
      setAlertsTotalPages(r.data.total_pages ?? 1)
    } catch { setAlerts([]) }
    finally { setAlertsLoading(false) }
  }, [filters, alertsPage])

  // Re-fetch quand page ou filtres changent
  useEffect(() => { fetchAlerts() }, [fetchAlerts])

  // Forcer le filtre hostname si fourni en prop
  useEffect(() => {
    if (defaultHostname) {
      setFilters(f => ({ ...f, hostname: defaultHostname }))
      setAlertsPage(1)
    }
  }, [defaultHostname])

  const updateFilter = (patch) => {
    setFilters(f => ({ ...f, ...patch }))
    setAlertsPage(1)
  }

  const resetFilters = () => {
    setFilters({ anomaly_type: "", severity: "", hostname: defaultHostname ?? "" })
    setAlertsPage(1)
  }

  const handleStatusChange = async (id, status) => {
    try {
      await API.updateMonitoringAlertStatus(id, status)
      setSelected(null)
      fetchAlerts()
    } catch {}
  }

  const hasFilters = filters.anomaly_type || filters.severity || filters.hostname

  return (
    <>
      {selected && (
        <AlertDetail
          alert={selected}
          onClose={() => setSelected(null)}
          onStatusChange={handleStatusChange}
        />
      )}

      <div className="flex flex-col h-full overflow-hidden gap-3">

        {/* Header */}
        <div className="flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-orange-400" />
            <h2 className="text-sm font-mono font-semibold text-slate-200">Alertes système</h2>
            <span className="text-[10px] font-mono text-slate-500">
              {alertsTotal} alerte{alertsTotal > 1 ? "s" : ""}
            </span>
            {hasFilters && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-900/30 border border-blue-700/40 text-blue-400">
                Filtres actifs
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => setShowFilters(f => !f)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-slate-700
                text-[11px] font-mono text-slate-500 hover:text-slate-300 hover:border-slate-600 transition-all">
              <Filter className="w-3 h-3" />
              Filtres
            </button>
            <button onClick={() => fetchAlerts()}
              className="p-1.5 rounded-lg hover:bg-slate-700/50 text-slate-500 hover:text-slate-300 transition-colors">
              <RefreshCw className={`w-3.5 h-3.5 ${alertsLoading ? "animate-spin" : ""}`} />
            </button>
          </div>
        </div>

        {/* Filtres */}
        {showFilters && (
          <div className="flex flex-wrap gap-3 p-3 rounded-xl bg-slate-800/40 border border-slate-700/30 shrink-0">
            <div className="flex flex-col gap-1">
              <label className="text-[9px] font-mono text-slate-500 uppercase tracking-wider">Type</label>
              <select value={filters.anomaly_type} onChange={e => updateFilter({ anomaly_type: e.target.value })}
                className="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1.5 text-[11px] font-mono text-slate-300 outline-none">
                <option value="">Tous</option>
                {ANOMALY_TYPES.map(t => <option key={t} value={t}>{ANOMALY_CFG[t].label}</option>)}
              </select>
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-[9px] font-mono text-slate-500 uppercase tracking-wider">Sévérité</label>
              <select value={filters.severity} onChange={e => updateFilter({ severity: e.target.value })}
                className="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1.5 text-[11px] font-mono text-slate-300 outline-none">
                <option value="">Toutes</option>
                {SEVERITIES.map(s => <option key={s} value={s}>{s.toUpperCase()}</option>)}
              </select>
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-[9px] font-mono text-slate-500 uppercase tracking-wider">Hôte</label>
              <input value={filters.hostname} onChange={e => updateFilter({ hostname: e.target.value })}
                placeholder="nom ou IP..."
                className="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1.5 text-[11px] font-mono text-slate-300 placeholder-slate-600 outline-none w-40" />
            </div>
            {hasFilters && (
              <button onClick={resetFilters}
                className="self-end flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[11px] font-mono text-red-400 border border-red-500/30 hover:bg-red-500/10 transition-colors">
                Réinitialiser
              </button>
            )}
          </div>
        )}

        {/* Tableau */}
        <div className="flex-1 min-h-0 bg-slate-900 border border-slate-700/40 rounded-xl overflow-hidden flex flex-col">
          <div className="grid grid-cols-12 gap-2 px-4 py-2.5 border-b border-slate-700
            bg-slate-800/60 text-[9px] font-mono text-slate-500 uppercase tracking-widest shrink-0">
            <div className="col-span-3">Type</div>
            <div className="col-span-1">Sévérité</div>
            <div className="col-span-2">Hôte</div>
            <div className="col-span-4">Détail</div>
            <div className="col-span-1">Heure</div>
            <div className="col-span-1">Actions</div>
          </div>

          <div className="overflow-y-auto flex-1 min-h-0">
            {alertsLoading ? (
              <div className="flex items-center justify-center py-16">
                <RefreshCw className="w-4 h-4 text-slate-500 animate-spin" />
              </div>
            ) : alerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-20 gap-3 text-slate-600">
                <ShieldAlert className="w-8 h-8 opacity-20" />
                <p className="text-xs font-mono">Aucune alerte système</p>
              </div>
            ) : (
              alerts.map((a, i) => (
                <AlertRow
                  key={a._id ?? i}
                  alert={a}
                  index={i}
                  onView={setSelected}
                  onStatusChange={handleStatusChange}
                />
              ))
            )}
          </div>
        </div>

        {/* Pagination */}
        {alertsTotalPages > 1 && (
          <div className="flex items-center justify-between text-xs font-mono shrink-0">
            <span className="text-slate-500">
              Page <span className="text-slate-300">{alertsPage}</span> / {alertsTotalPages}
            </span>
            <div className="flex items-center gap-1.5">
              <button onClick={() => setAlertsPage(p => Math.max(1, p - 1))} disabled={alertsPage === 1}
                className="p-1.5 rounded-lg border border-slate-700 text-slate-400
                  hover:text-slate-200 disabled:opacity-30 disabled:cursor-not-allowed transition-all">
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              {Array.from({ length: Math.min(5, alertsTotalPages) }, (_, i) => {
                const p = Math.max(1, Math.min(alertsPage - 2, alertsTotalPages - 4)) + i
                return (
                  <button key={p} onClick={() => setAlertsPage(p)}
                    className={`w-7 h-7 rounded-lg border text-[11px] transition-all
                      ${p === alertsPage
                        ? "bg-slate-700 border-slate-600 text-slate-200 font-semibold"
                        : "border-slate-700 text-slate-500 hover:text-slate-300"}`}>
                    {p}
                  </button>
                )
              })}
              <button onClick={() => setAlertsPage(p => Math.min(alertsTotalPages, p + 1))} disabled={alertsPage === alertsTotalPages}
                className="p-1.5 rounded-lg border border-slate-700 text-slate-400
                  hover:text-slate-200 disabled:opacity-30 disabled:cursor-not-allowed transition-all">
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>
    </>
  )
}