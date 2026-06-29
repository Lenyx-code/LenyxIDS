import { useState, useEffect, useCallback, useRef } from "react"
import { API } from "../services/api"
import { useAlertStore } from "../store/sseStore"
import { Badge } from "../components/ui/Badge"
import { LiveIndicator } from "../components/ui/LiveIndicator"
import {
  ShieldAlert, Filter, ChevronLeft, ChevronRight,
  RefreshCw, X, Eye, CheckCircle, XCircle,
  ChevronDown, ChevronUp, Layers
} from "lucide-react"

const ATTACK_TYPES = ["ALL", "PORT_SCAN", "BRUTE_FORCE", "SYN_FLOOD", "OS_FINGERPRINTING", "ARP_SPOOFING"]
const SEVERITIES   = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]

const GROUP_OPTIONS = [
  { value: "",            label: "Aucun"        },
  { value: "ip_src",      label: "IP source"    },
  { value: "attack_type", label: "Type attaque" },
  { value: "severity",    label: "Sévérité"     },
  { value: "status",      label: "Statut"       },
]

function AlertDetailModal({ alert, onClose }) {
  if (!alert) return null

  const specificFields = {
    PORT_SCAN: [
      { label: "Ports scannés",    value: alert.ports_scanned?.join(", ") || "—" },
      { label: "Ports uniques",    value: alert.unique_ports },
      { label: "Durée",            value: alert.duration ? `${alert.duration}s` : "—" },
    ],
    BRUTE_FORCE: [
      { label: "Service ciblé",    value: alert.service },
      { label: "Port",             value: alert.port_dst },
      { label: "Tentatives",       value: alert.attempts },
    ],
    SYN_FLOOD: [
      { label: "Port ciblé",       value: alert.port_dst },
      { label: "Paquets SYN",      value: alert.syn_packets },
      { label: "Durée",            value: alert.duration ? `${alert.duration}s` : "—" },
    ],
    OS_FINGERPRINTING: [
      { label: "Port ciblé",       value: alert.port_dst },
      { label: "Paquets suspects", value: alert.packets_count },
      { label: "Types détectés",   value: alert.scan_types?.join(", ") || "—" },
      { label: "Durée",            value: alert.duration ? `${alert.duration}s` : "—" },
    ],
    ARP_SPOOFING: [
      { label: "IP usurpée",       value: alert.ip_spoofed },
      { label: "MAC légitime",     value: alert.mac_legitimate },
      { label: "MAC frauduleux",   value: alert.mac_fraudulent },
      { label: "Cible",            value: alert.target_ip },
    ],
  }[alert.attack_type] || []

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl w-full max-w-lg mx-4 shadow-xl"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-5 border-b border-slate-200 dark:border-slate-700">
          <div className="flex items-center gap-3">
            <ShieldAlert className="text-red-500 w-4 h-4" />
            <div>
              <h2 className="font-mono font-semibold text-slate-800 dark:text-slate-200 text-sm">
                {(alert.attack_type ?? "—").replace(/_/g, " ")}
              </h2>
              <p className="text-xs font-mono text-slate-400 mt-0.5">
                {new Date(alert.detection_time).toLocaleString("fr-FR")}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge severity={alert.severity} />
            <button onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 p-1 rounded transition-colors">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="p-5 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: "IP source",      value: alert.ip_src,  color: "text-red-500 dark:text-red-400" },
              { label: "IP destination", value: alert.ip_dst,  color: "text-slate-700 dark:text-slate-300" },
              { label: "Interface",      value: alert.iface,   color: "text-slate-500" },
              { label: "Statut",         value: <Badge severity={alert.status} />, color: "" },
            ].map(({ label, value, color }) => (
              <div key={label} className="bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg p-3">
                <p className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1">{label}</p>
                <p className={`text-xs font-mono font-semibold ${color}`}>{value}</p>
              </div>
            ))}
          </div>

          {specificFields.length > 0 && (
            <div>
              <p className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-2">Détails de l'attaque</p>
              <div className="bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg divide-y divide-slate-200 dark:divide-slate-700/50">
                {specificFields.map(({ label, value }) => (
                  <div key={label} className="flex items-center justify-between px-3 py-2">
                    <span className="text-xs font-mono text-slate-400">{label}</span>
                    <span className="text-xs font-mono text-slate-700 dark:text-slate-300 font-semibold max-w-xs truncate text-right">{value ?? "—"}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {alert.integrity_hash && (
            <div className="bg-emerald-50 dark:bg-emerald-900/10 border border-emerald-200 dark:border-emerald-800 rounded-lg p-3">
              <p className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 uppercase tracking-wider mb-1">Hash d'intégrité SHA-256</p>
              <p className="text-[10px] font-mono text-slate-500 break-all">{alert.integrity_hash}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export function Alerts() {
  const { alertConn, toasts } = useAlertStore()

  const [alerts,      setAlerts]      = useState([])
  const [loading,     setLoading]     = useState(false)
  const [selected,    setSelected]    = useState(null)
  const [showFilters, setShowFilters] = useState(true)

  const [attackType, setAttackType] = useState("ALL")
  const [severity,   setSeverity]   = useState("ALL")
  const [ipSrc,      setIpSrc]      = useState("")
  const [status,     setStatus]     = useState("")
  const [groupBy,    setGroupBy]    = useState("")

  const [page,       setPage]       = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [total,      setTotal]      = useState(0)

  const stateRef     = useRef({})
  const toastsLenRef = useRef(0)

  useEffect(() => {
    stateRef.current = { page, attackType, severity, ipSrc, status, groupBy }
  }, [page, attackType, severity, ipSrc, status, groupBy])

  const fetchAlerts = useCallback(async (overrides = {}) => {
    const f = { ...stateRef.current, ...overrides }
    setLoading(true)
    try {
      const params = {
        page:  f.page ?? 1,
        limit: 10,
        ...(f.attackType !== "ALL" && { attack_type: f.attackType }),
        ...(f.severity   !== "ALL" && { severity:    f.severity   }),
        ...(f.ipSrc                && { ip_src:       f.ipSrc     }),
        ...(f.status               && { status:       f.status    }),
        ...(f.groupBy              && { group_by:     f.groupBy   }),
        sort_by:    "detection_time",
        sort_order: -1,
      }
      const res = await API.getAlerts(params)
      setAlerts(res.data.data || [])
      setTotal(res.data.total || 0)
      setTotalPages(res.data.total_pages || 1)
    } catch (e) {
      console.error("fetchAlerts error:", e)
    } finally {
      setLoading(false)
    }
  }, [])
  useEffect(() => {
    fetchAlerts()
  }, [page, attackType, severity, ipSrc, status, groupBy])

  useEffect(() => {
    setPage(1)
  }, [attackType, severity, ipSrc, status, groupBy])

  useEffect(() => {
    if (toasts.length > toastsLenRef.current && page === 1) {
      fetchAlerts()
    }
    toastsLenRef.current = toasts.length
  }, [toasts.length])

  const updateStatus = async (alertId, newStatus) => {
    try {
      await API.updateAlertStatus(alertId, newStatus)
      fetchAlerts()
    } catch (_) {}
  }

  const resetFilters = () => {
    setAttackType("ALL")
    setSeverity("ALL")
    setIpSrc("")
    setStatus("")
    setGroupBy("")
    setPage(1)
  }

  const hasActiveFilters = attackType !== "ALL" || severity !== "ALL" || ipSrc || status || groupBy


  return (
    <>
      {selected && <AlertDetailModal alert={selected} onClose={() => setSelected(null)} />}

      <div className="flex flex-col h-full overflow-hidden gap-3">

        {/* Header */}
        <div className="flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <ShieldAlert className="text-red-500 w-4 h-4" />
            <h1 className="text-sm font-mono font-semibold text-slate-800 dark:text-slate-200">Alertes</h1>
            <LiveIndicator connected={alertConn} />
            {hasActiveFilters && (
              <span className="text-[10px] font-mono bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 border border-blue-200 dark:border-blue-800 px-2 py-0.5 rounded">
                Filtres actifs
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-400">{total} alerte{total > 1 ? "s" : ""}</span>
            <button
              onClick={() => setShowFilters(f => !f)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-mono text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 hover:border-slate-300 dark:hover:border-slate-600 transition-all"
            >
              <Filter className="w-3.5 h-3.5" />
              Filtres
              {showFilters ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </button>
            <button
              onClick={() => fetchAlerts()}
              className="p-2 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-400 hover:text-blue-500 hover:border-blue-300 dark:hover:border-blue-700 transition-all"
              title="Rafraîchir"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            </button>
          </div>
        </div>

        {/* Filtres */}
        {showFilters && (
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg p-4 space-y-3 shrink-0">
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1.5">Type d'attaque</label>
                <select value={attackType} onChange={e => setAttackType(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-600 dark:text-slate-300 focus:outline-none focus:border-slate-400 transition-all">
                  {ATTACK_TYPES.map(t => <option key={t} value={t}>{t === "ALL" ? "Tous les types" : t.replace(/_/g, " ")}</option>)}
                </select>
              </div>
              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1.5">Sévérité</label>
                <select value={severity} onChange={e => setSeverity(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-600 dark:text-slate-300 focus:outline-none focus:border-slate-400 transition-all">
                  {SEVERITIES.map(s => <option key={s} value={s}>{s === "ALL" ? "Toutes" : s}</option>)}
                </select>
              </div>
              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1.5">IP source</label>
                <input type="text" placeholder="ex: 172.19.0.4" value={ipSrc} onChange={e => setIpSrc(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-600 dark:text-slate-300 placeholder-slate-400 focus:outline-none focus:border-slate-400 transition-all" />
              </div>
              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block mb-1.5">Statut</label>
                <select value={status} onChange={e => setStatus(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-600 dark:text-slate-300 focus:outline-none focus:border-slate-400 transition-all">
                  <option value="">Tous</option>
                  <option value="open">Open</option>
                  <option value="reviewed">Reviewed</option>
                  <option value="closed">Closed</option>
                </select>
              </div>
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-slate-100 dark:border-slate-800">
              <div className="flex items-center gap-2 flex-wrap">
                <Layers className="w-3 h-3 text-slate-400" />
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Grouper par</span>
                <div className="flex gap-1.5 flex-wrap">
                  {GROUP_OPTIONS.map(opt => (
                    <button key={opt.value}
                      onClick={() => setGroupBy(g => g === opt.value ? "" : opt.value)}
                      className={`px-2.5 py-1 rounded-lg text-[11px] font-mono border transition-all ${
                        groupBy === opt.value
                          ? "bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 border-blue-200 dark:border-blue-800"
                          : "text-slate-400 border-slate-200 dark:border-slate-700 hover:text-slate-600 dark:hover:text-slate-300 hover:border-slate-300 dark:hover:border-slate-600"
                      }`}
                    >{opt.label}</button>
                  ))}
                </div>
              </div>
              {hasActiveFilters && (
                <button onClick={resetFilters}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-mono text-red-500 border border-red-200 dark:border-red-800 hover:bg-red-50 dark:hover:bg-red-900/10 transition-all">
                  Réinitialiser
                </button>
              )}
            </div>
          </div>
        )}

        {/* Tableau */}
        <div className="flex-1 min-h-0 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg overflow-hidden flex flex-col">
          <div className={`grid gap-2 px-4 py-2.5 border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-[9px] font-mono text-slate-400 uppercase tracking-widest shrink-0 ${groupBy ? "grid-cols-4" : "grid-cols-12"}`}>
            {groupBy ? (
              <><div>Groupe</div><div>Nb alertes</div><div>Sévérités</div><div>Dernière alerte</div></>
            ) : (
              <>
                <div className="col-span-2">Timestamp</div>
                <div className="col-span-2">Type</div>
                <div className="col-span-1">Sévérité</div>
                <div className="col-span-2">IP source</div>
                <div className="col-span-2">IP destination</div>
                <div className="col-span-1">Port</div>
                <div className="col-span-1">Statut</div>
                <div className="col-span-1">Actions</div>
              </>
            )}
          </div>

          <div className="overflow-y-auto flex-1 min-h-0">
            {loading ? (
              <div className="flex items-center justify-center py-16">
                <RefreshCw className="w-4 h-4 text-slate-400 animate-spin" />
              </div>
            ) : alerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-20 text-slate-400">
                <ShieldAlert className="w-8 h-8 mb-3 opacity-20" />
                <p className="font-mono text-xs">Aucune alerte trouvée</p>
                {hasActiveFilters && (
                  <button onClick={resetFilters} className="mt-3 text-xs font-mono text-blue-500 hover:underline">
                    Effacer les filtres
                  </button>
                )}
              </div>
            ) : groupBy ? (
              alerts.map((group, i) => (
                <GroupRow key={i} group={group} groupBy={groupBy} onView={setSelected} onStatusChange={updateStatus} />
              ))
            ) : (
              alerts.map((alert, i) => (
                <AlertRow key={alert._id || i} alert={alert} index={i} onStatusChange={updateStatus} onView={() => setSelected(alert)} />
              ))
            )}
          </div>
        </div>

        {/* Pagination */}
        {!groupBy && totalPages > 1 && (
          <div className="flex items-center justify-between text-xs font-mono shrink-0">
            <span className="text-slate-400">
              Page <span className="text-slate-700 dark:text-slate-300">{page}</span> / {totalPages}
              <span className="text-slate-400 ml-2">— {total} alertes</span>
            </span>
            <div className="flex items-center gap-1.5">
              <button onClick={() => setPage(1)} disabled={page === 1}
                className="px-2 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 disabled:opacity-30 disabled:cursor-not-allowed text-[10px] transition-all">«</button>
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 disabled:opacity-30 disabled:cursor-not-allowed transition-all">
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                const p = Math.max(1, Math.min(page - 2, totalPages - 4)) + i
                return (
                  <button key={p} onClick={() => setPage(p)}
                    className={`w-8 h-8 rounded-lg border text-[11px] transition-all ${p === page
                      ? "bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200 border-slate-300 dark:border-slate-600 font-semibold"
                      : "border-slate-200 dark:border-slate-700 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:border-slate-300 dark:hover:border-slate-600"}`}
                  >{p}</button>
                )
              })}
              <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 disabled:opacity-30 disabled:cursor-not-allowed transition-all">
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
              <button onClick={() => setPage(totalPages)} disabled={page === totalPages}
                className="px-2 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 disabled:opacity-30 disabled:cursor-not-allowed text-[10px] transition-all">»</button>
            </div>
          </div>
        )}
      </div>
    </>
  )
}

function AlertRow({ alert, index, onStatusChange, onView, indent = false }) {
  const rowBg = index % 2 !== 0 ? "bg-slate-50/60 dark:bg-slate-800/20" : ""
  const px    = indent ? "px-8" : "px-4"

  return (
    <div className={`grid grid-cols-12 gap-2 ${px} py-2.5 border-b border-slate-100 dark:border-slate-800 text-xs font-mono hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-all cursor-default ${rowBg}`}>
      <div className="col-span-2 text-slate-400 flex items-center tabular-nums">
        {new Date(alert.detection_time).toLocaleString("fr-FR")}
      </div>
      <div className="col-span-2 text-slate-700 dark:text-slate-300 font-semibold truncate flex items-center">
        {(alert.attack_type ?? "—").replace(/_/g, " ")}
      </div>
      <div className="col-span-1 flex items-center"><Badge severity={alert.severity} /></div>
      <div className="col-span-2 text-red-500 dark:text-red-400 truncate flex items-center">{alert.ip_src}</div>
      <div className="col-span-2 text-slate-600 dark:text-slate-400 truncate flex items-center">{alert.ip_dst}</div>
      <div className="col-span-1 text-slate-400 flex items-center">{alert.port_dst || "—"}</div>
      <div className="col-span-1 flex items-center"><Badge severity={alert.status} /></div>
      <div className="col-span-1 flex items-center gap-1">
        <button onClick={onView}
          className="p-1 rounded border border-slate-200 dark:border-slate-700 text-slate-400 hover:text-blue-500 hover:border-blue-300 dark:hover:border-blue-700 transition-all"
          title="Voir les détails"><Eye className="w-3 h-3" /></button>
        {alert.status === "open" && (
          <button onClick={() => onStatusChange(alert._id, "reviewed")}
            className="p-1 rounded border border-slate-200 dark:border-slate-700 text-slate-400 hover:text-emerald-500 hover:border-emerald-300 dark:hover:border-emerald-700 transition-all"
            title="Marquer analysé"><CheckCircle className="w-3 h-3" /></button>
        )}
        {alert.status !== "closed" && (
          <button onClick={() => onStatusChange(alert._id, "closed")}
            className="p-1 rounded border border-slate-200 dark:border-slate-700 text-slate-400 hover:text-red-500 hover:border-red-300 dark:hover:border-red-700 transition-all"
            title="Fermer l'alerte"><XCircle className="w-3 h-3" /></button>
        )}
      </div>
    </div>
  )
}

function GroupRow({ group, groupBy, onView, onStatusChange }) {
  const [open,         setOpen]         = useState(false)
  const [innerAlerts,  setInnerAlerts]  = useState([])
  const [innerLoading, setInnerLoading] = useState(false)
  const [innerPage,    setInnerPage]    = useState(1)
  const [innerTotal,   setInnerTotal]   = useState(0)
  const [innerPages,   setInnerPages]   = useState(1)
  const INNER_LIMIT = 10

  const fetchInner = useCallback(async (p) => {
    setInnerLoading(true)
    try {
      const res = await API.getAlerts({
        page: p, limit: INNER_LIMIT,
        [groupBy]: group._id,
        sort_by: "detection_time", sort_order: -1,
      })
      setInnerAlerts(res.data.data || [])
      setInnerTotal(res.data.total || 0)
      setInnerPages(res.data.total_pages || 1)
    } catch (e) { console.error(e) }
    finally { setInnerLoading(false) }
  }, [group._id, groupBy])

  const handleToggle = () => {
    if (!open) { setInnerPage(1); fetchInner(1) }
    setOpen(o => !o)
  }

  const goPage = (p) => { setInnerPage(p); fetchInner(p) }

  return (
    <div className="border-b border-slate-100 dark:border-slate-800">
      {/* Ligne résumé */}
      <button onClick={handleToggle}
        className="w-full grid grid-cols-4 gap-2 px-4 py-3 text-xs font-mono text-left hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-all">
        <div className="flex items-center gap-2 text-slate-700 dark:text-slate-300 font-semibold truncate">
          {open ? <ChevronUp className="w-3.5 h-3.5 text-slate-400 shrink-0" /> : <ChevronDown className="w-3.5 h-3.5 text-slate-400 shrink-0" />}
          <span className="truncate">{group._id || "—"}</span>
        </div>
        <div className="text-slate-700 dark:text-slate-300 flex items-baseline gap-1">
          <span className="text-lg font-semibold tabular-nums">{group.count}</span>
          <span className="text-slate-400 text-[10px]">alertes</span>
        </div>
        <div className="flex flex-wrap gap-1 items-center">
          {group.severities?.map(s => <Badge key={s} severity={s} />)}
        </div>
        <div className="text-slate-400">
          {group.last ? new Date(group.last).toLocaleString("fr-FR") : "—"}
        </div>
      </button>

      {/* Contenu déplié */}
      {open && (
        <div className="border-t border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/20">
          <div className="grid grid-cols-12 gap-2 px-8 py-2 border-b border-slate-100 dark:border-slate-800 text-[9px] font-mono text-slate-400 uppercase tracking-widest bg-slate-50 dark:bg-slate-800/60">
            <div className="col-span-2">Timestamp</div>
            <div className="col-span-2">Type</div>
            <div className="col-span-1">Sévérité</div>
            <div className="col-span-2">IP source</div>
            <div className="col-span-2">IP destination</div>
            <div className="col-span-1">Port</div>
            <div className="col-span-1">Statut</div>
            <div className="col-span-1">Actions</div>
          </div>

          {innerLoading ? (
            <div className="flex items-center justify-center py-8">
              <RefreshCw className="w-3.5 h-3.5 text-slate-400 animate-spin" />
            </div>
          ) : innerAlerts.length === 0 ? (
            <div className="flex items-center justify-center py-8 text-xs font-mono text-slate-400">
              Aucune alerte dans ce groupe
            </div>
          ) : (
            innerAlerts.map((alert, i) => (
              <AlertRow key={alert._id || i} alert={alert} index={i} indent
                onStatusChange={(id, s) => { onStatusChange(id, s); fetchInner(innerPage) }}
                onView={() => onView(alert)} />
            ))
          )}

          {innerPages > 1 && (
            <div className="flex items-center justify-between px-8 py-2 border-t border-slate-100 dark:border-slate-800 text-[10px] font-mono text-slate-400">
              <span>Page <span className="text-slate-600 dark:text-slate-300">{innerPage}</span> / {innerPages} — {innerTotal} alertes</span>
              <div className="flex items-center gap-1">
                <button onClick={() => goPage(Math.max(1, innerPage - 1))} disabled={innerPage === 1}
                  className="p-1 rounded border border-slate-200 dark:border-slate-700 text-slate-400 hover:text-slate-600 disabled:opacity-30 disabled:cursor-not-allowed transition-all">
                  <ChevronLeft className="w-3 h-3" />
                </button>
                {Array.from({ length: Math.min(5, innerPages) }, (_, i) => {
                  const p = Math.max(1, Math.min(innerPage - 2, innerPages - 4)) + i
                  return (
                    <button key={p} onClick={() => goPage(p)}
                      className={`w-6 h-6 rounded border text-[10px] transition-all ${p === innerPage
                        ? "bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-200 border-slate-300 dark:border-slate-600 font-semibold"
                        : "border-slate-200 dark:border-slate-700 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300"}`}
                    >{p}</button>
                  )
                })}
                <button onClick={() => goPage(Math.min(innerPages, innerPage + 1))} disabled={innerPage === innerPages}
                  className="p-1 rounded border border-slate-200 dark:border-slate-700 text-slate-400 hover:text-slate-600 disabled:opacity-30 disabled:cursor-not-allowed transition-all">
                  <ChevronRight className="w-3 h-3" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}