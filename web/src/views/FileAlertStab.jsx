// Ajouter l'import en haut
import { useState, useEffect, useRef, useCallback } from "react"
import {
  Monitor, Cpu, MemoryStick, HardDrive, Network,
  Activity, AlertTriangle, ChevronRight, ChevronLeft,
  RefreshCw, X, FileText, Skull, ExternalLink, Filter
} from "lucide-react"
import { API } from "../services/api"
import { MonitoringAlerts } from "./MonitoringAlerts"

// ── FileChangesTab — définir ICI dans Monitoring.jsx ─────────────
export function FileChangesTab({ hostname }) {
  const [changes,    setChanges]    = useState([])
  const [loading,    setLoading]    = useState(false)
  const [filter,     setFilter]     = useState("")
  const [changeType, setChangeType] = useState("")
  const [page,       setPage]       = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [total,      setTotal]      = useState(0)

  const fetchChanges = useCallback(async () => {
    setLoading(true)
    try {
      const res = await API.getFileChanges(hostname, {
        page, limit: 50,
        ...(changeType && { change_type: changeType }),
      })
      setChanges(res.data.data || [])
      setTotal(res.data.total || 0)
      setTotalPages(res.data.total_pages || 1)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [hostname, page, changeType])

  useEffect(() => { fetchChanges() }, [fetchChanges])
  useEffect(() => { setPage(1) }, [changeType])

  const CHANGE_COLORS = {
    created:  "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
    modified: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
    deleted:  "text-red-400 bg-red-500/10 border-red-500/20",
    MODIFIED: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
    DELETED:  "text-red-400 bg-red-500/10 border-red-500/20",
    TRUNCATED:"text-orange-400 bg-orange-500/10 border-orange-500/20",
  }

  const filtered = changes.filter(c =>
    !filter || c.file_path?.toLowerCase().includes(filter.toLowerCase())
  )

  return (
    <div className="flex flex-col gap-3">

      {/* Toolbar */}
      <div className="flex items-center gap-2">
        <div className="flex-1 relative">
          <Filter className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-slate-500" />
          <input
            type="text"
            placeholder="Filtrer par chemin..."
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="w-full bg-slate-800/40 border border-slate-700/40 rounded-lg pl-8 pr-3 py-1.5 text-xs font-mono text-slate-300 placeholder-slate-600 focus:outline-none focus:border-slate-500"
          />
        </div>
        {["", "MODIFIED", "DELETED"].map(type => (
          <button key={type}
            onClick={() => setChangeType(type)}
            className={`px-2.5 py-1.5 rounded-lg text-[10px] font-mono border transition-all ${
              changeType === type
                ? "bg-slate-700 text-slate-200 border-slate-600"
                : "text-slate-500 border-slate-700/40 hover:text-slate-300"
            }`}>
            {type === "" ? "Tous" : type}
          </button>
        ))}
        <button onClick={fetchChanges}
          className="p-1.5 rounded-lg border border-slate-700/40 text-slate-500 hover:text-slate-300 transition-all">
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-2">
        {["MODIFIED", "DELETED", "TRUNCATED"].map(type => {
          const count = changes.filter(c => c.change_type === type).length
          return (
            <div key={type} className={`rounded-lg p-2.5 border text-center ${CHANGE_COLORS[type]}`}>
              <p className="text-lg font-mono font-bold">{count}</p>
              <p className="text-[9px] uppercase tracking-wider">{type}</p>
            </div>
          )
        })}
      </div>

      {/* Liste */}
      <div className="rounded-xl border border-slate-700/40 overflow-hidden">
        <div className="grid grid-cols-12 gap-2 px-3 py-2 bg-slate-800/60 text-[9px] font-mono text-slate-500 uppercase tracking-widest border-b border-slate-700/40">
          <div className="col-span-1">Type</div>
          <div className="col-span-8">Chemin</div>
          <div className="col-span-3">Horodatage</div>
        </div>
        <div className="overflow-y-auto max-h-64">
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <RefreshCw className="w-4 h-4 text-slate-500 animate-spin" />
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10 text-slate-600">
              <FileText className="w-5 h-5 mb-2 opacity-30" />
              <p className="text-xs font-mono">Aucune modification détectée</p>
            </div>
          ) : (
            filtered.map((change, i) => (
              <div key={change._id || i}
                className={`grid grid-cols-12 gap-2 px-3 py-2 border-b border-slate-700/20 text-[11px] font-mono hover:bg-slate-800/30 ${i % 2 !== 0 ? "bg-slate-800/10" : ""}`}>
                <div className="col-span-1 flex items-center">
                  <span className={`px-1.5 py-0.5 rounded text-[9px] border font-bold ${CHANGE_COLORS[change.change_type] || "text-slate-400 bg-slate-700 border-slate-600"}`}>
                    {(change.change_type || "?")[0]}
                  </span>
                </div>
                <div className="col-span-8 text-slate-300 truncate flex items-center" title={change.file_path}>
                  {change.file_path}
                </div>
                <div className="col-span-3 text-slate-500 flex items-center tabular-nums">
                  {change.timestamp
                    ? new Date(change.timestamp).toLocaleString("fr-FR")
                    : "—"
                  }
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between text-[10px] font-mono text-slate-600">
          <span>{total} fichiers au total</span>
          <div className="flex gap-1.5">
            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
              className="p-1 rounded border border-slate-700/40 disabled:opacity-30">
              <ChevronLeft className="w-3 h-3" />
            </button>
            <span className="px-2 py-0.5">{page}/{totalPages}</span>
            <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
              className="p-1 rounded border border-slate-700/40 disabled:opacity-30">
              <ChevronRight className="w-3 h-3" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}