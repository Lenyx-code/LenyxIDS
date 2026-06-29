// Composant onglet Fichiers pour HostDetail dans Monitoring.jsx
// À remplacer dans le tab === "files" de HostDetail

import { useEffect, useState, useCallback } from "react"
import { FileText, RefreshCw, ShieldAlert, CheckCircle, XCircle } from "lucide-react"
import { API } from "../services/api"

const CHANGE_CFG = {
  MODIFIED:  { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", dot: "bg-yellow-500" },
  DELETED:   { color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30",    dot: "bg-red-500"    },
  TRUNCATED: { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", dot: "bg-orange-500" },
  CREATED:   { color: "text-emerald-400",bg: "bg-emerald-500/10",border: "border-emerald-500/30",dot: "bg-emerald-500"},
}

const fmtSize = (bytes) => {
  if (bytes == null) return "—"
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

const fmt = (iso) => {
  if (!iso) return "—"
  return new Date(iso).toLocaleString("fr-FR", {
    day: "2-digit", month: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  })
}

export function FileAlertsTab({ hostname }) {
  const [alerts,   setAlerts]   = useState([])
  const [loading,  setLoading]  = useState(true)
  const [total,    setTotal]    = useState(0)

  const fetchFileAlerts = useCallback(async () => {
    setLoading(true)
    try {
      const r = await API.getMonitoringAlerts({
        anomaly_type: "FILE_CHANGE",
        hostname,
        limit: 50,
        page: 1,
      })
      setAlerts(r.data.data ?? [])
      setTotal(r.data.total ?? 0)
    } catch {
      setAlerts([])
    } finally {
      setLoading(false)
    }
  }, [hostname])

  useEffect(() => { fetchFileAlerts() }, [fetchFileAlerts])

  const handleStatus = async (id, status) => {
    try {
      await API.updateMonitoringAlertStatus(id, status)
      fetchFileAlerts()
    } catch {}
  }

  if (loading) return (
    <div className="flex items-center justify-center py-12">
      <RefreshCw className="w-4 h-4 text-slate-500 animate-spin" />
    </div>
  )

  if (alerts.length === 0) return (
    <div className="flex flex-col items-center justify-center gap-3 py-12 text-slate-600">
      <FileText className="w-8 h-8 opacity-30" />
      <p className="text-xs font-mono">Aucune modification de fichier détectée</p>
      <p className="text-[11px] text-slate-700">
        Le FileWatchdog surveille : /etc/passwd, /etc/shadow, /etc/hosts…
      </p>
      <button onClick={fetchFileAlerts}
        className="mt-2 flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700
          text-[11px] font-mono text-slate-400 hover:text-slate-200 transition-all">
        <RefreshCw className="w-3 h-3" /> Actualiser
      </button>
    </div>
  )

  return (
    <div className="flex flex-col gap-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
            Fichiers modifiés
          </span>
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/10
            border border-cyan-500/30 text-cyan-400">
            {total}
          </span>
        </div>
        <button onClick={fetchFileAlerts}
          className="p-1.5 rounded-lg hover:bg-slate-700/50 text-slate-500 hover:text-slate-300 transition-colors">
          <RefreshCw className="w-3 h-3" />
        </button>
      </div>

      {/* Liste */}
      <div className="flex flex-col gap-2">
        {alerts.map((alert) => {
          const cfg = CHANGE_CFG[alert.change_type] ?? CHANGE_CFG.MODIFIED
          const filename = alert.file_path?.split("/").pop() ?? "—"
          return (
            <div key={alert._id}
              className={`p-3 rounded-lg border ${cfg.bg} ${cfg.border} flex flex-col gap-1.5`}>

              {/* Ligne 1 : type + nom fichier */}
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                  <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded-full border
                    flex items-center gap-1 ${cfg.bg} ${cfg.border} ${cfg.color}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
                    {alert.change_type}
                  </span>
                  <span className="text-[11px] font-mono font-semibold text-slate-200 truncate">
                    {filename}
                  </span>
                </div>
                <span className="text-[9px] font-mono text-slate-600 shrink-0">
                  {fmt(alert.detection_time)}
                </span>
              </div>

              {/* Ligne 2 : chemin complet */}
              <p className="text-[10px] font-mono text-slate-500 truncate" title={alert.file_path}>
                {alert.file_path}
              </p>

              {/* Ligne 3 : tailles */}
              {alert.old_size != null && (
                <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-600">
                  <span>{fmtSize(alert.old_size)}</span>
                  <span className="text-slate-700">→</span>
                  <span className={alert.new_size === 0 ? "text-red-400" : "text-slate-400"}>
                    {fmtSize(alert.new_size)}
                  </span>
                </div>
              )}

              {/* Actions statut */}
              {alert.status !== "closed" && (
                <div className="flex gap-1.5 mt-0.5">
                  {alert.status === "open" && (
                    <button onClick={() => handleStatus(alert._id, "reviewed")}
                      className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono
                        bg-emerald-600/10 border border-emerald-600/20 text-emerald-400
                        hover:bg-emerald-600/20 transition-colors">
                      <CheckCircle className="w-3 h-3" /> Analysé
                    </button>
                  )}
                  <button onClick={() => handleStatus(alert._id, "closed")}
                    className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono
                      bg-slate-700/40 border border-slate-600/30 text-slate-400
                      hover:text-red-400 transition-colors">
                    <XCircle className="w-3 h-3" /> Fermer
                  </button>
                </div>
              )}
              {alert.status === "closed" && (
                <span className="text-[10px] font-mono text-slate-600">✓ Fermée</span>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}